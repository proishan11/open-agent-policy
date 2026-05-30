package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/jackc/pgx/v5"
)

const migrationLockKey int64 = 7020677177139950930

const schemaVersionBootstrap = `
CREATE TABLE IF NOT EXISTS oap_schema_version (
    version     INTEGER PRIMARY KEY,
    name        TEXT NOT NULL DEFAULT '',
    checksum    TEXT NOT NULL DEFAULT '',
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE oap_schema_version ADD COLUMN IF NOT EXISTS name TEXT NOT NULL DEFAULT '';
ALTER TABLE oap_schema_version ADD COLUMN IF NOT EXISTS checksum TEXT NOT NULL DEFAULT '';
`

// Migration is one ordered, durable database schema change.
type Migration struct {
	Version int
	Name    string
	SQL     string
}

// Migrations is the ordered Postgres schema migration set.
var Migrations = []Migration{
	{
		Version: 1,
		Name:    "base_control_plane_schema",
		SQL: `
CREATE TABLE IF NOT EXISTS oap_agents (
    id          TEXT PRIMARY KEY,           -- agent://ns/name
    namespace   TEXT NOT NULL,
    name        TEXT NOT NULL,
    data        JSONB NOT NULL,             -- full Agent JSON
    state       TEXT NOT NULL DEFAULT 'active',
    version     INTEGER NOT NULL DEFAULT 1,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(namespace, name)
);

CREATE INDEX IF NOT EXISTS idx_agents_namespace ON oap_agents(namespace);
CREATE INDEX IF NOT EXISTS idx_agents_state ON oap_agents(state);

CREATE TABLE IF NOT EXISTS oap_policies (
    id          TEXT PRIMARY KEY,           -- ns/name
    namespace   TEXT NOT NULL,
    name        TEXT NOT NULL,
    data        JSONB NOT NULL,             -- full AgentPolicy JSON
    version     INTEGER NOT NULL DEFAULT 1,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(namespace, name)
);

CREATE INDEX IF NOT EXISTS idx_policies_namespace ON oap_policies(namespace);

CREATE TABLE IF NOT EXISTS oap_resources (
    id          TEXT PRIMARY KEY,           -- ns/name
    namespace   TEXT NOT NULL,
    name        TEXT NOT NULL,
    data        JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(namespace, name)
);

CREATE TABLE IF NOT EXISTS oap_tools (
    id          TEXT PRIMARY KEY,           -- ns/name
    namespace   TEXT NOT NULL,
    name        TEXT NOT NULL,
    data        JSONB NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(namespace, name)
);

CREATE TABLE IF NOT EXISTS oap_audit_events (
    id          TEXT PRIMARY KEY,
    agent_id    TEXT NOT NULL,
    action      TEXT NOT NULL,
    decision    TEXT NOT NULL,
    data        JSONB NOT NULL,             -- full AuditEvent JSON
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_agent ON oap_audit_events(agent_id);
CREATE INDEX IF NOT EXISTS idx_audit_decision ON oap_audit_events(decision);
CREATE INDEX IF NOT EXISTS idx_audit_created ON oap_audit_events(created_at);
`,
	},
	{
		Version: 2,
		Name:    "audit_query_indexes",
		SQL: `
ALTER TABLE oap_audit_events ADD COLUMN IF NOT EXISTS actor_id TEXT;
ALTER TABLE oap_audit_events ADD COLUMN IF NOT EXISTS request_id TEXT;
ALTER TABLE oap_audit_events ADD COLUMN IF NOT EXISTS run_id TEXT;
ALTER TABLE oap_audit_events ADD COLUMN IF NOT EXISTS resource_type TEXT;
ALTER TABLE oap_audit_events ADD COLUMN IF NOT EXISTS resource_id TEXT;

CREATE INDEX IF NOT EXISTS idx_audit_actor ON oap_audit_events(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON oap_audit_events(action);
CREATE INDEX IF NOT EXISTS idx_audit_request ON oap_audit_events(request_id);
CREATE INDEX IF NOT EXISTS idx_audit_run ON oap_audit_events(run_id);
CREATE INDEX IF NOT EXISTS idx_audit_resource ON oap_audit_events(resource_type, resource_id);
`,
	},
}

// LatestSchemaVersion returns the highest migration version known to this binary.
func LatestSchemaVersion() int {
	if len(Migrations) == 0 {
		return 0
	}
	return Migrations[len(Migrations)-1].Version
}

// ensureSchema applies all migrations in a transaction protected by a Postgres
// advisory lock so multiple server instances cannot race schema updates.
func (s *Store) ensureSchema(ctx context.Context) error {
	if err := validateMigrations(Migrations); err != nil {
		return err
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin migration transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, migrationLockKey); err != nil {
		return fmt.Errorf("postgres: acquire migration lock: %w", err)
	}
	if _, err := tx.Exec(ctx, schemaVersionBootstrap); err != nil {
		return fmt.Errorf("postgres: bootstrap schema version table: %w", err)
	}

	for _, migration := range Migrations {
		state, err := migrationState(ctx, tx, migration.Version)
		if err != nil {
			return err
		}
		checksum := migrationChecksum(migration)
		if !state.Applied {
			if _, err := tx.Exec(ctx, migration.SQL); err != nil {
				return fmt.Errorf("postgres: apply migration %d %s: %w", migration.Version, migration.Name, err)
			}
			if _, err := tx.Exec(ctx,
				`INSERT INTO oap_schema_version (version, name, checksum) VALUES ($1, $2, $3)`,
				migration.Version, migration.Name, checksum,
			); err != nil {
				return fmt.Errorf("postgres: record migration %d: %w", migration.Version, err)
			}
			continue
		}

		if err := validateAppliedMigration(migration, state, checksum); err != nil {
			return err
		}

		if _, err := tx.Exec(ctx,
			`UPDATE oap_schema_version
			 SET name = CASE WHEN name = '' THEN $2 ELSE name END,
			     checksum = CASE WHEN checksum = '' THEN $3 ELSE checksum END
			 WHERE version = $1`,
			migration.Version, migration.Name, checksum,
		); err != nil {
			return fmt.Errorf("postgres: backfill migration metadata %d: %w", migration.Version, err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit migrations: %w", err)
	}
	return nil
}

type appliedMigration struct {
	Applied  bool
	Name     string
	Checksum string
}

func migrationState(ctx context.Context, tx pgx.Tx, version int) (appliedMigration, error) {
	var state appliedMigration
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM oap_schema_version WHERE version = $1)`,
		version,
	).Scan(&state.Applied); err != nil {
		return state, fmt.Errorf("postgres: check migration %d: %w", version, err)
	}
	if !state.Applied {
		return state, nil
	}

	if err := tx.QueryRow(ctx,
		`SELECT name, checksum FROM oap_schema_version WHERE version = $1`,
		version,
	).Scan(&state.Name, &state.Checksum); err != nil {
		return state, fmt.Errorf("postgres: read migration metadata %d: %w", version, err)
	}
	return state, nil
}

func validateAppliedMigration(migration Migration, state appliedMigration, checksum string) error {
	if state.Name != "" && state.Name != migration.Name {
		return fmt.Errorf("postgres: migration %d name mismatch: database has %q, binary has %q", migration.Version, state.Name, migration.Name)
	}
	if state.Checksum != "" && state.Checksum != checksum {
		return fmt.Errorf("postgres: migration %d checksum mismatch", migration.Version)
	}
	return nil
}

func validateMigrations(migrations []Migration) error {
	if len(migrations) == 0 {
		return fmt.Errorf("postgres: no migrations configured")
	}

	versions := make([]int, 0, len(migrations))
	seen := make(map[int]bool, len(migrations))
	for _, migration := range migrations {
		if migration.Version <= 0 {
			return fmt.Errorf("postgres: migration version must be positive")
		}
		if migration.Name == "" {
			return fmt.Errorf("postgres: migration %d has empty name", migration.Version)
		}
		if migration.SQL == "" {
			return fmt.Errorf("postgres: migration %d has empty SQL", migration.Version)
		}
		if seen[migration.Version] {
			return fmt.Errorf("postgres: duplicate migration version %d", migration.Version)
		}
		seen[migration.Version] = true
		versions = append(versions, migration.Version)
	}
	if !sort.IntsAreSorted(versions) {
		return fmt.Errorf("postgres: migrations must be sorted by version")
	}
	return nil
}

func migrationChecksum(migration Migration) string {
	sum := sha256.Sum256([]byte(migration.SQL))
	return hex.EncodeToString(sum[:])
}

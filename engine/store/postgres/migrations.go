package postgres

// Schema contains the SQL migrations for the OAP Postgres store.
// Applied on first connection via EnsureSchema().
const Schema = `
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

CREATE TABLE IF NOT EXISTS oap_schema_version (
    version     INTEGER PRIMARY KEY,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO oap_schema_version (version) VALUES (1) ON CONFLICT DO NOTHING;
`

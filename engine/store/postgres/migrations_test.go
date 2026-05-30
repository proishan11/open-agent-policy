package postgres

import "testing"

func TestMigrationsAreValid(t *testing.T) {
	if err := validateMigrations(Migrations); err != nil {
		t.Fatalf("validateMigrations: %v", err)
	}
	if LatestSchemaVersion() != 2 {
		t.Fatalf("LatestSchemaVersion = %d, want 2", LatestSchemaVersion())
	}
}

func TestValidateMigrationsRejectsInvalidSet(t *testing.T) {
	tests := []struct {
		name       string
		migrations []Migration
	}{
		{name: "empty", migrations: nil},
		{name: "duplicate", migrations: []Migration{
			{Version: 1, Name: "one", SQL: "SELECT 1"},
			{Version: 1, Name: "again", SQL: "SELECT 1"},
		}},
		{name: "unsorted", migrations: []Migration{
			{Version: 2, Name: "two", SQL: "SELECT 2"},
			{Version: 1, Name: "one", SQL: "SELECT 1"},
		}},
		{name: "missing name", migrations: []Migration{{Version: 1, SQL: "SELECT 1"}}},
		{name: "missing sql", migrations: []Migration{{Version: 1, Name: "one"}}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateMigrations(tc.migrations); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestMigrationChecksumIsStable(t *testing.T) {
	migration := Migration{Version: 1, Name: "test", SQL: "SELECT 1"}
	got := migrationChecksum(migration)
	if got == "" {
		t.Fatal("checksum is empty")
	}
	if got != migrationChecksum(migration) {
		t.Fatal("checksum changed across calls")
	}
}

func TestValidateAppliedMigrationDetectsDrift(t *testing.T) {
	migration := Migration{Version: 1, Name: "test", SQL: "SELECT 1"}
	checksum := migrationChecksum(migration)

	if err := validateAppliedMigration(migration, appliedMigration{Name: migration.Name, Checksum: checksum}, checksum); err != nil {
		t.Fatalf("validateAppliedMigration: %v", err)
	}
	if err := validateAppliedMigration(migration, appliedMigration{Name: "renamed", Checksum: checksum}, checksum); err == nil {
		t.Fatal("expected name mismatch")
	}
	if err := validateAppliedMigration(migration, appliedMigration{Name: migration.Name, Checksum: "different"}, checksum); err == nil {
		t.Fatal("expected checksum mismatch")
	}
}

# Database Migration Discipline

**Status:** draft, first implementation slice in progress  
**Date:** 2026-05-30  
**Track:** Production database operations

## Goal

OAP must be able to evolve the production Postgres schema without relying on a
single monolithic `CREATE TABLE IF NOT EXISTS` block. Database changes need to be
ordered, durable, auditable, and safe when multiple server instances start at
the same time.

## Non-Goals

- This slice does not introduce an external migration tool.
- This slice does not implement down migrations.
- This slice does not replace backup, restore, or HA runbooks.

## Schema Version Contract

Postgres stores applied migrations in `oap_schema_version`:

| Column | Meaning |
|---|---|
| `version` | Integer migration version, unique and ordered. |
| `name` | Stable human-readable migration name. |
| `checksum` | SHA-256 checksum of the migration SQL shipped by the binary. |
| `applied_at` | Time the migration was recorded. |

The migration runner must:

- Validate that migrations are non-empty, sorted, uniquely versioned, and named.
- Acquire a Postgres advisory transaction lock before applying migrations.
- Apply all pending migrations in one transaction.
- Record migration metadata only after the SQL succeeds.
- Backfill metadata for older installs that only recorded numeric versions.
- Reject an already-applied migration if its stored name or checksum differs
  from the binary's migration definition.
- Fail closed if the configured migration list is invalid.

## First Migration Set

| Version | Name | Purpose |
|---|---|---|
| 1 | `base_control_plane_schema` | Durable agents, policies, resources, tools, and base audit table. |
| 2 | `audit_query_indexes` | Audit query columns and indexes for agent, actor, action, decision, request, run, resource, and time filters. |

## Operational Rules

- Application startup may run migrations automatically while the project remains
  in developer-preview mode.
- Before enterprise-GA, operators need an explicit migration command, backup
  checklist, online migration guidance, and rollback/recovery runbook.
- Future migrations that rewrite large tables must be split into online-safe
  steps instead of holding long exclusive locks during server startup.

## Validation Requirements

- Unit tests must validate migration ordering and checksum stability.
- Postgres integration tests must verify that the latest version has non-empty
  metadata.
- Audit query tests must run against the migrated schema.

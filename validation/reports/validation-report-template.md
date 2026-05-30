# OAP Production-Like Validation Report

Date:  
Environment:  
OAP version:  
Agent version:  
IdP provider:  
Policy bundle version:  

---

## Summary

| Metric | Value |
|---|---:|
| Total tests | |
| Passed | |
| Failed | |
| Skipped | |

---

## Environment

- **Runtime**: Docker Compose (local) / Kubernetes
- **IdP**: Keycloak 25.0
- **Resource APIs**: ticket-api, customer-api, approval-api (FastAPI + Postgres)
- **Database**: PostgreSQL 16
- **Audit sink**: JSONL file + Postgres audit_events table

---

## Scenario Results

| Scenario | ID | Result | Notes |
|---|---|---|---|
| Happy path assigned ticket | S001 | | |
| Cross-user ticket denied | S002 | | |
| Region mismatch denied | S003 | | |
| Restricted customer denied | S004 | | |
| Bulk export denied | S005 | | |
| Internal message allowed | S006 | | |
| External message requires approval | S007 | | |
| Approval scope mismatch denied | S008 | | |
| Prompt injection blocked | S009 | | |
| Suspended user denied | S010 | | |
| Revoked agent denied | S011 | | |
| Unknown agent denied | S012 | | |
| Grant replay denied | S013 | | |
| Direct API bypass | S014 | | |
| Escalation allowed, settings denied | S015 | | |

---

## Security Findings

| Category | Tests | Passed | Notes |
|---|---:|---:|---|
| Prompt injection | | | |
| Privilege escalation | | | |
| Grant replay | | | |
| Direct bypass | | | |

---

## Performance Metrics

| Metric | Result | Target |
|---|---:|---:|
| p50 authorize latency | | < 20 ms |
| p95 authorize latency | | < 100 ms |
| Audit event coverage | | 100% |

---

## Audit Evidence

- [ ] Every decision emits an audit event
- [ ] Audit events queryable by request ID
- [ ] Audit events queryable by agent ID
- [ ] Denial reasons included
- [ ] Constraints included for constrained decisions

---

## Before/After Comparison

### Before OAP
- Agent uses broad service account credentials
- All ticket and customer data accessible
- No per-action audit trail
- Revocation requires credential rotation

### After OAP
- Agent has registered identity
- Access governed by policy
- Bulk export denied
- Sensitive fields redacted
- Revoked agents immediately denied
- Full audit trail per decision

---

## Known Limitations

-

---

## Go/No-Go Recommendation

-

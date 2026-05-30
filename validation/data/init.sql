-- OAP Production Validation — Database Schema + Seed Data
-- This runs on first startup of the Postgres container.

-- ============================================================
-- Schema: resource APIs
-- ============================================================

CREATE TABLE IF NOT EXISTS tickets (
    id          TEXT PRIMARY KEY,
    subject     TEXT NOT NULL,
    description TEXT DEFAULT '',
    customer_id TEXT NOT NULL,
    assigned_to TEXT,                   -- user email who owns this ticket
    status      TEXT NOT NULL DEFAULT 'open',
    priority    TEXT NOT NULL DEFAULT 'P3',
    region      TEXT NOT NULL DEFAULT 'US',
    classification TEXT NOT NULL DEFAULT 'confidential',
    tags        TEXT[] DEFAULT '{}',
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS customers (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    email           TEXT NOT NULL,
    company         TEXT NOT NULL,
    plan            TEXT NOT NULL DEFAULT 'pro',
    region          TEXT NOT NULL DEFAULT 'US',
    classification  TEXT NOT NULL DEFAULT 'confidential',
    -- Synthetic PII-like fields for redaction testing
    tax_identifier  TEXT,
    billing_account TEXT,
    bank_account    TEXT,
    phone           TEXT,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS approvals (
    id          TEXT PRIMARY KEY,
    agent_id    TEXT NOT NULL,
    actor_id    TEXT NOT NULL,
    action      TEXT NOT NULL,
    resource_type TEXT,
    resource_id TEXT,
    purpose     TEXT,
    status      TEXT NOT NULL DEFAULT 'pending',  -- pending, approved, denied, expired
    approver_id TEXT,
    approved_at TIMESTAMPTZ,
    expires_at  TIMESTAMPTZ,
    constraints JSONB DEFAULT '{}',
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS messages (
    id          TEXT PRIMARY KEY,
    channel     TEXT NOT NULL,
    sender      TEXT NOT NULL,
    body        TEXT NOT NULL,
    metadata    JSONB DEFAULT '{}',
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================
-- Schema: audit
-- ============================================================

CREATE TABLE IF NOT EXISTS audit_events (
    id              SERIAL PRIMARY KEY,
    request_id      TEXT NOT NULL,
    trace_id        TEXT,
    agent_id        TEXT,
    actor_id        TEXT,
    action          TEXT,
    resource_type   TEXT,
    resource_id     TEXT,
    resource_class  TEXT,
    decision        TEXT NOT NULL,
    policy_ids      TEXT[],
    constraints     JSONB,
    approval_id     TEXT,
    grant_id        TEXT,
    reason          TEXT,
    latency_ms      INTEGER,
    raw_event       JSONB,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_request_id ON audit_events(request_id);
CREATE INDEX IF NOT EXISTS idx_audit_agent_id ON audit_events(agent_id);
CREATE INDEX IF NOT EXISTS idx_audit_actor_id ON audit_events(actor_id);
CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_events(created_at);

-- ============================================================
-- Seed: Tickets (from test plan section 6.4)
-- ============================================================

INSERT INTO tickets (id, subject, description, customer_id, assigned_to, status, priority, region, classification, tags) VALUES
('T-100', 'Cannot access dashboard after password reset',
 'User reports they cannot log in after using the password reset link. Tried clearing cookies. Issue persists.',
 'C-100', 'alice@company.test', 'open', 'P2', 'US', 'confidential',
 ARRAY['access', 'password', 'dashboard']),

('T-200', 'Production database connection timeout',
 'Customer production DB connections timing out since 08:00 UTC. Affecting all services. P1 escalation requested.',
 'C-100', 'bob@company.test', 'open', 'P1', 'EU', 'confidential',
 ARRAY['database', 'production', 'critical']),

('T-300', 'GDPR data export request for EU customer',
 'EU customer requesting full data export under GDPR Article 15. Must be handled by EU-region support.',
 'C-200', 'bob@company.test', 'open', 'P2', 'EU', 'confidential',
 ARRAY['gdpr', 'data-export', 'eu']),

('T-400', 'Feature request: dark mode in settings',
 'Customer requests dark mode option in the settings UI.',
 'C-100', NULL, 'open', 'P4', 'US', 'confidential',
 ARRAY['feature-request', 'ui']),

('T-500', 'Billing discrepancy on restricted account',
 'Highly restricted financial customer reports billing anomaly. Requires special access clearance.',
 'C-900', NULL, 'open', 'P2', 'US', 'highly_restricted',
 ARRAY['billing', 'restricted'])
ON CONFLICT (id) DO NOTHING;

-- ============================================================
-- Seed: Customers (from test plan section 6.4)
-- ============================================================

INSERT INTO customers (id, name, email, company, plan, region, classification, tax_identifier, billing_account, bank_account, phone) VALUES
('C-100', 'Alice Johnson', 'alice@acmecorp.com', 'Acme Corp', 'enterprise', 'US', 'confidential',
 'US-TAX-1234567', 'BILL-AC-001', 'BANK-001-XXXX', '+1-555-0101'),

('C-200', 'Hans Mueller', 'hans@eurocorp.de', 'EuroCorp GmbH', 'enterprise', 'EU', 'confidential',
 'DE-TAX-7654321', 'BILL-EU-002', 'BANK-002-XXXX', '+49-555-0202'),

('C-300', 'Carol Davis', 'carol@startup.dev', 'StartupDev', 'pro', 'US', 'confidential',
 'US-TAX-9876543', 'BILL-SD-003', 'BANK-003-XXXX', '+1-555-0303'),

('C-400', 'David Park', 'david@globalcorp.kr', 'GlobalCorp', 'enterprise', 'APAC', 'confidential',
 'KR-TAX-1357924', 'BILL-GC-004', 'BANK-004-XXXX', '+82-555-0404'),

('C-900', 'RESTRICTED: Federal Reserve Bank Test Account', 'restricted@fedreserve.test',
 'Federal Reserve (Test)', 'government', 'US', 'highly_restricted',
 'GOV-TAX-CLASSIFIED', 'BILL-GOV-900', 'BANK-GOV-CLASSIFIED', '+1-555-0900')
ON CONFLICT (id) DO NOTHING;

-- ============================================================
-- Seed: Slack-like channels (for messaging scenarios)
-- ============================================================

CREATE TABLE IF NOT EXISTS channels (
    id              TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    classification  TEXT NOT NULL DEFAULT 'internal',
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO channels (id, name, classification) VALUES
('slack:#support-triage', '#support-triage', 'internal'),
('slack:#external-customer-updates', '#external-customer-updates', 'restricted')
ON CONFLICT (id) DO NOTHING;

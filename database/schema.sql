-- ============================================================================
-- Unified Wazuh Security Operations Platform — Database Schema
-- PostgreSQL 16
-- ============================================================================

-- ─── Extensions ───
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ─── Tenants (multi-tenant root) ───
CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    config JSONB DEFAULT '{}',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─── API Keys (bind to tenant) ───
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    key_hash TEXT NOT NULL UNIQUE,
    key_prefix TEXT NOT NULL,
    label TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_api_keys_tenant ON api_keys(tenant_id);
CREATE INDEX idx_api_keys_hash ON api_keys(key_hash);

-- ─── Assets (agent inventory from Wazuh) ───
CREATE TABLE assets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    agent_id TEXT NOT NULL,
    agent_name TEXT,
    agent_ip TEXT,
    os_platform TEXT,
    os_version TEXT,
    os_name TEXT,
    os_major INTEGER,
    os_minor INTEGER,
    architecture TEXT,
    version TEXT,
    status TEXT DEFAULT 'active',
    last_seen TIMESTAMPTZ,
    groups TEXT[] DEFAULT '{}',
    labels JSONB DEFAULT '{}',
    node_name TEXT,
    date_add TIMESTAMPTZ,
    criticality INTEGER DEFAULT 5 CHECK (criticality BETWEEN 1 AND 10),
    owner TEXT,
    raw_data JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, agent_id)
);
CREATE INDEX idx_assets_tenant ON assets(tenant_id);
CREATE INDEX idx_assets_status ON assets(status);
CREATE INDEX idx_assets_group ON assets USING GIN(groups);
CREATE INDEX idx_assets_criticality ON assets(criticality);

-- ─── Alerts (normalized Wazuh alerts) ───
CREATE TABLE alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    wazuh_alert_id TEXT UNIQUE,
    rule_id INTEGER,
    rule_description TEXT,
    rule_level INTEGER,
    rule_groups TEXT[] DEFAULT '{}',
    rule_firedtimes INTEGER,
    mitre_tactic TEXT,
    mitre_technique TEXT,
    agent_id TEXT,
    agent_name TEXT,
    agent_ip TEXT,
    source_ip TEXT,
    source_port INTEGER,
    destination_ip TEXT,
    destination_port INTEGER,
    protocol TEXT,
    user_name TEXT,
    process_name TEXT,
    process_pid INTEGER,
    file_path TEXT,
    file_name TEXT,
    file_hash TEXT,
    event_id TEXT,
    event_type TEXT,
    event_action TEXT,
    log_source TEXT,
    raw_alert_redacted JSONB,
    alert_timestamp TIMESTAMPTZ,
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_alerts_tenant ON alerts(tenant_id);
CREATE INDEX idx_alerts_rule_level ON alerts(rule_level);
CREATE INDEX idx_alerts_timestamp ON alerts(alert_timestamp DESC);
CREATE INDEX idx_alerts_agent ON alerts(agent_id);
CREATE INDEX idx_alerts_source_ip ON alerts(source_ip);
CREATE INDEX idx_alerts_groups ON alerts USING GIN(rule_groups);
CREATE INDEX idx_alerts_mitre ON alerts(mitre_technique);
CREATE INDEX idx_alerts_ingested_at ON alerts(ingested_at DESC);

-- ─── AI Triage Results (every AI decision) ───
CREATE TABLE ai_triage_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    alert_id UUID REFERENCES alerts(id) ON DELETE SET NULL,
    model_name TEXT NOT NULL,
    model_version TEXT,
    prompt_text TEXT,
    response_text TEXT,
    summary TEXT,
    category TEXT,
    severity TEXT CHECK (severity IN ('low','medium','high','critical')),
    confidence DECIMAL(3,2),
    false_positive_likelihood DECIMAL(3,2),
    mitre_mapping JSONB DEFAULT '[]',
    investigation_steps JSONB DEFAULT '[]',
    do_not_do JSONB DEFAULT '[]',
    key_entities JSONB DEFAULT '[]',
    escalation_required BOOLEAN DEFAULT FALSE,
    suggested_soc_action TEXT,
    latency_ms INTEGER,
    tokens_input INTEGER,
    tokens_output INTEGER,
    cost DECIMAL(10,6),
    success BOOLEAN DEFAULT TRUE,
    error_message TEXT,
    raw_request JSONB,
    raw_response JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_triage_alert ON ai_triage_results(alert_id);
CREATE INDEX idx_triage_tenant ON ai_triage_results(tenant_id);
CREATE INDEX idx_triage_created ON ai_triage_results(created_at DESC);
CREATE INDEX idx_triage_severity ON ai_triage_results(severity);

-- ─── Cases (incident/case records) ───
CREATE TABLE cases (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    alert_id UUID REFERENCES alerts(id) ON DELETE SET NULL,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT CHECK (severity IN ('low','medium','high','critical')),
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','in_progress','resolved','closed','false_positive')),
    category TEXT,
    assigned_to TEXT,
    false_positive BOOLEAN DEFAULT FALSE,
    escalation_required BOOLEAN DEFAULT FALSE,
    escalation_level TEXT,
    risk_score DECIMAL(5,2),
    closed_at TIMESTAMPTZ,
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_cases_tenant ON cases(tenant_id);
CREATE INDEX idx_cases_status ON cases(status);
CREATE INDEX idx_cases_severity ON cases(severity);
CREATE INDEX idx_cases_created ON cases(created_at DESC);
CREATE INDEX idx_cases_assigned ON cases(assigned_to);

-- ─── Analyst Notes ───
CREATE TABLE analyst_notes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    case_id UUID REFERENCES cases(id) ON DELETE CASCADE,
    analyst TEXT NOT NULL,
    note TEXT NOT NULL,
    note_type TEXT DEFAULT 'general' CHECK (note_type IN ('general','investigation','resolution','escalation','feedback')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_notes_case ON analyst_notes(case_id);
CREATE INDEX idx_notes_tenant ON analyst_notes(tenant_id);
CREATE INDEX idx_notes_type ON analyst_notes(note_type);

-- ─── Vulnerabilities (from Wazuh VM) ───
CREATE TABLE vulnerabilities (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    asset_id UUID REFERENCES assets(id) ON DELETE CASCADE,
    cve_id TEXT NOT NULL,
    cvss_score DECIMAL(3,1),
    severity TEXT CHECK (severity IN ('none','low','medium','high','critical')),
    epss_score DECIMAL(5,4),
    cisa_kev BOOLEAN,
    exploitability TEXT,
    package_name TEXT,
    package_version TEXT,
    package_architecture TEXT,
    cve_description TEXT,
    patch_available BOOLEAN,
    patch_sla DATE,
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','in_progress','patched','verified','accepted_risk','false_positive','not_applicable')),
    risk_score DECIMAL(5,2),
    assigned_owner TEXT,
    remediation_notes TEXT,
    exception_approved_by TEXT,
    exception_reason TEXT,
    exception_expires_at TIMESTAMPTZ,
    first_detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    patched_at TIMESTAMPTZ,
    verified_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_vuln_asset ON vulnerabilities(asset_id);
CREATE INDEX idx_vuln_cve ON vulnerabilities(cve_id);
CREATE INDEX idx_vuln_severity ON vulnerabilities(severity);
CREATE INDEX idx_vuln_status ON vulnerabilities(status);
CREATE INDEX idx_vuln_risk ON vulnerabilities(risk_score DESC);
CREATE INDEX idx_vuln_sla ON vulnerabilities(patch_sla) WHERE status NOT IN ('patched','verified','false_positive');
CREATE INDEX idx_vuln_tenant ON vulnerabilities(tenant_id);

-- ─── Generated Reports ───
CREATE TABLE reports (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    report_type TEXT NOT NULL CHECK (report_type IN ('executive','vulnerability','case','compliance')),
    format TEXT NOT NULL CHECK (format IN ('PDF','HTML','JSON')),
    parameters JSONB NOT NULL DEFAULT '{}',
    file_path TEXT,
    file_size BIGINT,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','generating','completed','failed')),
    error_message TEXT,
    created_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ
);
CREATE INDEX idx_reports_tenant ON reports(tenant_id);
CREATE INDEX idx_reports_type ON reports(report_type);
CREATE INDEX idx_reports_status ON reports(status);
CREATE INDEX idx_reports_created_at ON reports(created_at DESC);

-- ─── Audit Log ───
CREATE TABLE audit_log (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT,
    actor TEXT NOT NULL,
    actor_type TEXT DEFAULT 'api_key' CHECK (actor_type IN ('api_key','system','analyst')),
    details JSONB DEFAULT '{}',
    ip_address TEXT,
    user_agent TEXT,
    status TEXT DEFAULT 'success' CHECK (status IN ('success','failure','error')),
    error_message TEXT,
    latency_ms INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_audit_tenant ON audit_log(tenant_id);
CREATE INDEX idx_audit_action ON audit_log(action);
CREATE INDEX idx_audit_created ON audit_log(created_at DESC);
CREATE INDEX idx_audit_resource ON audit_log(resource_type, resource_id);
CREATE INDEX idx_audit_actor ON audit_log(actor);

-- ─── Model Runs (LLM invocation tracking) ───
CREATE TABLE model_runs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    model_name TEXT NOT NULL,
    prompt_hash TEXT,
    input_tokens INTEGER,
    output_tokens INTEGER,
    latency_ms INTEGER,
    success BOOLEAN DEFAULT TRUE,
    error TEXT,
    cost DECIMAL(10,6),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_model_runs_tenant ON model_runs(tenant_id);
CREATE INDEX idx_model_runs_model ON model_runs(model_name);
CREATE INDEX idx_model_runs_created ON model_runs(created_at DESC);

-- ─── System Health (periodic health snapshots) ───
CREATE TABLE system_health (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    component TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('healthy','degraded','down')),
    latency_ms INTEGER,
    details JSONB DEFAULT '{}',
    checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_health_tenant ON system_health(tenant_id);
CREATE INDEX idx_health_component ON system_health(component, checked_at DESC);

-- ─── Seed Data ───
INSERT INTO tenants (id, name, slug) VALUES
    ('00000000-0000-0000-0000-000000000001', 'Default Tenant', 'default');

-- ─── Updated At Triggers ───
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_tenants_updated_at
    BEFORE UPDATE ON tenants FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trg_assets_updated_at
    BEFORE UPDATE ON assets FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trg_cases_updated_at
    BEFORE UPDATE ON cases FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trg_vulnerabilities_updated_at
    BEFORE UPDATE ON vulnerabilities FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

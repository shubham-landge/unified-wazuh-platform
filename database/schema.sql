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
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    manager_label TEXT
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
    feedback_count INTEGER DEFAULT 0,
    avg_rating DECIMAL(3,2),
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

-- ─── Notifications ───
CREATE TABLE notification_channels (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    channel_type TEXT NOT NULL,
    destination TEXT NOT NULL,
    config JSONB DEFAULT '{}',
    severity_filter TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_notification_channels_tenant ON notification_channels(tenant_id);
CREATE INDEX idx_notification_channels_active ON notification_channels(is_active);

CREATE TABLE notification_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    channel_id UUID REFERENCES notification_channels(id) ON DELETE SET NULL,
    name TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT,
    conditions JSONB DEFAULT '{}',
    is_enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_notification_rules_tenant ON notification_rules(tenant_id);
CREATE INDEX idx_notification_rules_channel ON notification_rules(channel_id);
CREATE INDEX idx_notification_rules_enabled ON notification_rules(is_enabled);

CREATE TABLE notification_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    rule_id UUID REFERENCES notification_rules(id) ON DELETE SET NULL,
    channel_id UUID REFERENCES notification_channels(id) ON DELETE SET NULL,
    event_type TEXT NOT NULL,
    payload JSONB DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'pending',
    error_message TEXT,
    sent_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_notification_events_tenant ON notification_events(tenant_id);
CREATE INDEX idx_notification_events_rule ON notification_events(rule_id);
CREATE INDEX idx_notification_events_channel ON notification_events(channel_id);
CREATE INDEX idx_notification_events_created ON notification_events(created_at DESC);

-- ─── SOAR ───
CREATE TABLE soar_playbooks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    description TEXT,
    trigger_type TEXT NOT NULL,
    steps JSONB DEFAULT '[]',
    enabled BOOLEAN DEFAULT TRUE,
    created_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_soar_playbooks_tenant ON soar_playbooks(tenant_id);
CREATE INDEX idx_soar_playbooks_enabled ON soar_playbooks(enabled);

CREATE TABLE soar_tasks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    playbook_id UUID REFERENCES soar_playbooks(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    task_type TEXT NOT NULL,
    parameters JSONB DEFAULT '{}',
    order_index INTEGER DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pending',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_soar_tasks_tenant ON soar_tasks(tenant_id);
CREATE INDEX idx_soar_tasks_playbook ON soar_tasks(playbook_id);
CREATE INDEX idx_soar_tasks_status ON soar_tasks(status);

CREATE TABLE soar_executions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    playbook_id UUID REFERENCES soar_playbooks(id) ON DELETE SET NULL,
    task_id UUID REFERENCES soar_tasks(id) ON DELETE SET NULL,
    alert_id UUID REFERENCES alerts(id) ON DELETE SET NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    triggered_by TEXT,
    result JSONB DEFAULT '{}',
    error_message TEXT,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_soar_executions_tenant ON soar_executions(tenant_id);
CREATE INDEX idx_soar_executions_playbook ON soar_executions(playbook_id);
CREATE INDEX idx_soar_executions_task ON soar_executions(task_id);
CREATE INDEX idx_soar_executions_status ON soar_executions(status);

-- ─── SOAR Playbooks (Claude SOAR engine — denormalized) ───
CREATE TABLE playbooks (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    trigger JSONB NOT NULL DEFAULT '{}',
    actions JSONB NOT NULL DEFAULT '[]',
    priority INTEGER DEFAULT 100,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_playbooks_active ON playbooks(is_active) WHERE is_active = TRUE;

CREATE TABLE playbook_runs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    playbook_id UUID NOT NULL REFERENCES playbooks(id) ON DELETE CASCADE,
    alert_id UUID REFERENCES alerts(id) ON DELETE SET NULL,
    case_id UUID REFERENCES cases(id) ON DELETE SET NULL,
    status TEXT DEFAULT 'pending',
    actions_completed INTEGER DEFAULT 0,
    actions_total INTEGER DEFAULT 0,
    error TEXT,
    result JSONB,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_playbook_runs_playbook ON playbook_runs(playbook_id);
CREATE INDEX idx_playbook_runs_alert ON playbook_runs(alert_id);

-- ─── Threat Intel ───
CREATE TABLE threat_intel_feeds (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    source_url TEXT NOT NULL,
    feed_type TEXT NOT NULL,
    refresh_interval_minutes INTEGER NOT NULL DEFAULT 60,
    parser_config JSONB DEFAULT '{}',
    last_fetched_at TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_threat_feeds_tenant ON threat_intel_feeds(tenant_id);
CREATE INDEX idx_threat_feeds_active ON threat_intel_feeds(is_active);

CREATE TABLE threat_intel_indicators (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    feed_id UUID REFERENCES threat_intel_feeds(id) ON DELETE SET NULL,
    indicator_type TEXT NOT NULL,
    value TEXT NOT NULL,
    confidence DECIMAL(3,2),
    severity TEXT,
    context JSONB DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'active',
    first_seen_at TIMESTAMPTZ,
    last_seen_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_threat_indicators_tenant ON threat_intel_indicators(tenant_id);
CREATE INDEX idx_threat_indicators_feed ON threat_intel_indicators(feed_id);
CREATE INDEX idx_threat_indicators_type ON threat_intel_indicators(indicator_type);
CREATE INDEX idx_threat_indicators_status ON threat_intel_indicators(status);
CREATE INDEX idx_threat_indicators_expires ON threat_intel_indicators(expires_at);

-- ─── Threat Intel IOCs (automated TI polling — AlienVault, MISP, VirusTotal) ───
CREATE TABLE threat_intel_iocs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    ioc_type TEXT NOT NULL,
    ioc_value TEXT NOT NULL,
    source TEXT NOT NULL,
    threat_score DECIMAL(5,2),
    confidence DECIMAL(3,2),
    malware_families JSONB DEFAULT '[]',
    tags JSONB DEFAULT '[]',
    raw_data JSONB,
    is_active BOOLEAN DEFAULT TRUE,
    first_seen TIMESTAMPTZ,
    last_seen TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX idx_ti_iocs_source_value ON threat_intel_iocs(source, ioc_value);
CREATE INDEX idx_ti_iocs_type_value ON threat_intel_iocs(ioc_type, ioc_value);
CREATE INDEX idx_ti_iocs_active ON threat_intel_iocs(is_active) WHERE is_active = TRUE;

CREATE TABLE alert_ioc_matches (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    alert_id UUID NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    ioc_id UUID NOT NULL REFERENCES threat_intel_iocs(id) ON DELETE CASCADE,
    matched_field TEXT NOT NULL,
    matched_value TEXT NOT NULL,
    threat_score DECIMAL(5,2),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_alert_ioc_matches_alert ON alert_ioc_matches(alert_id);

-- ─── UEBA ───
CREATE TABLE ueba_baselines (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    subject_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    metric_name TEXT NOT NULL,
    baseline_value DOUBLE PRECISION,
    stddev DOUBLE PRECISION,
    window_days INTEGER DEFAULT 30,
    status TEXT NOT NULL DEFAULT 'active',
    n INTEGER DEFAULT 0,
    mean DOUBLE PRECISION DEFAULT 0.0,
    m2 DOUBLE PRECISION DEFAULT 0.0,
    last_updated TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_ueba_baselines_tenant ON ueba_baselines(tenant_id);
CREATE INDEX idx_ueba_baselines_subject ON ueba_baselines(subject_type, subject_id);
CREATE INDEX idx_ueba_baselines_metric ON ueba_baselines(metric_name);

CREATE TABLE ueba_anomalies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    baseline_id UUID REFERENCES ueba_baselines(id) ON DELETE SET NULL,
    alert_id UUID REFERENCES alerts(id) ON DELETE SET NULL,
    subject_type TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    anomaly_type TEXT NOT NULL,
    score DOUBLE PRECISION,
    severity TEXT,
    description TEXT,
    features JSONB DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'new',
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reviewed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_ueba_anomalies_tenant ON ueba_anomalies(tenant_id);
CREATE INDEX idx_ueba_anomalies_baseline ON ueba_anomalies(baseline_id);
CREATE INDEX idx_ueba_anomalies_alert ON ueba_anomalies(alert_id);
CREATE INDEX idx_ueba_anomalies_subject ON ueba_anomalies(subject_type, subject_id);
CREATE INDEX idx_ueba_anomalies_status ON ueba_anomalies(status);
CREATE INDEX idx_ueba_anomalies_detected ON ueba_anomalies(detected_at DESC);

-- ─── OSINT ───
CREATE TABLE osint_targets (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    target_type TEXT NOT NULL,
    target_value TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_osint_targets_tenant ON osint_targets(tenant_id);
CREATE INDEX idx_osint_targets_type ON osint_targets(target_type);
CREATE INDEX idx_osint_targets_created ON osint_targets(created_at DESC);

CREATE TABLE osint_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    target_id UUID NOT NULL REFERENCES osint_targets(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    profile_url TEXT,
    name TEXT,
    location TEXT,
    raw_data JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_osint_results_target ON osint_results(target_id);
CREATE INDEX idx_osint_results_source ON osint_results(source);
CREATE INDEX idx_osint_results_created ON osint_results(created_at DESC);

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
    accuracy DECIMAL(3,2),
    total_feedback INTEGER,
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

CREATE TRIGGER trg_notification_channels_updated_at
    BEFORE UPDATE ON notification_channels FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trg_notification_rules_updated_at
    BEFORE UPDATE ON notification_rules FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trg_soar_playbooks_updated_at
    BEFORE UPDATE ON soar_playbooks FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trg_soar_tasks_updated_at
    BEFORE UPDATE ON soar_tasks FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trg_threat_intel_feeds_updated_at
    BEFORE UPDATE ON threat_intel_feeds FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trg_threat_intel_indicators_updated_at
    BEFORE UPDATE ON threat_intel_indicators FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trg_ueba_baselines_updated_at
    BEFORE UPDATE ON ueba_baselines FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trg_ueba_anomalies_updated_at
    BEFORE UPDATE ON ueba_anomalies FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ─── Phase 3A: Users & RBAC ───
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    email TEXT UNIQUE NOT NULL,
    username TEXT UNIQUE,
    password_hash TEXT,
    oidc_provider TEXT,
    oidc_subject TEXT UNIQUE,
    full_name TEXT,
    role TEXT NOT NULL DEFAULT 'viewer',
    permissions JSONB DEFAULT '[]',
    is_active BOOLEAN DEFAULT TRUE,
    last_login_at TIMESTAMPTZ,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_tenant ON users(tenant_id);
CREATE INDEX idx_users_oidc_subject ON users(oidc_subject);

-- ─── Legacy API Keys (Phase 1-2 backward compat) ───
CREATE TABLE api_keys_phase3a (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    key_prefix TEXT UNIQUE NOT NULL,
    key_hash TEXT UNIQUE NOT NULL,
    label TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    last_used_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_api_keys_hash ON api_keys_phase3a(key_hash);

-- ─── Alert Deduplication / Incident Grouping ───
CREATE TABLE alert_incidents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    group_key TEXT NOT NULL,
    rule_id INTEGER,
    rule_description TEXT,
    agent_id TEXT,
    source_ip TEXT,
    alert_count INTEGER DEFAULT 1,
    severity TEXT,
    status TEXT DEFAULT 'open',
    first_alert_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_alert_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    correlation_window_minutes INTEGER DEFAULT 120,
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_alert_incidents_group_key ON alert_incidents(group_key);
CREATE INDEX idx_alert_incidents_tenant ON alert_incidents(tenant_id);
CREATE INDEX idx_alert_incidents_status ON alert_incidents(status);

-- ─── Report Scheduling ───
CREATE TABLE report_schedules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    name TEXT NOT NULL,
    description TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    report_type TEXT NOT NULL,
    cron_expression TEXT NOT NULL,
    parameters JSONB DEFAULT '{}',
    delivery_method TEXT DEFAULT 'email',
    recipients JSONB DEFAULT '[]',
    cc_recipients JSONB DEFAULT '[]',
    last_run_at TIMESTAMPTZ,
    last_run_status TEXT,
    next_run_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_report_schedules_tenant ON report_schedules(tenant_id);
CREATE INDEX idx_report_schedules_active ON report_schedules(is_active);

CREATE TABLE report_deliveries (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    schedule_id UUID NOT NULL REFERENCES report_schedules(id) ON DELETE CASCADE,
    report_id UUID,
    status TEXT DEFAULT 'pending',
    error_message TEXT,
    recipient_count INTEGER DEFAULT 0,
    delivery_method TEXT,
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ
);
CREATE INDEX idx_report_deliveries_schedule ON report_deliveries(schedule_id);

-- ─── User Feedback (analyst verdicts on AI triage) ───
CREATE TABLE user_feedback (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    triage_result_id UUID NOT NULL REFERENCES ai_triage_results(id) ON DELETE CASCADE,
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
    category_correct BOOLEAN,
    severity_correct BOOLEAN,
    correction_text TEXT,
    corrected_category VARCHAR(255),
    corrected_severity VARCHAR(16),
    corrected_confidence DECIMAL(3,2),
    reviewed_by UUID,
    reviewed_at TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX idx_feedback_triage ON user_feedback(triage_result_id);
CREATE INDEX idx_feedback_tenant ON user_feedback(tenant_id);
CREATE INDEX idx_feedback_created ON user_feedback(created_at DESC);

-- ─── Knowledge Base (RAG vector store) ───
CREATE TABLE knowledge_chunks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    chunk_text TEXT NOT NULL,
    embedding JSONB,
    metadata JSONB DEFAULT '{}',
    token_count INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_knowledge_source ON knowledge_chunks(source);
CREATE INDEX idx_knowledge_tenant ON knowledge_chunks(tenant_id);
CREATE INDEX idx_knowledge_created ON knowledge_chunks(created_at DESC);

-- ─── Compliance Frameworks ───
CREATE TABLE compliance_frameworks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    version TEXT NOT NULL DEFAULT '1.0',
    description TEXT,
    total_controls INTEGER DEFAULT 0,
    compliant_controls INTEGER DEFAULT 0,
    score DECIMAL(5,2) DEFAULT 0.00,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE compliance_controls (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    framework_id UUID NOT NULL REFERENCES compliance_frameworks(id) ON DELETE CASCADE,
    control_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    category TEXT,
    severity TEXT CHECK (severity IN ('low','medium','high','critical')),
    status TEXT NOT NULL DEFAULT 'unknown' CHECK (status IN ('compliant','non_compliant','warning','unknown','not_applicable')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(framework_id, control_id)
);
CREATE INDEX idx_controls_framework ON compliance_controls(framework_id);
CREATE INDEX idx_controls_status ON compliance_controls(status);

CREATE TABLE compliance_mappings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    control_id UUID NOT NULL REFERENCES compliance_controls(id) ON DELETE CASCADE,
    rule_id INTEGER,
    rule_level_min INTEGER DEFAULT 0,
    cve_pattern TEXT,
    mitre_technique TEXT,
    description TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_mappings_control ON compliance_mappings(control_id);
CREATE INDEX idx_mappings_rule ON compliance_mappings(rule_id);

CREATE TABLE compliance_exceptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    control_id UUID NOT NULL REFERENCES compliance_controls(id) ON DELETE CASCADE,
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    reason TEXT NOT NULL,
    requested_by UUID,
    approved_by UUID,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected','expired')),
    duration_days INTEGER DEFAULT 30,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_exceptions_control ON compliance_exceptions(control_id);
CREATE INDEX idx_exceptions_status ON compliance_exceptions(status);
CREATE INDEX idx_exceptions_tenant ON compliance_exceptions(tenant_id);

-- ─── Multi-Agent Orchestration ───
CREATE TABLE agent_definitions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    agent_type VARCHAR(64) NOT NULL,
    autonomy_level VARCHAR(16) NOT NULL DEFAULT 'approval',  -- read-only | approval | full
    config JSONB DEFAULT '{}',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_agent_definitions_active ON agent_definitions(is_active) WHERE is_active = TRUE;

CREATE TABLE agent_runs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    definition_id UUID NOT NULL REFERENCES agent_definitions(id) ON DELETE CASCADE,
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    trigger_type VARCHAR(32) NOT NULL DEFAULT 'manual',
    trigger_ref VARCHAR(255),
    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    result_summary TEXT,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_agent_runs_definition ON agent_runs(definition_id);
CREATE INDEX idx_agent_runs_tenant ON agent_runs(tenant_id);
CREATE INDEX idx_agent_runs_status ON agent_runs(status);
CREATE INDEX idx_agent_runs_created ON agent_runs(created_at DESC);

CREATE TABLE agent_tasks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id UUID NOT NULL REFERENCES agent_runs(id) ON DELETE CASCADE,
    parent_task_id UUID,
    agent_type VARCHAR(64) NOT NULL,
    input_data JSONB DEFAULT '{}',
    output_data JSONB,
    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    error TEXT,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_agent_tasks_run ON agent_tasks(run_id);
CREATE INDEX idx_agent_tasks_status ON agent_tasks(status);

-- ─── Triggers ───
CREATE TABLE approval_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    requested_by VARCHAR(255) NOT NULL,
    action_type VARCHAR(64) NOT NULL,
    action_params JSONB NOT NULL,
    target_ref VARCHAR(255),
    rationale TEXT NOT NULL,
    risk_level VARCHAR(16) NOT NULL,
    status VARCHAR(16) NOT NULL DEFAULT 'pending',
    reviewed_by VARCHAR(255),
    review_comment TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_approval_requests_tenant ON approval_requests(tenant_id);
CREATE INDEX idx_approval_requests_status ON approval_requests(status);

CREATE TRIGGER trg_users_updated_at
    BEFORE UPDATE ON users FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trg_alert_incidents_updated_at
    BEFORE UPDATE ON alert_incidents FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trg_report_schedules_updated_at
    BEFORE UPDATE ON report_schedules FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ─── Ticketing Integrations ───
CREATE TABLE ticketing_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    config JSONB DEFAULT '{}',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE ticket_links (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    case_id UUID NOT NULL,
    provider TEXT NOT NULL,
    remote_ticket_id TEXT NOT NULL,
    remote_ticket_url TEXT,
    sync_status TEXT DEFAULT 'pending',
    last_synced_at TIMESTAMPTZ,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_ticket_links_case ON ticket_links(case_id);
CREATE INDEX idx_ticket_links_provider ON ticket_links(provider);

CREATE TRIGGER trg_ticketing_configs_updated_at
    BEFORE UPDATE ON ticketing_configs FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER trg_approval_requests_updated_at
    BEFORE UPDATE ON approval_requests FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ─── Usage Metering (Track E) ───
CREATE TABLE tenant_usage (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    period_start TIMESTAMPTZ NOT NULL,
    period_end TIMESTAMPTZ NOT NULL,
    alerts_count INTEGER DEFAULT 0,
    api_calls_count INTEGER DEFAULT 0,
    cases_count INTEGER DEFAULT 0,
    agents_count INTEGER DEFAULT 0,
    storage_mb DOUBLE PRECISION DEFAULT 0.0,
    ai_triage_count INTEGER DEFAULT 0,
    report_count INTEGER DEFAULT 0,
    total_score INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_tenant_usage_tenant ON tenant_usage(tenant_id);
CREATE INDEX idx_tenant_usage_period ON tenant_usage(tenant_id, period_start, period_end);

CREATE TABLE usage_records (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    resource_id TEXT,
    resource_type TEXT NOT NULL,
    extra_meta JSONB DEFAULT '{}',
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_usage_records_tenant ON usage_records(tenant_id);
CREATE INDEX idx_usage_records_event ON usage_records(event_type);
CREATE INDEX idx_usage_records_recorded ON usage_records(recorded_at);

CREATE TRIGGER trg_tenant_usage_updated_at
    BEFORE UPDATE ON tenant_usage FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ─── Credential Leak Monitoring ───
CREATE TABLE credential_leaks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    target TEXT NOT NULL,
    target_type TEXT DEFAULT 'email' CHECK (target_type IN ('email', 'domain')),
    breach_name TEXT NOT NULL,
    breach_date TEXT,
    compromised_data JSONB DEFAULT '[]',
    breach_description TEXT,
    is_acknowledged BOOLEAN DEFAULT FALSE,
    acknowledged_at TIMESTAMPTZ,
    acknowledged_by TEXT,
    source TEXT DEFAULT 'hibp',
    raw_data JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_credential_leaks_tenant ON credential_leaks(tenant_id);
CREATE INDEX idx_credential_leaks_tenant_created ON credential_leaks(tenant_id, created_at);
CREATE INDEX idx_credential_leaks_target ON credential_leaks(target);

CREATE TRIGGER trg_credential_leaks_updated_at
    BEFORE UPDATE ON credential_leaks FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();


-- ═══════════════════════════════════════════════════════════════════════════
-- Phase 9 — Detection Beyond the Endpoint
-- Entity extraction, cross-domain stitching, kill-chain tracking
-- ═══════════════════════════════════════════════════════════════════════════

-- Normalized entities extracted from every alert (cheap, no LLM).
CREATE TABLE entities (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    entity_type  VARCHAR(24) NOT NULL,   -- user | host | ip | principal | session | device
    value        VARCHAR(512) NOT NULL,  -- normalized (lowercased UPN, canonical IP, ARN, ...)
    risk_score   NUMERIC(5,2) DEFAULT 0,
    first_seen   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen    TIMESTAMPTZ NOT NULL DEFAULT now(),
    tags         JSONB DEFAULT '{}',
    UNIQUE (tenant_id, entity_type, value)
);
CREATE INDEX ix_entities_tenant_type_value ON entities (tenant_id, entity_type, value);

-- Links extracted entities to the alert they came from, with role designations.
CREATE TABLE alert_entities (
    alert_id   UUID NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    entity_id  UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    role       VARCHAR(16) NOT NULL DEFAULT 'observed',  -- actor | target | source | dest | observed
    PRIMARY KEY (alert_id, entity_id, role)
);

-- Entities that define an incident's identity (the stitching backbone).
CREATE TABLE incident_entities (
    incident_id UUID NOT NULL REFERENCES alert_incidents(id) ON DELETE CASCADE,
    entity_id   UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    PRIMARY KEY (incident_id, entity_id)
);

-- Extend alerts for cross-domain detection (identity/cloud/saas).
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS source_type VARCHAR(24) DEFAULT 'endpoint';
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS principal   VARCHAR(512);
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS session_id  VARCHAR(256);

-- Extend alert_incidents for cross-domain stitching and kill-chain tracking.
ALTER TABLE alert_incidents ADD COLUMN IF NOT EXISTS cross_domain      BOOLEAN     DEFAULT false;
ALTER TABLE alert_incidents ADD COLUMN IF NOT EXISTS source_domains    JSONB       DEFAULT '[]';
ALTER TABLE alert_incidents ADD COLUMN IF NOT EXISTS kill_chain_stage  VARCHAR(24) DEFAULT 'unknown';
ALTER TABLE alert_incidents ADD COLUMN IF NOT EXISTS stage_history     JSONB       DEFAULT '[]';
ALTER TABLE alert_incidents ADD COLUMN IF NOT EXISTS sla_due_at        TIMESTAMPTZ;
ALTER TABLE alert_incidents ADD COLUMN IF NOT EXISTS first_enriched_at TIMESTAMPTZ;

-- Extend agent_definitions: autonomy level gate for orchestration policy guard.
ALTER TABLE agent_definitions ADD COLUMN IF NOT EXISTS autonomy_level VARCHAR(16) NOT NULL DEFAULT 'approval';

-- ─── Phase 9.x: composite indexes for tenant-scoped time-range queries ───
-- The hot path on every list endpoint is "WHERE tenant_id = ? ORDER BY created_at DESC".
CREATE INDEX IF NOT EXISTS idx_alerts_tenant_created ON alerts (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_cases_tenant_created ON cases (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_triage_tenant_created ON ai_triage_results (tenant_id, created_at DESC);

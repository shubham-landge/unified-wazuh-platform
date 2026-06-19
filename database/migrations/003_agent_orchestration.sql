-- ═══════════════════════════════════════════════════════════════════════════
-- Migration 003: Multi-Agent Orchestration tables + seed data
-- Run: psql -U soc_user -d soc_platform -f 003_agent_orchestration.sql
-- ═══════════════════════════════════════════════════════════════════════════

-- Agent Definitions (idempotent)
CREATE TABLE IF NOT EXISTS agent_definitions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    agent_type VARCHAR(64) NOT NULL,
    autonomy_level VARCHAR(16) NOT NULL DEFAULT 'approval',
    config JSONB DEFAULT '{}',
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Agent Runs
CREATE TABLE IF NOT EXISTS agent_runs (
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

-- Agent Tasks
CREATE TABLE IF NOT EXISTS agent_tasks (
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

-- Indexes
CREATE INDEX IF NOT EXISTS idx_agent_definitions_active ON agent_definitions(is_active) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_agent_runs_definition ON agent_runs(definition_id);
CREATE INDEX IF NOT EXISTS idx_agent_runs_tenant ON agent_runs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_agent_runs_status ON agent_runs(status);
CREATE INDEX IF NOT EXISTS idx_agent_runs_created ON agent_runs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_agent_tasks_run ON agent_tasks(run_id);
CREATE INDEX IF NOT EXISTS idx_agent_tasks_status ON agent_tasks(status);

-- Add status column to ai_triage_results if not present
ALTER TABLE ai_triage_results ADD COLUMN IF NOT EXISTS status VARCHAR(20) DEFAULT 'completed';

-- Add tenant_id to agent_definitions if not present (TenantMixin requirement)
ALTER TABLE agent_definitions ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE;
CREATE INDEX IF NOT EXISTS idx_agent_definitions_tenant ON agent_definitions(tenant_id);

-- ═══════════════════════════════════════════════════════════════════════════
-- Seed agent definitions (4 core agents)
-- ═══════════════════════════════════════════════════════════════════════════

INSERT INTO agent_definitions (name, description, agent_type, autonomy_level, config, is_active, tenant_id)
SELECT 'Sigma Detection Agent', 'Queries Wazuh indexer for missed detections using Sigma rules. Scans for alerts that bypassed initial triage.', 'sigma_detection', 'read-only', '{"poll_interval_hours": 24, "indexer_index": "wazuh-alerts-*", "max_results": 200}', TRUE, '00000000-0000-0000-0000-000000000001'
WHERE NOT EXISTS (SELECT 1 FROM agent_definitions WHERE name = 'Sigma Detection Agent');

INSERT INTO agent_definitions (name, description, agent_type, autonomy_level, config, is_active, tenant_id)
SELECT 'Correlation Agent', 'Correlates related alerts by source IP, user, or MITRE technique within time windows. Identifies multi-stage attack chains.', 'correlation', 'approval', '{"correlation_window_minutes": 120, "group_by": ["source_ip", "user_name", "mitre_technique"], "min_alerts_for_chain": 3}', TRUE, '00000000-0000-0000-0000-000000000001'
WHERE NOT EXISTS (SELECT 1 FROM agent_definitions WHERE name = 'Correlation Agent');

INSERT INTO agent_definitions (name, description, agent_type, autonomy_level, config, is_active, tenant_id)
SELECT 'Risk Scoring Agent', 'Enriches alerts with CVSS/EPSS scores, asset criticality, and threat intel context. Computes composite risk scores.', 'risk_scoring', 'read-only', '{"cve_lookback_days": 30, "criticality_weight": 0.3, "ti_weight": 0.2, "severity_weight": 0.5}', TRUE, '00000000-0000-0000-0000-000000000001'
WHERE NOT EXISTS (SELECT 1 FROM agent_definitions WHERE name = 'Risk Scoring Agent');

INSERT INTO agent_definitions (name, description, agent_type, autonomy_level, config, is_active, tenant_id)
SELECT 'Meta Agent', 'Orchestrates and synthesizes outputs from all agents. Generates consolidated incident summaries and recommends response actions.', 'meta_agent', 'approval', '{"synthesis_window_minutes": 30, "require_approval_for": ["case_creation", "auto_respond"]}', TRUE, '00000000-0000-0000-0000-000000000001'
WHERE NOT EXISTS (SELECT 1 FROM agent_definitions WHERE name = 'Meta Agent');
-- Migration 005: Create entities tables (missing from migrations)
-- These tables are defined in schema.sql but missing from migrations
-- Created manually during deployment, now adding proper migration

-- Entities table for normalized entities extracted from alerts
CREATE TABLE IF NOT EXISTS entities (
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
CREATE INDEX IF NOT EXISTS ix_entities_tenant_type_value ON entities (tenant_id, entity_type, value);

-- Links extracted entities to the alert they came from, with role designations
CREATE TABLE IF NOT EXISTS alert_entities (
    alert_id   UUID NOT NULL REFERENCES alerts(id) ON DELETE CASCADE,
    entity_id  UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    role       VARCHAR(16) NOT NULL DEFAULT 'observed',  -- actor | target | source | dest | observed
    PRIMARY KEY (alert_id, entity_id, role)
);

-- Entities that define an incident's identity (the stitching backbone)
CREATE TABLE IF NOT EXISTS incident_entities (
    incident_id UUID NOT NULL REFERENCES alert_incidents(id) ON DELETE CASCADE,
    entity_id   UUID NOT NULL REFERENCES entities(id) ON DELETE CASCADE,
    PRIMARY KEY (incident_id, entity_id)
);

-- Add indexes for performance
CREATE INDEX IF NOT EXISTS idx_alert_entities_alert ON alert_entities(alert_id);
CREATE INDEX IF NOT EXISTS idx_alert_entities_entity ON alert_entities(entity_id);
CREATE INDEX IF NOT EXISTS idx_incident_entities_incident ON incident_entities(incident_id);
CREATE INDEX IF NOT EXISTS idx_incident_entities_entity ON incident_entities(entity_id);

-- Note: The alert_incidents table already has columns for cross_domain, source_domains, kill_chain_stage
-- These were added via ALTER TABLE statements in schema.sql (lines 1053-1058)
-- The migration should also ensure these columns exist (they should from schema.sql)

-- Verify that the alert_incidents table has the required columns
DO $$
BEGIN
    -- Check if cross_domain column exists
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'alert_incidents' AND column_name = 'cross_domain') THEN
        ALTER TABLE alert_incidents ADD COLUMN cross_domain BOOLEAN DEFAULT false;
    END IF;
    
    -- Check if source_domains column exists
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'alert_incidents' AND column_name = 'source_domains') THEN
        ALTER TABLE alert_incidents ADD COLUMN source_domains JSONB DEFAULT '[]';
    END IF;
    
    -- Check if kill_chain_stage column exists
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'alert_incidents' AND column_name = 'kill_chain_stage') THEN
        ALTER TABLE alert_incidents ADD COLUMN kill_chain_stage VARCHAR(24) DEFAULT 'unknown';
    END IF;
    
    -- Check if stage_history column exists
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'alert_incidents' AND column_name = 'stage_history') THEN
        ALTER TABLE alert_incidents ADD COLUMN stage_history JSONB DEFAULT '[]';
    END IF;
    
    -- Check if sla_due_at column exists
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'alert_incidents' AND column_name = 'sla_due_at') THEN
        ALTER TABLE alert_incidents ADD COLUMN sla_due_at TIMESTAMPTZ;
    END IF;
    
    -- Check if first_enriched_at column exists
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'alert_incidents' AND column_name = 'first_enriched_at') THEN
        ALTER TABLE alert_incidents ADD COLUMN first_enriched_at TIMESTAMPTZ;
    END IF;
END $$;

COMMENT ON TABLE entities IS 'Normalized entities extracted from every alert (cheap, no LLM)';
COMMENT ON TABLE alert_entities IS 'Links extracted entities to the alert they came from, with role designations';
COMMENT ON TABLE incident_entities IS 'Entities that define an incident\'s identity (the stitching backbone)';
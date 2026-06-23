-- Migration 006: Add incident_id foreign key to cases table
-- Run: psql -U soc_user -d soc_platform -f 006_case_incident_fk.sql

-- Add incident_id column to cases table
ALTER TABLE cases
ADD COLUMN IF NOT EXISTS incident_id UUID REFERENCES alert_incidents(id) ON DELETE SET NULL;

-- Create index for performance
CREATE INDEX IF NOT EXISTS idx_cases_incident ON cases(incident_id);

-- Add comment
COMMENT ON COLUMN cases.incident_id IS 'Foreign key to alert_incidents table for incident-level case tracking';

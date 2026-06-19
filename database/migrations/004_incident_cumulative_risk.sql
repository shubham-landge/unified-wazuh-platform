-- Migration: Add cumulative_risk_score to alert_incidents
-- Created: 2025-06-19
-- Purpose: Track cumulative risk score per incident for auto-case threshold

ALTER TABLE alert_incidents
ADD COLUMN IF NOT EXISTS cumulative_risk_score INTEGER NOT NULL DEFAULT 0;

-- Index for threshold queries
CREATE INDEX IF NOT EXISTS idx_alert_incidents_cumulative_risk
ON alert_incidents(cumulative_risk_score)
WHERE status != 'closed';

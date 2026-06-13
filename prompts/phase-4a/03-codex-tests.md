# Phase 4A — Codex: Tests + Validation

## Goal
Write comprehensive tests for Phase 4A features: CaseEvent model, investigation steps, timeline endpoint, auto-logging, triage_worker risk scoring, and dashboard template rendering.

## Test files to create/modify

### 1. `tests/test_phase4a.py` (new)
Test categories and specific tests:

### CaseEvent Model Tests
- test_case_event_creation: verify all fields set correctly
- test_case_event_auto_log_status_change: PATCH /cases/{id} with new status → verify CaseEvent created with old_value/new_value
- test_case_event_auto_log_note: POST /cases/{id}/notes → verify event_type="note_added"
- test_case_event_auto_log_assignment: PATCH /cases/{id} with assigned_to → verify event_type="assigned"

### Investigation Step Tests
- test_create_investigation_step: verify model creation
- test_mark_step_complete: PATCH /cases/{id}/steps/{step_id} → verify completed=true, completed_at set
- test_list_steps_ordered: verify steps returned in `order` asc
- test_auto_create_steps_from_triage: mock triage_worker creating case with investigation_steps → verify steps created

### Timeline Endpoint Tests
- test_timeline_pagination: verify limit/offset work
- test_timeline_event_type_filter: verify ?event_type=status_changed filters correctly

### Risk Score Tests
- test_risk_score_computation: verify formula confidence * (1-fp) * (level/15) * 10
- test_triage_worker_sets_risk_score: mock triage_worker → verify case.risk_score set

### Dashboard Rendering Tests
- test_triage_partial_renders_dynamic_steps: verify investigation_steps appear in rendered HTML
- test_timeline_partial_renders_events: verify timeline partial renders each event type

### Bug Fix Validation
- test_bulk_status_update: verify all selected cases get updated
- test_bulk_status_response: verify correct count returned

## Testing approach
Use the same pattern as existing tests: MagicMock for DB, ASGITransport for API, direct template rendering for dashboard.

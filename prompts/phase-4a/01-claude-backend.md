# Phase 4A — Claude: Case Timeline + Investigation Steps (Backend)

## Goal
Build structured timeline events for cases and investigation checklist items. Auto-log status changes, add risk scoring to auto-created cases.

## Files to create/modify

### 1. `shared/models/case_event.py` (new)
`CaseEvent` model:
- id: UUID PK
- case_id: UUID FK -> cases, indexed
- tenant_id: UUID | None, indexed
- event_type: str(32) — case_created, status_changed, note_added, triage_run, assigned, step_completed, resolved, closed
- actor_id: UUID | None
- actor_name: str(255) | None
- old_value: str(255) | None
- new_value: str(255) | None
- description: text | None
- metadata: JSON | None
- created_at: datetime(tz)

### 2. `shared/models/case_investigation_step.py` (new)
`CaseInvestigationStep` model:
- id: UUID PK
- case_id: UUID FK -> cases, indexed
- tenant_id: UUID | None
- description: text
- order: int (default 0)
- completed: bool (default false)
- completed_by: UUID | None
- completed_at: datetime(tz) | None
- created_at: datetime(tz)

### 3. `shared/models/__init__.py`
Add CaseEvent, CaseInvestigationStep imports

### 4. `services/api/app/routers/cases.py` — major update
Add endpoints:
- `GET /cases/{case_id}/timeline` — paginated timeline events, ordered by created_at desc. Query params: limit (default 50), offset, event_type filter
- `GET /cases/{case_id}/steps` — list investigation steps ordered by `order`
- `PATCH /cases/{case_id}/steps/{step_id}` — mark step complete (set completed=true, completed_by=current_user, completed_at=now)

Auto-log CaseEvent on:
- POST /cases → event_type="case_created"
- PATCH /cases/{id} when status changes → event_type="status_changed", old_value=old_status, new_value=new_status
- POST /cases/{id}/notes → event_type="note_added", metadata={"note_type": note_type}
- PATCH /cases/{id} when assigned_to changes → event_type="assigned", old_value=old_assignee, new_value=new_assignee

### 5. `services/worker/app/triage_worker.py`
When creating a case from LLM escalation:
- Set risk_score: use LLM confidence, false_positive_likelihood, rule_level to compute (e.g., risk_score = confidence * (1 - false_positive_likelihood) * min(rule_level/15, 1) * 10)
- Create CaseInvestigationStep rows from investigation_steps JSON array in the triage result
- Auto-create CaseEvent for triage sourcing

### 6. `shared/soar/actions.py`
Same risk_score logic when SOAR action creates a case. Create investigation steps if the action payload includes them.

### 7. `shared/models/case.py`
No changes needed — risk_score field already exists.

### 8. Retroactive migration helper function
Add a function in `services/api/app/routers/cases.py` or a new `services/worker/app/case_migration.py`:
- Iterates existing cases, creates case_created events
- Iterates existing notes, creates note_added events
- Creates resolved/closed events for cases with closed_at set
- Can be triggered as a one-off script

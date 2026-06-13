# Phase 3B — Claude: Feedback Loop

## Goal
Build the backend for collecting and processing user feedback on AI triage results.

## Files to create/modify

### 1. `shared/models/feedback.py` (new)
`UserFeedback` model:
- id: UUID PK
- triage_result_id: UUID FK -> ai_triage_results
- tenant_id: UUID, indexed
- rating: int (1-5)
- category_correct: bool | None
- severity_correct: bool | None
- correction_text: text | None
- corrected_category: str | None
- corrected_severity: str | None
- corrected_confidence: decimal(3,2) | None
- reviewed_by: UUID FK -> users
- reviewed_at: datetime
- created_at: datetime

### 2. `shared/models/ai_triage_result.py`
Add fields: feedback_count (int, default 0), avg_rating (decimal(3,2) | None)

### 3. `services/api/app/routers/triage.py`
Add endpoint:
- `POST /triage/{id}/feedback` — accepts rating, correction fields; JWT-protected (analyst+); creates UserFeedback; updates AiTriageResult feedback_count/avg_rating; pushes to feedback_queue

### 4. `services/worker/app/feedback_worker.py` (new)
`FeedbackWorker` class:
- Consumes `feedback_queue` Redis list
- Logs metrics: rating distribution, accuracy per model/rule/tenant
- Updates `rule_model_accuracy` tracking (fast vs full model accuracy per rule_id)
- Auto-calibrates confidence: if a model consistently mis-classifies category X, lower confidence for that category
- Follows existing worker pattern (start/stop, Redis brpop)

### 5. `services/worker/app/main.py`
Add `("app.feedback_worker", "FeedbackWorker")` to auto-discovery list

### 6. `shared/config.py`
Add: feedback_enabled (bool, default True)

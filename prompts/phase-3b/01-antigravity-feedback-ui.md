# Phase 3B — Antigravity: Dashboard Feedback UI

## Goal
Add user feedback controls to the alert triage result display, and a feedback analytics page for admins.

## Files to modify

### 1. `services/dashboard/templates/triage_result_partial.html`
Add after the confidence/false-positive gauges:

- **Model name & tier badge**: Show `{{ result.model }}` with a badge ("Fast" / "Full") based on model name
- **Thumbs up / thumbs down buttons**: Two buttons that POST via HTMX to `/triage/{id}/feedback?rating=helpful` or `?rating=not_helpful`
- **Correction form** (expandable/conditional — only shows after thumbs down):
  - Category correction dropdown (recon, malware, phishing, brute_force, etc)
  - Severity correction dropdown (low/medium/high/critical)
  - Free-text correction field
  - Submit button → POST to `/triage/{id}/feedback` with full correction data
- **Existing feedback indicator**: if `result.user_rated` is true, show "You rated this as helpful/not helpful"

### 2. `services/dashboard/app/main.py`
Add proxy routes:
- `POST /feedback/{triage_id}` — proxies to API `POST /triage/{id}/feedback`, returns updated partial
- `GET /feedback` — admin-only analytics page listing feedback entries with accuracy stats

### 3. `services/dashboard/templates/feedback.html` (new)
Admin feedback analytics page:
- Table of feedback entries: triage ID, rating, category/severity corrections, reviewed by, timestamp
- Summary stats: total feedback, avg rating, most-corrected categories, per-model accuracy
- Only accessible by admin role

### 4. `services/dashboard/static/js/triage.js` (or inline in partial)
- Show/hide correction form when thumbs down is clicked
- Disable buttons after voting
- Show success/error toast

## UI/UX requirements
- Thumbs up/down should be styled consistently with the existing dark-theme SOC dashboard
- Correction form should slide down with CSS animation
- Show loading spinner during HTMX requests
- Keep it minimal — don't block the existing triage display

## No new dependencies needed
Stick with existing Jinja2 + HTMX + Alpine.js stack. No npm packages.

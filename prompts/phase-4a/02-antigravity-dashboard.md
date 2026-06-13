# Phase 4A — Antigravity: Case Timeline UI + Investigation Checklist + Bug Fix

## Goal
Render a structured CaseEvent timeline on case detail page, add investigation checklist, fix triage result partial to show dynamic steps, and fix bulk status update bug.

## Files to modify

### 1. `services/dashboard/templates/triage_result_partial.html`
**Fix:** Replace hardcoded "Recommended Actions" and "Critical Restrictions" with dynamic rendering from the triage result:

```html
<div class="border-t border-slate-700 pt-4 mt-4">
  <h4 class="text-sm font-semibold text-slate-300 mb-2">Investigation Steps</h4>
  <ul class="space-y-1">
    {% for step in result.investigation_steps or [] %}
    <li class="flex items-start gap-2 text-sm text-slate-400">
      <span class="text-cyan-400 mt-0.5">→</span>
      <span>{{ step }}</span>
    </li>
    {% endfor %}
  </ul>
</div>
<div class="border-t border-slate-700 pt-4 mt-4">
  <h4 class="text-sm font-semibold text-slate-300 mb-2">Do Not Do</h4>
  <ul class="space-y-1">
    {% for item in result.do_not_do or [] %}
    <li class="flex items-start gap-2 text-sm text-red-400">
      <span class="mt-0.5">✕</span>
      <span>{{ item }}</span>
    </li>
    {% endfor %}
  </ul>
</div>
```

Also add: "Create Case from Investigation" button that POST to `/cases` with pre-filled title, severity, category, and steps from the triage result.

### 2. `services/dashboard/templates/case_detail.html`
**Replace the manual timeline section** (lines ~104-158) with a proper CaseEvent-driven timeline:

- Fetch timeline via HTMX: `hx-get="/cases/{{ case.id }}/timeline" hx-trigger="load"`
- Each event type gets an icon/color:
  - case_created → green circle + "Case Opened"
  - status_changed → amber circle + "Status: open → in_progress"
  - note_added → blue circle + note excerpt
  - triage_run → purple circle + "AI Triage: [summary]"
  - assigned → orange circle + "Assigned to [name]"
  - step_completed → green checkmark + "Step completed: [description]"
  - resolved → green check + "Case Resolved"
  - closed → gray circle + "Case Closed"
- Right-side timestamp for each event
- Click on timeline events to expand details from metadata

**Add investigation checklist panel** (below timeline, above notes):
- Fetch via HTMX: `hx-get="/cases/{{ case.id }}/steps"`
- Render as vertical list with checkboxes
- Checkbox → `hx-patch="/cases/{{ case.id }}/steps/{{ step.id }}"` → marks complete
- "+ Add Step" button at bottom → POST /cases/{id}/steps (inline input, Alpine.js)
- Show completed steps with strikethrough + green check

### 3. `services/dashboard/templates/cases.html`
**Fix bulk status bug**: The current implementation only patches the first selected case. Fix the Alpine.js `bulkUpdateStatus()` function to iterate over all checked cases and send individual PATCH requests via HTXM or a single batch PATCH to a new `/cases/bulk-status` endpoint.

### 4. `services/dashboard/app/main.py`
Add proxy routes:
- `GET /cases/{case_id}/timeline` → proxy to API `GET /cases/{case_id}/timeline`
- `GET /cases/{case_id}/steps` → proxy to API `GET /cases/{case_id}/steps`
- `PATCH /cases/{case_id}/steps/{step_id}` → proxy to API
- `POST /cases/{case_id}/steps` → proxy to API (create manual step)
- `POST /cases/bulk-status` → proxy to API (batch status update)

### 5. `services/dashboard/static/charts.js` or inline
- Timeline animation: fade-in events as they load
- Smooth checkbox transitions

## No new dependencies
Stick with Jinja2 + HTMX + Alpine.js.

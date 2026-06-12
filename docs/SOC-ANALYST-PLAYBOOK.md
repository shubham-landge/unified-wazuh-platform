# SOC Analyst Playbook — Unified Wazuh Platform

## Table of Contents
1. [Overview](#1-overview)
2. [Getting Started](#2-getting-started)
3. [Dashboard Tour](#3-dashboard-tour)
4. [Alert Triage Workflow](#4-alert-triage-workflow)
5. [Case Investigation](#5-case-investigation)
6. [Vulnerability Management](#6-vulnerability-management)
7. [AI Triage Confidence](#7-ai-triage-confidence)
8. [Reporting](#8-reporting)
9. [Escalation Procedures](#9-escalation-procedures)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. Overview

The Unified Wazuh Security Operations Platform is a read-only threat triage and case management layer designed to operate on top of your existing Wazuh enterprise infrastructure. By combining the powerful indexing of Wazuh alerts with a commercial-grade, multi-tenant database schema, the platform automates the initial layers of threat analysis, allowing analysts to prioritize active threats and remediate vulnerabilities faster.

The primary objective of the platform is to reduce "alert fatigue" through a localized, private AI triage copilot. Instead of sending sensitive alerts to public cloud LLMs, the platform integrates with localized Ollama container services to perform cryptographic masking of sensitive assets, conduct MITRE ATT&CK framework mapping, and generate step-by-step containment checklists directly inside your security boundary.

### Key Capabilities
- **AI-Powered Triage**: Every Wazuh alert is automatically analyzed by AI.
- **Case Management**: Structured incident tracking with an interactive vertical timeline.
- **Vulnerability Management**: Risk-prioritized CVE tracking with SLA enforcement.
- **Executive Reporting**: One-click print-ready summaries for management.
- **Multi-Tenant**: Isolated data per customer/site.

### Architecture
For a detailed diagram of the platform modules, see the [System Architecture Diagram](docs/diagrams/system-architecture.md).

---

## 2. Getting Started

As an analyst, you access the system through your web browser via HTTP Port 80 (e.g. `http://localhost/` or your corporate subdomain).
Ensure you have:
1. Your user credentials or dashboard API key.
2. The keyboard shortcut list (press `?` to toggle it overlay).

---

## 3. Dashboard Tour

* **Overview Dashboard**: Renders system health, alertTimeline frequencies, case severity divisions, and active high-risk inventories.
* **Alerts Console**: Serves as the central repository where all incoming events are sorted, filtered, and selected for bulk actions.
* **Case Manager**: Logs ongoing tickets, notes, and containment playbooks.
* **Vulnerability Board**: Evaluates CISA KEV markers and CVSS risk scores.

---

## 4. Alert Triage Workflow

### Step 1: Open the Alerts Page
- Navigate to **Alerts** in the sidebar.
- Alerts are displayed newest-first.
- Use filters: severity, group, agent, time range.

### Step 2: Review the AI Triage Summary
- Each alert shows an AI triage readiness indicator.
- Click any alert to open the detail view.
- The AI Triage Result panel shows:

| Field | What it means |
|---|---|
| Summary | One-line description of the alert |
| Category | Classification (e.g. phishing, malware, recon) |
| Severity | critical/high/medium/low |
| Confidence (0-1) | How confident the AI is in its assessment |
| FP Likelihood (0-1) | How likely this is a false positive |
| MITRE Mapping | ATT&CK tactic + technique IDs |
| Investigation Steps | Ordered checklist for the analyst |
| Do Not Do | Actions to avoid |

### Step 3: Verify the Evidence
- Check the raw alert details.
- Review source IP, user, process, file hash.
- Cross-reference with the Wazuh dashboard.
- Check if related alerts exist for the same agent/IP.

### Step 4: Classify
- **True Positive (TP)**: Alert correctly identifies malicious activity.
- **False Positive (FP)**: Alert triggered by benign activity.
- **Benign True Positive (BTP)**: Alert is accurate but expected (e.g., approved scan).

### Step 5: Take Action
- If TP and critical &rarr; escalate immediately.
- If TP and medium/high &rarr; create investigation case.
- If FP &rarr; mark as false positive with a note explaining why.
- If uncertain &rarr; assign to senior analyst.

### Step 6: Document
- Add analyst note with your findings.
- Update case status: `open` &rarr; `in_progress` &rarr; `resolved` &rarr; `closed`.
- If escalated, note escalation level and recipient.

---

## 5. Case Investigation

1. Open the case details from the **Cases** board.
2. Review the **Investigation Timeline** to see previous analyst actions, notes, and status changes.
3. Log containment actions in the comments box (assign notes type like *Investigation*, *Resolution*, etc.).
4. Close the case once containment is verified.

---

## 6. Vulnerability Management

1. Navigate to **Vulnerabilities** to view prioritized CVEs.
2. **Prioritization Rule**: KEV-status vulnerability &rarr; CVSS &rarr; EPSS probability.
3. Track the **SLA Date** to verify patches before the deadline.

---

## 7. AI Triage Confidence

The AI models output a confidence rating from `0.00` to `1.00`. 
- **Score > 0.85**: Highly reliable. Playbook steps can be executed immediately.
- **Score 0.50 - 0.84**: Moderate. Requires manual validation of process/user context.
- **Score < 0.50**: Low. Verify all threat indicators manually before locking accounts or stopping services.

---

## 8. Reporting

- Open **Reports** from the navigation sidebar.
- Choose template type (Executive, Technical, Compliance), radio output format (PDF, Excel, HTML), and date range.
- Retrieve generated files from the **Report Run History** board.

---

## 9. Escalation Procedures

- **Level 1 Escalation**: Assign the case to a Level 2 SOC analyst for further log review.
- **Level 2 Escalation (Critical Breach)**: Flag `escalation_required = true` on the case. Send a critical email notification to the site administrator and isolate the agent node.

---

## 10. Troubleshooting

- **405 Method Not Allowed**: Verify dashboard proxy endpoints are running and the API backend is healthy.
- **Connection timeouts**: Run `bash deploy/status.sh` to check container availability.

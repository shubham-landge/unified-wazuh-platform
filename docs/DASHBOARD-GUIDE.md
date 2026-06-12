# Unified Wazuh SOC Dashboard User Guide

Welcome to the **Unified Wazuh Security Operations Center (SOC) Dashboard**. This platform sits on top of your existing Wazuh deployment, adding commercial-grade case management, AI triage, vulnerability prioritization, compliance reporting, and executive metrics.

---

## 1. Console Navigation & Shortcuts

The dashboard supports full keyboard-based navigation to speed up analyst response time. Press `?` at any time to open the Keyboard Shortcuts help dialog.

### Shortcuts Reference
* `g` then `o` &rarr; Go to **Overview**
* `g` then `a` &rarr; Go to **Alerts**
* `g` then `c` &rarr; Go to **Cases**
* `g` then `v` &rarr; Go to **Vulnerabilities**
* `⌘K` or `Ctrl+K` &rarr; Open **Search Console**
* `r` &rarr; Refresh current page content via HTMX
* `?` &rarr; Toggle shortcuts help overlay

---

## 2. Overview Dashboard

The **Overview** is the central landing page. It presents executive metrics, live security graphs, and high-risk inventory lists.

* **Stat Cards**: Real-time counters showing Total Alerts (24h), Open Cases, Critical Cases, and prioritized Vulnerabilities. Hovering on any card provides a lift highlight. Left border accents display severity gradients.
* **Alert Timeline (24h)**: Area chart powered by Chart.js displaying security event frequencies per hour.
* **Case Severity Distribution**: Doughnut chart representing the division of active incidents by severity levels (Critical, High, Medium, Low).
* **Recent Alerts**: High-priority alert list with quick-navigation links.
* **Top Vulnerabilities**: Highlight of CVEs presenting the highest prioritised risk scores.

---

## 3. Alerts Console & AI Triage

The **Alerts Console** is where security alerts from the Wazuh manager are indexed and filtered.

### Filtering and Searching
You can filter alerts by:
* **Search input**: Matches descriptions, rule IDs, and IP addresses.
* **Severity level**: Filter by Level 12+ (Critical), Level 10-11 (High), Level 7-9 (Medium), or Level 0-6 (Low).
* **Agent name**: Isolates events to specific hosts.
* **Wazuh Group**: Filters by Wazuh ruleset classification group (e.g., `syslog`, `sshd`, `web`).
* **Time**: Limits results to the last 24 hours or the last 7 days.

### Bulk Actions
* Select alerts by checking row boxes. A float action bar allows you to select "Create Case" to bundle multiple alerts into a single investigation case.

### AI Threat Analysis
Clicking an alert opens the **Alert Details** page. From here, you can trigger the **AI Copilot Threat Analysis**:
1. Click **Analyze Event**.
2. A local LLM is invoked to correlate the signature description.
3. The dashboard renders a triage report containing a **Confidence Score**, **False Positive Likelihood**, **Recommended Actions**, **Critical Restrictions** (things to avoid), and creates a connected database Case.

---

## 4. Case Management & Incident Response

The **Case Manager** tracks long-running security investigations.

* **Create Cases**: Click **New Case** to open the creation modal. Provide Title, Description, Severity, and Category.
* **Incident Lifecycle**: Under **Case Details**, assign owners (analysts), escalate cases, or mark them *In Progress*, *Resolved*, or *Closed*.
* **Investigation Timeline**: A vertical chronological feed displaying dots corresponding to note submissions, assignee adjustments, and status changes.
* **Analyst Action Board**: Log notes with specific labels (e.g. *Investigation Log*, *Resolution Steps*, *Escalation Details*) to document containment and remediation actions.

---

## 5. Vulnerability Prioritization

The **Vulnerabilities Page** helps patch management teams prioritize remediation.

* **CVSS & EPSS Tracking**: Renders CVE severity alongside CVSS and EPSS (Exploit Prediction Scoring System) likelihood percentage gauges.
* **CISA KEV Highlight**: Flags vulnerabilities identified on the CISA Known Exploited Vulnerability catalog with a flashing alert badge.
* **Risk Score Bar**: Prioritised risk is plotted as a colored progress bar (Red = Critical/High, Yellow = Medium, Blue = Low) to quickly identify immediate patching candidates.

---

## 6. Asset & Agent Inventory

The **Assets Page** tracks endpoint properties synchronized from the Wazuh manager.

* **Status Indicators**: Identifies Active vs. Disconnected agents.
* **Criticality Index**: Renders custom machine criticality (1 to 10 scale).
* **OS & Details**: Details kernel distribution names and versions.

---

## 7. Reports & Settings

### Executive Reports
The **Reports Page** allows running security summaries on-demand:
* **Templates**: Executive Security Summary, Technical Vulnerability Report, or Compliance Audit (PCI-DSS/HIPAA).
* **Formats**: PDF, Excel, or HTML.
* **Audit History**: A table logs previous runs, report sizes, and download endpoints.

### Platform Configuration
The **Settings Page** manages connection profiles:
* Dashboard API secret keys.
* Wazuh Manager REST APIs.
* Selected LLM model engines (Ollama Mistral, Llama, Phi, or Gemini Flash).
* Data retention boundaries and agent sync timeouts.

#!/bin/bash
# =============================================================================
# Daily Health Check — Unified Wazuh SOC Platform (Payless)
# -----------------------------------------------------------------------------
# Validates Wazuh manager, indexer, Filebeat, agent connectivity, and the
# platform's own services. Designed to run from cron every morning and email
# (or Slack/Teams) the result.
#
#   Cron example (06:00 daily):
#     0 6 * * *  /opt/soc-platform/scripts/daily-health-check.sh >> /var/log/soc-health.log 2>&1
#
# Env vars (override as needed):
#   WAZUH_MANAGER_HOST   default 127.0.0.1
#   INDEXER_URL          default https://127.0.0.1:9200
#   INDEXER_USER         default admin
#   INDEXER_PASS         (required for indexer checks)
#   PLATFORM_URL         default http://localhost:8000
#   PLATFORM_API_KEY     (required for platform checks)
#   DISCONNECT_WARN_PCT  default 10  (warn if >X% agents disconnected)
#   ALERT_WEBHOOK        optional Slack/Teams webhook for the summary
# =============================================================================
set -uo pipefail

WAZUH_MANAGER_HOST="${WAZUH_MANAGER_HOST:-127.0.0.1}"
INDEXER_URL="${INDEXER_URL:-https://127.0.0.1:9200}"
INDEXER_USER="${INDEXER_USER:-admin}"
INDEXER_PASS="${INDEXER_PASS:-}"
PLATFORM_URL="${PLATFORM_URL:-http://localhost:8000}"
PLATFORM_API_KEY="${PLATFORM_API_KEY:-}"
DISCONNECT_WARN_PCT="${DISCONNECT_WARN_PCT:-10}"
ALERT_WEBHOOK="${ALERT_WEBHOOK:-}"

WARN=0
FAIL=0
SUMMARY=""

note()  { echo "   $1"; SUMMARY="${SUMMARY}\n   $1"; }
ok()    { echo "✅ $1"; SUMMARY="${SUMMARY}\n✅ $1"; }
warn()  { echo "⚠️  $1"; SUMMARY="${SUMMARY}\n⚠️  $1"; WARN=$((WARN+1)); }
bad()   { echo "❌ $1"; SUMMARY="${SUMMARY}\n❌ $1"; FAIL=$((FAIL+1)); }

echo "==================================================================="
echo " Daily SOC Health Check — $(date '+%Y-%m-%d %H:%M:%S %Z')"
echo "==================================================================="

# ---------------------------------------------------------------------------
# 1. Wazuh manager core daemons
# ---------------------------------------------------------------------------
echo ""; echo "── Wazuh Manager ──"
if command -v /var/ossec/bin/wazuh-control >/dev/null 2>&1; then
    STATUS=$(/var/ossec/bin/wazuh-control status 2>/dev/null)
    for daemon in wazuh-analysisd wazuh-remoted wazuh-execd wazuh-db wazuh-modulesd; do
        if echo "$STATUS" | grep -q "${daemon} is running"; then
            ok "${daemon} running"
        else
            bad "${daemon} NOT running"
        fi
    done
else
    note "wazuh-control not found locally — skipping daemon check (remote manager?)"
fi

# ---------------------------------------------------------------------------
# 2. Event queue flooding — analysisd queue usage
# ---------------------------------------------------------------------------
echo ""; echo "── Event Queue ──"
QSTAT="/var/ossec/var/run/wazuh-analysisd.state"
if [ -f "$QSTAT" ]; then
    EVT_USAGE=$(grep -E '^event_queue_usage' "$QSTAT" | cut -d"'" -f2)
    RULE_USAGE=$(grep -E '^rule_matching_queue_usage' "$QSTAT" | cut -d"'" -f2)
    [ -n "$EVT_USAGE" ] && note "event_queue_usage=${EVT_USAGE} rule_matching_queue_usage=${RULE_USAGE:-n/a}"
    # Flag if usage > 0.8 (queue filling up → events dropping)
    if [ -n "$EVT_USAGE" ] && awk "BEGIN{exit !($EVT_USAGE > 0.8)}"; then
        warn "Event queue >80% full — events may be dropping (check rule 1234 / EPS spike)"
    else
        ok "Event queue healthy"
    fi
else
    note "analysisd.state not found — skipping queue check"
fi

# ---------------------------------------------------------------------------
# 3. Wazuh indexer cluster health
# ---------------------------------------------------------------------------
echo ""; echo "── Wazuh Indexer ──"
if [ -n "$INDEXER_PASS" ]; then
    HEALTH=$(curl -sk -u "${INDEXER_USER}:${INDEXER_PASS}" "${INDEXER_URL}/_cluster/health" 2>/dev/null)
    CLUSTER_STATUS=$(echo "$HEALTH" | grep -o '"status":"[a-z]*"' | cut -d'"' -f4)
    case "$CLUSTER_STATUS" in
        green)  ok "Indexer cluster GREEN" ;;
        yellow) warn "Indexer cluster YELLOW — unassigned replicas (single-node is expected yellow)" ;;
        red)    bad "Indexer cluster RED — primary shards unassigned, data unavailable" ;;
        *)      bad "Indexer unreachable at ${INDEXER_URL}" ;;
    esac
    # Disk watermark check
    DISK=$(curl -sk -u "${INDEXER_USER}:${INDEXER_PASS}" "${INDEXER_URL}/_cat/allocation?h=disk.percent" 2>/dev/null | tr -d ' ')
    if [ -n "$DISK" ]; then
        note "Indexer disk used: ${DISK}%"
        awk "BEGIN{exit !($DISK > 85)}" && warn "Indexer disk >85% — approaching flood-stage watermark (95% blocks writes)"
    fi
else
    note "INDEXER_PASS not set — skipping indexer checks"
fi

# ---------------------------------------------------------------------------
# 4. Filebeat → indexer pipeline
# ---------------------------------------------------------------------------
echo ""; echo "── Filebeat Pipeline ──"
if command -v filebeat >/dev/null 2>&1; then
    if filebeat test output 2>&1 | grep -q "talk to server... OK"; then
        ok "Filebeat → indexer output OK"
    else
        bad "Filebeat cannot reach indexer (filebeat test output failed)"
    fi
else
    note "filebeat CLI not found locally — skipping (check via indexer ingest rate instead)"
fi
# Confirm today's alerts index is receiving data
if [ -n "$INDEXER_PASS" ]; then
    TODAY=$(date '+%Y.%m.%d')
    DOC_COUNT=$(curl -sk -u "${INDEXER_USER}:${INDEXER_PASS}" \
        "${INDEXER_URL}/wazuh-alerts-*-${TODAY}/_count" 2>/dev/null | grep -o '"count":[0-9]*' | cut -d: -f2)
    if [ -n "$DOC_COUNT" ] && [ "$DOC_COUNT" -gt 0 ] 2>/dev/null; then
        ok "Alerts index receiving data today (${DOC_COUNT} docs)"
    else
        warn "No alerts indexed today — pipeline may be stalled"
    fi
fi

# ---------------------------------------------------------------------------
# 5. Agent connectivity
# ---------------------------------------------------------------------------
echo ""; echo "── Agents ──"
if command -v /var/ossec/bin/agent_control >/dev/null 2>&1; then
    AGENT_LIST=$(/var/ossec/bin/agent_control -l 2>/dev/null)
    TOTAL=$(echo "$AGENT_LIST" | grep -cE 'ID: [0-9]')
    DISC=$(echo "$AGENT_LIST" | grep -c 'Disconnected')
    NEVER=$(echo "$AGENT_LIST" | grep -c 'Never connected')
    ACTIVE=$(echo "$AGENT_LIST" | grep -c 'Active')
    note "Agents: ${TOTAL} total | ${ACTIVE} active | ${DISC} disconnected | ${NEVER} never connected"
    if [ "$TOTAL" -gt 0 ]; then
        PCT=$(( (DISC + NEVER) * 100 / TOTAL ))
        if [ "$PCT" -gt "$DISCONNECT_WARN_PCT" ]; then
            warn "${PCT}% of agents are down (threshold ${DISCONNECT_WARN_PCT}%) — see enrollment-failure dashboard"
        else
            ok "Agent connectivity within threshold (${PCT}% down)"
        fi
    fi
else
    note "agent_control not found locally — query via platform API instead"
    if [ -n "$PLATFORM_API_KEY" ]; then
        curl -s -H "X-API-Key: ${PLATFORM_API_KEY}" "${PLATFORM_URL}/agents/health" 2>/dev/null | head -c 400
    fi
fi

# ---------------------------------------------------------------------------
# 6. Platform services (API, worker, dashboard, redis, postgres)
# ---------------------------------------------------------------------------
echo ""; echo "── SOC Platform Services ──"
API_HEALTH=$(curl -s -o /dev/null -w "%{http_code}" "${PLATFORM_URL}/health" 2>/dev/null)
[ "${API_HEALTH:0:1}" = "2" ] && ok "Platform API healthy (${API_HEALTH})" || bad "Platform API unhealthy (${API_HEALTH})"

if [ -n "$PLATFORM_API_KEY" ]; then
    # Agent worker queue depth (Prometheus metric exposed at /metrics)
    QDEPTH=$(curl -s -H "X-API-Key: ${PLATFORM_API_KEY}" "${PLATFORM_URL}/metrics" 2>/dev/null \
        | grep -E '^soc_agent_queue_depth' | awk '{print $2}')
    [ -n "$QDEPTH" ] && note "Agent worker queue depth: ${QDEPTH}"
    awk "BEGIN{exit !(${QDEPTH:-0} > 500)}" && warn "Triage/agent queue backing up (>500) — worker may be stuck"
fi

if command -v docker >/dev/null 2>&1; then
    for svc in postgres redis api worker dashboard; do
        STATE=$(docker compose ps --format '{{.Service}} {{.State}}' 2>/dev/null | grep -w "$svc" | awk '{print $2}')
        case "$STATE" in
            running) ok "container ${svc} running" ;;
            "")      note "container ${svc} not found (different compose project?)" ;;
            *)       bad "container ${svc} state=${STATE}" ;;
        esac
    done
fi

# ---------------------------------------------------------------------------
# Summary + optional webhook
# ---------------------------------------------------------------------------
echo ""; echo "==================================================================="
if [ "$FAIL" -gt 0 ]; then
    RESULT="❌ FAIL — ${FAIL} critical, ${WARN} warnings"
elif [ "$WARN" -gt 0 ]; then
    RESULT="⚠️  WARN — ${WARN} warnings"
else
    RESULT="✅ ALL HEALTHY"
fi
echo " Result: ${RESULT}"
echo "==================================================================="

if [ -n "$ALERT_WEBHOOK" ] && { [ "$FAIL" -gt 0 ] || [ "$WARN" -gt 0 ]; }; then
    PAYLOAD=$(printf '{"text":"Daily SOC Health Check — %s\\n%b"}' "$RESULT" "$SUMMARY")
    curl -s -X POST -H 'Content-Type: application/json' -d "$PAYLOAD" "$ALERT_WEBHOOK" >/dev/null 2>&1
fi

[ "$FAIL" -gt 0 ] && exit 2
[ "$WARN" -gt 0 ] && exit 1
exit 0

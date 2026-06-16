#!/bin/bash
# =============================================================================
# Weekly Capacity Report — Unified Wazuh SOC Platform (Payless)
# -----------------------------------------------------------------------------
# Produces a capacity & coverage snapshot for the trailing 7 days: agent fleet
# growth, EPS, index storage growth, alert volume by level, top noisy rules,
# and indexer disk runway. Intended for the Monday morning ops review.
#
#   Cron example (Mon 07:00):
#     0 7 * * 1  /opt/soc-platform/scripts/weekly-capacity-report.sh > /var/log/soc-capacity-$(date +\%Y\%m\%d).txt 2>&1
#
# Env vars:
#   INDEXER_URL   default https://127.0.0.1:9200
#   INDEXER_USER  default admin
#   INDEXER_PASS  (required)
#   PLATFORM_URL / PLATFORM_API_KEY  (optional, for triage/case metrics)
# =============================================================================
set -uo pipefail

INDEXER_URL="${INDEXER_URL:-https://127.0.0.1:9200}"
INDEXER_USER="${INDEXER_USER:-admin}"
INDEXER_PASS="${INDEXER_PASS:-}"
PLATFORM_URL="${PLATFORM_URL:-http://localhost:8000}"
PLATFORM_API_KEY="${PLATFORM_API_KEY:-}"

q() { curl -sk -u "${INDEXER_USER}:${INDEXER_PASS}" "$@"; }

echo "###################################################################"
echo "#  WEEKLY CAPACITY REPORT — Payless SOC"
echo "#  Generated: $(date '+%Y-%m-%d %H:%M %Z')   Window: last 7 days"
echo "###################################################################"

if [ -z "$INDEXER_PASS" ]; then
    echo "INDEXER_PASS not set — cannot query indexer. Aborting." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# 1. Agent fleet
# ---------------------------------------------------------------------------
echo ""
echo "═══ 1. AGENT FLEET ═══"
if command -v /var/ossec/bin/agent_control >/dev/null 2>&1; then
    AL=$(/var/ossec/bin/agent_control -l 2>/dev/null)
    echo "   Total enrolled : $(echo "$AL" | grep -cE 'ID: [0-9]')"
    echo "   Active         : $(echo "$AL" | grep -c 'Active')"
    echo "   Disconnected   : $(echo "$AL" | grep -c 'Disconnected')"
    echo "   Never connected: $(echo "$AL" | grep -c 'Never connected')"
else
    echo "   (agent_control unavailable — run on the manager host)"
fi

# ---------------------------------------------------------------------------
# 2. Event volume & EPS
# ---------------------------------------------------------------------------
echo ""
echo "═══ 2. EVENT / ALERT VOLUME (7d) ═══"
WEEK_COUNT=$(q "${INDEXER_URL}/wazuh-alerts-*/_count" \
    -H 'Content-Type: application/json' -d '{
      "query":{"range":{"timestamp":{"gte":"now-7d/d","lte":"now"}}}}' \
    2>/dev/null | grep -o '"count":[0-9]*' | cut -d: -f2)
echo "   Total alerts (7d): ${WEEK_COUNT:-?}"
if [ -n "$WEEK_COUNT" ] && [ "$WEEK_COUNT" -gt 0 ] 2>/dev/null; then
    echo "   Avg alerts/day  : $(( WEEK_COUNT / 7 ))"
    echo "   Avg alert EPS   : $(awk "BEGIN{printf \"%.2f\", $WEEK_COUNT/604800}")"
fi

echo ""
echo "   By severity level:"
for band in "12 15 critical(12-15)" "7 11 high(7-11)" "4 6 medium(4-6)" "0 3 low(0-3)"; do
    set -- $band; LO=$1; HI=$2; LABEL=$3
    C=$(q "${INDEXER_URL}/wazuh-alerts-*/_count" -H 'Content-Type: application/json' -d "{
      \"query\":{\"bool\":{\"filter\":[
        {\"range\":{\"timestamp\":{\"gte\":\"now-7d/d\"}}},
        {\"range\":{\"rule.level\":{\"gte\":${LO},\"lte\":${HI}}}}]}}}" \
      2>/dev/null | grep -o '"count":[0-9]*' | cut -d: -f2)
    printf "      %-16s %s\n" "$LABEL" "${C:-0}"
done

# ---------------------------------------------------------------------------
# 3. Top 10 noisy rules (tuning candidates)
# ---------------------------------------------------------------------------
echo ""
echo "═══ 3. TOP 10 NOISY RULES (tuning candidates) ═══"
q "${INDEXER_URL}/wazuh-alerts-*/_search" -H 'Content-Type: application/json' -d '{
  "size":0,
  "query":{"range":{"timestamp":{"gte":"now-7d/d"}}},
  "aggs":{"rules":{"terms":{"field":"rule.id","size":10,"order":{"_count":"desc"}},
    "aggs":{"desc":{"terms":{"field":"rule.description","size":1}}}}}}' 2>/dev/null \
  | python3 -c '
import sys, json
try:
    d = json.load(sys.stdin)
    for b in d["aggregations"]["rules"]["buckets"]:
        desc = b["desc"]["buckets"][0]["key"] if b["desc"]["buckets"] else "?"
        print(f"      rule {b[\"key\"]:>7}  {b[\"doc_count\"]:>8,}  {desc[:60]}")
except Exception as e:
    print(f"      (could not parse aggregation: {e})")
'

# ---------------------------------------------------------------------------
# 4. Index storage & growth
# ---------------------------------------------------------------------------
echo ""
echo "═══ 4. INDEX STORAGE ═══"
echo "   Per-index (wazuh-alerts), newest 8:"
q "${INDEXER_URL}/_cat/indices/wazuh-alerts-*?h=index,docs.count,store.size&s=index:desc" 2>/dev/null \
  | head -8 | awk '{printf "      %-40s docs=%-12s size=%s\n", $1, $2, $3}'

TOTAL_SIZE=$(q "${INDEXER_URL}/_cat/indices/wazuh-*?h=store.size&bytes=gb" 2>/dev/null \
  | awk '{s+=$1} END{printf "%.1f", s}')
echo "   Total wazuh-* on disk: ${TOTAL_SIZE:-?} GB"

# ---------------------------------------------------------------------------
# 5. Disk runway
# ---------------------------------------------------------------------------
echo ""
echo "═══ 5. INDEXER DISK RUNWAY ═══"
DISK_PCT=$(q "${INDEXER_URL}/_cat/allocation?h=disk.percent" 2>/dev/null | tr -d ' ' | head -1)
DISK_AVAIL=$(q "${INDEXER_URL}/_cat/allocation?h=disk.avail" 2>/dev/null | head -1 | tr -d ' ')
echo "   Disk used: ${DISK_PCT:-?}%   Available: ${DISK_AVAIL:-?}"
if [ -n "$WEEK_COUNT" ] && [ -n "$TOTAL_SIZE" ] && awk "BEGIN{exit !($WEEK_COUNT>0)}"; then
    # crude: GB/week ≈ total_size / (retention weeks). Use 7d ingest as proxy.
    echo "   (Estimate runway from 7d ingest rate vs. disk.avail; tune retention if <4 weeks.)"
fi

# ---------------------------------------------------------------------------
# 6. Platform triage / case throughput (optional)
# ---------------------------------------------------------------------------
if [ -n "$PLATFORM_API_KEY" ]; then
    echo ""
    echo "═══ 6. AI TRIAGE & CASE THROUGHPUT ═══"
    curl -s -H "X-API-Key: ${PLATFORM_API_KEY}" "${PLATFORM_URL}/metrics" 2>/dev/null \
      | grep -E '^soc_(alert_volume_24h|open_cases_total|mttr_seconds|mttd_seconds)' \
      | awk '{printf "      %-28s %s\n", $1, $2}'
fi

echo ""
echo "###################################################################"
echo "#  End of report. Review noisy rules (§3) for tuning, disk (§5)"
echo "#  for retention changes, and agent fleet (§1) for enrollment gaps."
echo "###################################################################"

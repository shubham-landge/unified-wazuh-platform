#!/bin/bash
# Health check script — validates all SOC platform components
set -euo pipefail

API_KEY="${API_KEY:-soc-key-001}"
BASE_URL="${BASE_URL:-http://localhost:8000}"
FAILED=0

check() {
    local name="$1"
    local url="$2"
    local expect="$3"

    echo -n "Checking $name... "
    resp=$(curl -s -o /dev/null -w "%{http_code}" -H "X-API-Key: $API_KEY" "$url" 2>/dev/null || echo "000")

    if [ "$resp" = "$expect" ] || [ "${resp:0:1}" = "${expect:0:1}" ]; then
        echo "✅ ($resp)"
    else
        echo "❌ (expected $expect, got $resp)"
        FAILED=1
    fi
}

echo "=== SOC Platform Health Check ==="
echo ""

check "API Health"       "$BASE_URL/health"         "200"
check "Wazuh Health"     "$BASE_URL/wazuh/health"     "200"
check "Model Status"     "$BASE_URL/model/status"     "200"
check "Alerts Endpoint"  "$BASE_URL/alerts/recent"    "200"
check "Cases Endpoint"   "$BASE_URL/cases"            "200"
check "Assets Endpoint"  "$BASE_URL/assets"           "200"
check "Vulns Endpoint"   "$BASE_URL/vulnerabilities"  "200"
check "Audit Endpoint"   "$BASE_URL/audit"            "200"
check "Auth Required"    "$BASE_URL/health"           "401"

echo ""
if [ "$FAILED" -eq 0 ]; then
    echo "✅ All checks passed"
else
    echo "❌ Some checks failed — check docker compose logs"
fi

exit "$FAILED"

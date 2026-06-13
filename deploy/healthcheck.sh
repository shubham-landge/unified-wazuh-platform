#!/bin/bash
# Health check script — validates all SOC platform components
set -euo pipefail

API_KEY="${API_KEY:-}"
BASE_URL="${BASE_URL:-http://localhost:8000}"
FAILED=0

check_auth() {
    local name="$1"
    local url="$2"
    local expect="$3"

    echo -n "Checking $name... "
    resp=$(curl -s -o /dev/null -w "%{http_code}" -H "X-API-Key: $API_KEY" "$url" 2>/dev/null || echo "000")

    if [ "${resp:0:1}" = "${expect:0:1}" ]; then
        echo "✅ ($resp)"
    else
        echo "❌ (expected ${expect}xx, got $resp)"
        FAILED=1
    fi
}

check_noauth() {
    local name="$1"
    local url="$2"

    echo -n "Checking $name... "
    resp=$(curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null || echo "000")

    if [ "$resp" = "200" ]; then
        echo "✅ ($resp)"
    else
        echo "❌ (expected 200, got $resp)"
        FAILED=1
    fi
}

echo "=== SOC Platform Health Check ==="
echo ""

# Health endpoint does not require auth
check_noauth  "API Health"       "$BASE_URL/health"

# Auth-required endpoints
if [ -n "$API_KEY" ]; then
    check_auth  "Wazuh Health"     "$BASE_URL/wazuh/health"     "2"
    check_auth  "Model Status"     "$BASE_URL/model/status"     "2"
    check_auth  "Alerts Endpoint"  "$BASE_URL/alerts/recent"    "2"
    check_auth  "Cases Endpoint"   "$BASE_URL/cases"            "2"
    check_auth  "Assets Endpoint"  "$BASE_URL/assets"           "2"
    check_auth  "Vulns Endpoint"   "$BASE_URL/vulnerabilities"  "2"
    check_auth  "Audit Endpoint"   "$BASE_URL/audit"            "2"
else
    echo "⚠  Set API_KEY env var to check auth-required endpoints"
fi

echo ""
if [ "$FAILED" -eq 0 ]; then
    echo "✅ All checks passed"
else
    echo "❌ Some checks failed — check docker compose logs"
fi

exit "$FAILED"

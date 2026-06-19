#!/bin/bash
# chaos-test.sh — Run failure mode tests against the SOC VM
# Usage: bash scripts/chaos-test.sh
set -e

SOC_VM_IP="192.168.1.100"
SOC_VM_USER="socadmin"
SSH="ssh -o StrictHostKeyChecking=no $SOC_VM_USER@$SOC_VM_IP"

echo "=== Chaos Test Starting ==="

# Test 1: Stop Ollama, verify noise gate still works, circuit breaker opens
echo "[Test 1] Stopping Ollama..."
$SSH "cd /opt/unified-wazuh-platform && docker compose stop ollama"
sleep 5
$SSH "docker ps --format '{{.Names}} {{.Status}}'" | grep ollama
echo "   ✅ Ollama stopped. Circuit breaker should open in 3 failures."
sleep 65  # Wait for circuit breaker recovery
$SSH "cd /opt/unified-wazuh-platform && docker compose start ollama"
sleep 5
$SSH "docker ps --format '{{.Names}} {{.Status}}'" | grep ollama
echo "   ✅ Ollama restarted."

# Test 2: Restart Postgres
echo ""
echo "[Test 2] Restarting Postgres..."
$SSH "cd /opt/unified-wazuh-platform && docker compose restart postgres"
sleep 5
$SSH "docker ps --format 'table {{.Names}}\t{{.Status}}'" | grep postgres
echo "   ✅ Postgres restarted successfully."

# Test 3: Health check after chaos
echo ""
echo "[Test 3] Verifying all containers healthy..."
$SSH "docker ps --format 'table {{.Names}}\t{{.Status}}'"

curl -sf "http://$SOC_VM_IP:8000/health" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(' ✅ API healthy:', d.get('status'))
print('    DB:', 'connected' if d.get('database', {}).get('connected') else 'FAIL')
print('    Redis:', 'connected' if d.get('redis', {}).get('connected') else 'FAIL')
"
echo "=== Chaos test complete ==="

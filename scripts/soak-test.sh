#!/bin/bash
# soak-test.sh — Run a 24-hour production simulation on the SOC VM
# Usage: bash scripts/soak-test.sh
set -e

SOC_VM_IP="192.168.1.100"
SOC_VM_USER="socadmin"
SSH="ssh -o StrictHostKeyChecking=no $SOC_VM_USER@$SOC_VM_IP"
LOGFILE="/tmp/soc-soak-$(date +%Y%m%d-%H%M).log"

echo "=== SOC Soak Test Starting $(date) ===" | tee "$LOGFILE"
echo "Logging to: $LOGFILE"

# 1. Baseline
echo "--- Baseline ---" | tee -a "$LOGFILE"
$SSH "docker stats --no-stream --format 'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}'" | tee -a "$LOGFILE"

# 2. Generate test alerts (if script exists)
if [ -f scripts/generate-test-alerts.py ]; then
  echo "--- Generating test alerts ---" | tee -a "$LOGFILE"
  $SSH "cd /opt/unified-wazuh-platform && python3 scripts/generate-test-alerts.py --count 100" | tee -a "$LOGFILE"
fi

# 3. Monitor for 10 minutes (instead of 24h for demo)
echo "--- Monitoring for 10 minutes (24h in production) ---" | tee -a "$LOGFILE"
for i in $(seq 1 10); do
  TIMESTAMP=$(date +%H:%M:%S)
  STATS=$($SSH "docker stats --no-stream --format '{{.Name}} {{.CPUPerc}} {{.MemPerc}}' 2>/dev/null" 2>/dev/null)
  QUEUE=$($SSH "cd /opt/unified-wazuh-platform && docker compose exec -T redis redis-cli LLEN triage_queue 2>/dev/null || echo 0" 2>/dev/null)
  echo "[$TIMESTAMP] CPU/MEM: $STATS | Queue: $QUEUE" >> "$LOGFILE"
  sleep 60
done

# 4. Final state
echo "--- Final state ---" | tee -a "$LOGFILE"
$SSH "docker ps --format 'table {{.Names}}\t{{.Status}}'" | tee -a "$LOGFILE"
echo "=== Soak test complete $(date) ===" | tee -a "$LOGFILE"

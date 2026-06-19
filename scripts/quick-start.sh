#!/bin/bash
# quick-start.sh — Unified Wazuh SOC Platform Quick Start
# Idempotent. Safe to run multiple times. Works from personal Mac against
# Proxmox VMs. This is the power-cut recovery script — run it after Proxmox
# comes back online to get the SOC stack running in ~2 minutes.
#
# Usage: bash scripts/quick-start.sh [--skip-build] [--skip-pull]
#   --skip-build  Skip docker compose build (only git pull + restart)
#   --skip-pull   Skip git pull (assume repo is current)

set -euo pipefail

PROXMOX_HOST="192.168.1.200"
SOC_VM_ID="200"
WAZUH_VM_ID="102"
SOC_VM_IP="192.168.1.100"
SOC_VM_USER="socadmin"
SOC_VM_PASS="Shubham@1234"
PROMOX_USER="root@pam"
PROXMOX_PASS="Shubham@1234"
REPO_DIR="/opt/unified-wazuh-platform"
LOCAL_REPO="/Users/shubhamlandge/Documents/Wazuh AI/unified-wazuh-platform"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Unified Wazuh SOC Platform — Quick Start / Power Recovery  ║"
echo "╚══════════════════════════════════════════════════════════════╝"

# ── Step 1: Check Proxmox availability ──
echo ""
echo "[1/5] Checking Proxmox at $PROXMOX_HOST:8006..."
TICKET=$(curl -sk --connect-timeout 5 -X POST \
  "https://$PROXMOX_HOST:8006/api2/json/access/ticket" \
  -d "username=$PROMOX_USER&password=$PROXMOX_PASS" 2>/dev/null \
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('ticket',''))" 2>/dev/null || echo "")

if [ -z "$TICKET" ]; then
  echo "⚠  Proxmox unreachable. Running local test suite instead..."
  cd "$LOCAL_REPO" 2>/dev/null || { echo "Repo not found locally"; exit 1; }
  source .venv/bin/activate 2>/dev/null || true
  python -m pytest -q 2>&1 | tail -3
  echo "✅ Local tests done. Re-run when Proxmox is available."
  exit 0
fi
echo "   ✅ Proxmox reachable"

# ── Step 2: Start VMs if stopped ──
echo ""
echo "[2/5] Ensuring VMs are running..."

CSRF=$(echo "$TICKET" | cut -d: -f2-)
for VM_ID in $SOC_VM_ID $WAZUH_VM_ID; do
  STATUS=$(curl -sk "https://$PROXMOX_HOST:8006/api2/json/nodes/lab/qemu/$VM_ID/status/current" \
    -H "Cookie: PVEAuthCookie=$TICKET" 2>/dev/null \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('status','stopped'))" 2>/dev/null)
  
  if [ "$STATUS" = "stopped" ]; then
    echo "   Starting VM $VM_ID..."
    curl -sk -X POST "https://$PROXMOX_HOST:8006/api2/json/nodes/lab/qemu/$VM_ID/status/start" \
      -H "Cookie: PVEAuthCookie=$TICKET" -H "CSRFPreventionToken: $CSRF" >/dev/null 2>&1
    sleep 2
  else
    echo "   VM $VM_ID already running ($STATUS)"
  fi
done

# ── Step 3: Wait for SSH on SOC VM ──
echo ""
echo "[3/5] Waiting for SOC VM SSH..."
for i in $(seq 1 30); do
  if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 -o BatchMode=yes \
    "$SOC_VM_USER@$SOC_VM_IP" "hostname" 2>/dev/null | grep -q soc; then
    echo "   ✅ SOC VM reachable at $SOC_VM_IP"
    break
  fi
  if [ "$i" -eq 30 ]; then
    echo "   ❌ SOC VM not reachable after 60s. Check: $SOC_VM_IP"
    echo "   Try: ping $SOC_VM_IP"
    exit 1
  fi
  sleep 2
done

# ── Step 4: Deploy latest code ──
echo ""
echo "[4/5] Deploying latest code..."
SSH_CMD="ssh -o StrictHostKeyChecking=no -o ConnectTimeout=10 $SOC_VM_USER@$SOC_VM_IP"

$SSH_CMD "cd $REPO_DIR && git pull origin main 2>&1" || {
  echo " git pull failed, trying fresh clone..."
  $SSH_CMD "sudo rm -rf $REPO_DIR && sudo git clone https://github.com/shubham-landge/unified-wazuh-platform.git $REPO_DIR && sudo chown -R $SOC_VM_USER:$SOC_VM_USER $REPO_DIR"
}

if [ "${1:-}" != "--skip-build" ]; then
  echo "   Building and restarting containers..."
  $SSH_CMD "cd $REPO_DIR && docker compose up -d --build 2>&1 | tail -5"
else
  echo "   --skip-build: restarting existing containers..."
  $SSH_CMD "cd $REPO_DIR && docker compose up -d 2>&1 | tail -5"
fi

# ── Step 5: Verify ──
echo ""
echo "[5/5] Running health check..."
sleep 10

$SSH_CMD "docker ps --format 'table {{.Names}}\t{{.Status}}'" 2>/dev/null | head -10

echo ""
echo "=== Health ==="
curl -sf "http://$SOC_VM_IP:8000/health" 2>/dev/null | python3 -m json.tool 2>/dev/null || echo "⚠  API not responding"

echo ""
echo "=== MCP Tools ==="
curl -sf "http://$SOC_VM_IP:9000/tools" 2>/dev/null | python3 -c "
import sys, json
d = json.load(sys.stdin)
tools = set(d.get('tools', []))
print(f'{len(tools)} tools available')
" 2>/dev/null || echo "⚠  MCP not responding"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  SOC Platform running at http://$SOC_VM_IP              ║"
echo "║  API at http://$SOC_VM_IP:8000                         ║"
echo "║  When power cuts: re-run this script — it auto-recovers  ║"
echo "╚══════════════════════════════════════════════════════════════╝"

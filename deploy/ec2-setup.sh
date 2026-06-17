#!/bin/bash
# Unified Wazuh SOC Platform — EC2 Setup Script
# Works on: Amazon Linux 2023, Ubuntu 22.04/24.04, RHEL 8/9
# Minimum: 8 vCPU, 32 GB RAM, 50+ GB disk
set -euo pipefail

echo "=== Unified Wazuh SOC Platform — EC2 Setup ==="

# Configuration
REPO_URL="https://github.com/shubham-landge/unified-wazuh-platform.git"
INSTALL_DIR="/opt/unified-wazuh-platform"
BRANCH="main"

# ── Detect OS ──
source /etc/os-release 2>/dev/null || true
OS_ID="${ID:-unknown}"

# ── 1. System dependencies ──
echo "[1/8] Installing system dependencies..."
if command -v dnf &>/dev/null; then
    sudo dnf update -y
    sudo dnf install -y docker git curl python3.12 python3.12-pip
elif command -v apt-get &>/dev/null; then
    sudo apt-get update -y
    sudo apt-get install -y docker.io docker-compose-plugin git curl python3
else
    echo "❌ Unsupported OS. Install Docker + Git manually, then re-run with SKIP_DEPS=1"
    [ "${SKIP_DEPS:-0}" = "1" ] || exit 1
fi

sudo systemctl enable docker 2>/dev/null || true
sudo systemctl start docker 2>/dev/null || true

if ! docker compose version &>/dev/null; then
    echo "❌ Docker Compose plugin missing. Install it first."
    exit 1
fi

# ── 2. Clone repo ──
echo "[2/8] Cloning repository..."
if [ -d "$INSTALL_DIR" ]; then
    echo "   Directory $INSTALL_DIR exists. Pulling latest..."
    cd "$INSTALL_DIR"
    sudo git fetch origin "$BRANCH"
    sudo git checkout "$BRANCH"
    sudo git pull origin "$BRANCH"
else
    sudo git clone --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

# ── 3. Configure environment ──
echo "[3/8] Setting up environment..."
if [ ! -f .env ]; then
    cp .env.example .env
    echo ""
    echo "   ╔════════════════════════════════════════════════════════╗"
    echo "   ║  Edit .env with your Wazuh credentials, then re-run.  ║"
    echo "   ║  nano $INSTALL_DIR/.env                               ║"
    echo "   ╚════════════════════════════════════════════════════════╝"
    echo ""
    echo "   Required vars: API_KEYS, SECRET_KEY, JWT_SECRET_KEY,"
    echo "   WAZUH_API_URL, WAZUH_API_USER, WAZUH_API_PASSWORD,"
    echo "   WAZUH_INDEXER_URL, WAZUH_INDEXER_USER, WAZUH_INDEXER_PASSWORD"
    echo "   TENANT_ID, DASHBOARD_ADMIN_EMAIL, DASHBOARD_ADMIN_PASSWORD"
    exit 1
fi

# Validate required env vars
echo "   Validating .env..."
REQUIRED_VARS=("API_KEYS" "SECRET_KEY" "JWT_SECRET_KEY" "WAZUH_API_URL" "WAZUH_INDEXER_URL")
MISSING=0
for var in "${REQUIRED_VARS[@]}"; do
    val=$(grep -E "^${var}=" .env 2>/dev/null | cut -d= -f2-)
    if [ -z "$val" ] || echo "$val" | grep -qiE "your-key-here|change.me|generate.a.random|changeme"; then
        echo "   ⚠  $var is missing or has placeholder value"
        MISSING=1
    fi
done
if [ "$MISSING" -eq 1 ]; then
    echo "   ⚠  Please update .env with real values and re-run."
    exit 1
fi
echo "   ✅ .env validation passed"

# ── 3b. Port check ──
echo "   Checking port availability (80, 5432, 6379, 8000, 9000, 11434)..."
for port in 80 5432 6379 8000 9000 11434; do
    if ss -tlnp "sport = :$port" 2>/dev/null | grep -q ":$port" || \
       netstat -tlnp 2>/dev/null | grep -q ":$port"; then
        echo "   ⚠  Port $port is in use — free it before deploying"
    fi
done

# ── 4. Start Ollama & pull models FIRST (3-5 min network-bound) ──
echo "[4/8] Starting Ollama and pulling AI models (this takes a few minutes)..."
sudo docker compose up -d ollama
sleep 3

# Primary triage model — 3.2B params, 128K context, cybersecurity-specialized, 2.0 GB
echo "   Pulling CyberCrew/notmythos-8b (2.0 GB)..."
sudo docker compose exec -T ollama ollama pull CyberCrew/notmythos-8b 2>/dev/null || \
    echo "   ⚠  notmythos-8b pull failed — check ollama logs"

# Fast / noise-gate tier — 3B params, 1.9 GB
echo "   Pulling qwen2.5:3b-instruct (1.9 GB)..."
sudo docker compose exec -T ollama ollama pull qwen2.5:3b-instruct 2>/dev/null || \
    echo "   ⚠  qwen2.5:3b-instruct pull failed — check ollama logs"

# RAG embeddings model — 274 MB, runs fast on CPU
echo "   Pulling nomic-embed-text (274 MB)..."
sudo docker compose exec -T ollama ollama pull nomic-embed-text 2>/dev/null || \
    echo "   ⚠  nomic-embed-text pull failed — check ollama logs"

echo "   Models pulled:"
sudo docker compose exec -T ollama ollama list 2>/dev/null || true

# ── 5. Build all images ──
echo "[5/8] Building Docker images..."
sudo docker compose build

# ── 6. Start core infrastructure ──
echo "[6/8] Starting core services (postgres, redis)..."
sudo docker compose up -d postgres redis

echo "   Waiting for PostgreSQL..."
for i in $(seq 1 30); do
    if sudo docker compose exec -T postgres pg_isready -U soc_user -d soc_platform 2>/dev/null; then
        echo "   ✅ PostgreSQL ready"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "❌ PostgreSQL failed to start after 60s"
        exit 1
    fi
    sleep 2
done

# ── 7. Start remaining services ──
echo "[7/8] Starting platform services..."
sudo docker compose up -d api worker dashboard mcp maigret

# ── 8. Health check ──
echo "[8/8] Waiting for health checks..."
sleep 10

echo ""
echo "=== Container Status ==="
sudo docker ps --format 'table {{.Names}}\t{{.Status}}'

echo ""
echo "=== Health Endpoint ==="
curl -sf http://localhost:8000/health 2>/dev/null | python3 -m json.tool 2>/dev/null || \
    echo "⚠  Health check failed — check: docker compose logs api"

echo ""
echo "=== MCP Tools ==="
curl -sf http://localhost:9000/tools 2>/dev/null | python3 -c "
import sys, json
data = json.load(sys.stdin)
tools = list(set(data.get('tools', [])))
print(f'  {len(tools)} tools available')
for t in sorted(tools):
    print(f'    - {t}')
" 2>/dev/null || echo "⚠  MCP not responding — check: docker compose logs mcp"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║              Deployment Complete                             ║"
echo "╠══════════════════════════════════════════════════════════════╣"
EC2_IP=$(curl -sf http://checkip.amazonaws.com 2>/dev/null || echo "YOUR-EC2-IP")
echo "║ Dashboard:  http://$EC2_IP                             "
echo "║ API:        http://$EC2_IP:8000                        "
echo "║ API Docs:   http://$EC2_IP:8000/docs                   "
echo "║ MCP:        http://$EC2_IP:9000/tools                  "
echo "║ Health:     http://$EC2_IP:8000/health                 "
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Next steps:"
echo "  1. Open EC2 security group ports: 80, 8000, 9000"
echo "  2. Login to dashboard and configure admin credentials"
echo "  3. Monitor triage: docker compose logs -f worker | grep triage"
echo "  4. Run health script: bash deploy/healthcheck.sh"
echo ""
echo "Model tiering:"
echo "  Fast tier (noise gate): qwen2.5:3b-instruct"
echo "  Full tier (primary):   CyberCrew/notmythos-8b (128K ctx)"
echo "  Embeddings (RAG):      nomic-embed-text"
echo ""
echo "To add escalation model (domain-specialist, 4.7 GB):"
echo "  docker compose exec ollama ollama pull OpenNix/wazuh-llama-3.1-8B-v1"
echo ""
echo "Rollback:"
echo "  cd $INSTALL_DIR && git checkout <commit> && docker compose down && docker compose up -d"

#!/bin/bash
# Unified Wazuh SOC Platform — EC2 Setup Script
# Run on fresh m7i.2xlarge EC2 (Amazon Linux 2023)
set -euo pipefail

echo "=== Unified Wazuh SOC Platform — EC2 Setup ==="

# Configuration
REPO_URL="https://github.com/shubham-landge/unified-wazuh-platform.git"
INSTALL_DIR="/opt/unified-wazuh-platform"

# Pre-flight: check for Docker Compose plugin
if ! command -v docker &>/dev/null; then
    echo "❌ Docker not found. Will install."
fi

# 1. System dependencies
echo "[1/8] Installing system dependencies..."
sudo dnf update -y
sudo dnf install -y docker git curl python3.12 python3.12-pip
sudo systemctl enable docker
sudo systemctl start docker

# Verify Docker Compose plugin
if ! docker compose version &>/dev/null; then
    echo "❌ Docker Compose plugin missing. Install with:"
    echo "   sudo dnf install -y docker-compose-plugin"
    exit 1
fi

# 2. Clone repo
echo "[2/8] Cloning repository..."
if [ -d "$INSTALL_DIR" ]; then
    echo "⚠  Directory $INSTALL_DIR exists. Pulling latest..."
    cd "$INSTALL_DIR"
    sudo git pull
else
    sudo git clone "$REPO_URL" "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

# 3. Configure environment
echo "[3/8] Setting up environment..."
if [ ! -f .env ]; then
    cp .env.example .env
    echo "⚠  Edit .env with your Wazuh credentials before continuing."
    echo "   nano $INSTALL_DIR/.env"
    echo "   Then re-run this script."
    echo "   Required vars: API_KEYS, SECRET_KEY, WAZUH_API_USER, WAZUH_API_PASSWORD"
    exit 1
fi

# Validate required env vars
echo "   Validating .env..."
REQUIRED_VARS=("API_KEYS" "SECRET_KEY" "WAZUH_API_URL" "WAZUH_INDEXER_URL")
MISSING=0
for var in "${REQUIRED_VARS[@]}"; do
    val=$(grep -E "^${var}=" .env | cut -d= -f2-)
    if [ -z "$val" ] || echo "$val" | grep -q "your-key-here\|change_me\|generate_a_random"; then
        echo "   ⚠  $var is missing or has placeholder value"
        MISSING=1
    fi
done
if [ "$MISSING" -eq 1 ]; then
    echo "⚠  Please update .env with real values and re-run."
    exit 1
fi
echo "   ✅ .env validation passed"

# Pre-flight: check ports
echo "   Checking port availability..."
for port in 5432 6379 8000 8050 11434 80; do
    if ss -tlnp "sport = :$port" 2>/dev/null | grep -q ":$port"; then
        echo "   ⚠  Port $port is in use — consider stopping the conflicting service"
    fi
done

# 4. Build Docker images
echo "[4/8] Building Docker images..."
sudo docker compose build

# 5. Start core services
echo "[5/8] Starting core services..."
sudo docker compose up -d postgres redis

echo "   Waiting for PostgreSQL..."
for i in $(seq 1 30); do
    if sudo docker compose exec -T postgres pg_isready -U soc_user -d soc_platform 2>/dev/null; then
        echo "   PostgreSQL ready"
        break
    fi
    if [ "$i" -eq 30 ]; then
        echo "❌ PostgreSQL failed to start"
        exit 1
    fi
    sleep 2
done

# 6. Start API and Worker
echo "[6/8] Starting API and workers..."
sudo docker compose up -d api worker dashboard

# 7. Pull Ollama models (optional, can run in background)
echo "[7/8] Pulling Ollama models (this may take a while)..."
sudo docker compose up -d ollama
sudo docker compose exec -T ollama ollama pull qwen2.5-coder:3b 2>/dev/null || true
sudo docker compose exec -T ollama ollama pull qwen2.5-coder:7b 2>/dev/null || true

# 8. Verify
echo "[8/8] Verifying deployment..."
sleep 5

echo ""
echo "=== Health Check ==="
# Health endpoint does not require auth
curl -s http://localhost:8000/health | python3 -m json.tool 2>/dev/null || echo "⚠  Health check failed — check docker compose logs"

echo ""
echo "=== Deployment Complete ==="
echo "Dashboard:  http://$(curl -s http://checkip.amazonaws.com)"
echo "API:        http://localhost:8000"
echo "API Docs:   http://localhost:8000/docs"
echo ""
echo "Next steps:"
echo "  1. Edit .env with your Wazuh read-only credentials"
echo "  2. Restart: sudo docker compose restart api worker"
echo "  3. Monitor: sudo docker compose logs -f"
echo "  4. Backup:  sudo ./deploy/backup.sh"
echo ""
echo "Rollback:"
echo "  cd $INSTALL_DIR && git checkout <previous-tag> && sudo docker compose down && sudo docker compose up -d"

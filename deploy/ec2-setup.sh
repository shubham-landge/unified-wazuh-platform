#!/bin/bash
# Unified Wazuh SOC Platform — EC2 Setup Script
# Run on fresh m7i.2xlarge EC2 (Amazon Linux 2023)
set -euo pipefail

echo "=== Unified Wazuh SOC Platform — EC2 Setup ==="

# Configuration
REPO_URL="https://github.com/shubham-landge/unified-wazuh-platform.git"
INSTALL_DIR="/opt/unified-wazuh-platform"

# 1. System dependencies
echo "[1/8] Installing system dependencies..."
sudo dnf update -y
sudo dnf install -y docker git curl python3.12 python3.12-pip
sudo systemctl enable docker
sudo systemctl start docker

# 2. Clone repo
echo "[2/8] Cloning repository..."
sudo git clone "$REPO_URL" "$INSTALL_DIR"
cd "$INSTALL_DIR"

# 3. Configure environment
echo "[3/8] Setting up environment..."
if [ ! -f .env ]; then
    cp .env.example .env
    echo "⚠  Edit .env with your Wazuh credentials before continuing."
    echo "   nano $INSTALL_DIR/.env"
    echo "   Then re-run this script."
fi

# 4. Build Docker images
echo "[4/8] Building Docker images..."
sudo docker compose build

# 5. Start services (except Ollama first, for model download)
echo "[5/8] Starting core services..."
sudo docker compose up -d postgres redis

# Wait for DB
echo "   Waiting for PostgreSQL..."
sleep 5
until sudo docker compose exec -T postgres pg_isready -U soc_user -d soc_platform 2>/dev/null; do
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
API_KEY=$(grep API_KEYS .env | head -1 | cut -d= -f2 | cut -d, -f1)

echo ""
echo "=== Health Check ==="
curl -s -H "X-API-Key: $API_KEY" http://localhost:8000/health | python3 -m json.tool 2>/dev/null || echo "⚠  Health check failed — check docker compose logs"

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

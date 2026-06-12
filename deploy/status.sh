#!/bin/bash
# SOC Platform — Quick status overview
set -euo pipefail

echo "╔══════════════════════════════════════════╗"
echo "║   SOC Platform — Status Overview         ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# Branch status
echo "📂 BRANCH STATUS"
printf "  %-20s %s\n" "tool/claude" "📝 Not Started"
printf "  %-20s %s\n" "tool/codex" "📝 Not Started"
printf "  %-20s %s\n" "tool/antigravity" "📝 Not Started"
printf "  %-20s %s\n" "tool/opencode" "🔄 Ready"
echo ""

# Docker services
if docker compose ps &>/dev/null 2>&1; then
    echo "🐳 DOCKER SERVICES"
    docker compose ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null || echo "  (docker not running)"
    echo ""
fi

# Recent commits per branch
echo "📝 RECENT COMMITS (last 3 per branch)"
for branch in main tool/claude tool/codex tool/antigravity tool/opencode; do
    if git rev-parse --verify "origin/$branch" &>/dev/null 2>&1; then
        printf "  %-20s" "$branch"
        git log "origin/$branch" --oneline -3 2>/dev/null | head -3 | while read line; do
            echo "           $line"
        done
    fi
done
echo ""

# Open PRs
echo "🔗 OPEN PULL REQUESTS"
gh pr list --state open --repo shubham-landge/unified-wazuh-platform 2>/dev/null || echo "  (no open PRs)"
echo ""

# Project board
echo "📋 PROJECT BOARD"
echo "  https://github.com/users/shubham-landge/projects/1"
echo ""
echo "  Quick links:"
gh pr list --state open --json number,headRefName,title --repo shubham-landge/unified-wazuh-platform 2>/dev/null | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    for pr in data:
        print(f'    PR #{pr[\"number\"]} ({pr[\"headRefName\"]}): {pr[\"title\"]}')
except:
    pass
" 2>/dev/null || true

# MCP Integration Guide

> **Status**: Implemented as an HTTP MCP-compatible server. Upgrade to `fastmcp.FastMCP` planned.  
> **Updated**: 2026-06-17  
> **Scope**: How to query the SOC platform via the Model Context Protocol from Claude Desktop, Cursor, or any MCP client.

---

## 1. What is exposed

The file `services/mcp/server.py` runs a small FastAPI application that implements the MCP convention:

- `GET /tools` — list available tools and their parameters.
- `POST /tools/call` — invoke a tool by name.

It is **not** a full MCP SDK implementation yet; it follows the same request/response shape so existing MCP clients can call it with a thin adapter. Once the `mcp` Python package is available in the deployment environment, the file can be swapped for `fastmcp.FastMCP` without changing the tool contract.

### Available tools

| Tool | Method | Risk | Description |
|------|--------|------|-------------|
| `list_alerts` | read | read | List recent alerts, optional severity filter |
| `get_triage` | read | read | Get AI triage result for an alert |
| `get_agents` | read | read | List Wazuh agent definitions |
| `list_rules` | read | read | List Wazuh rules |
| `get_stats` | read | read | Platform health / statistics |
| `list_vulnerabilities` | read | read | List detected vulnerabilities |
| `create_case` | write | write-low | Create an investigation case |
| `run_playbook` | write | write-high | Execute a SOAR playbook (gated by approvals) |

All write tools are routed through the existing SOAR/case APIs, which in turn run through `policy_guard` and the approval workflow.

---

## 2. Running the server

### Option A: Docker Compose (recommended)

The MCP server is currently invoked as a standalone container. Add the service block below to `docker-compose.yml` if it is not already present:

```yaml
  mcp:
    build:
      context: .
      dockerfile: services/mcp/Dockerfile
    container_name: soc-mcp
    restart: unless-stopped
    depends_on:
      - api
    env_file:
      - .env
    environment:
      API_BASE_URL: http://api:8000
    ports:
      - "9000:9000"
    networks:
      - soc-network
```

> **Note**: A dedicated Dockerfile for `services/mcp/` is not created yet. Until then, you can run the MCP server inside the API container by mounting `services/mcp/server.py` and exposing it on a second port, or by including it as a sub-application under `/mcp` in `services/api/app/main.py`.

### Option B: Local smoke test

```bash
python -m uvicorn services.mcp.server:app --host 127.0.0.1 --port 9000
curl http://127.0.0.1:9000/tools
curl -X POST http://127.0.0.1:9000/tools/call \
  -H 'Content-Type: application/json' \
  -d '{"tool":"list_alerts","params":{"limit":5}}'
```

The server expects the SOC API to be reachable at `API_BASE_URL` (default `http://api:8000`). It uses the first key from `API_KEYS` to authenticate upstream requests.

---

## 3. Authentication

The MCP server reads `API_KEYS` from the environment. For each tool call it forwards the first key as `X-API-Key` to the backend API. Ensure the key has the permissions required for the tools you intend to expose.

In a future iteration, per-tool or per-client API keys should be supported so a read-only MCP client cannot invoke `run_playbook`.

---

## 4. Connecting Claude Desktop / Cursor

### Example `claude_desktop_config.json`

```json
{
  "mcpServers": {
    "soc-platform": {
      "command": "npx",
      "args": [
        "-y",
        "@modelcontextprotocol/server-sse",
        "http://localhost:9000/tools/call"
      ]
    }
  }
}
```

> The current server uses a simple HTTP POST convention, not SSE. Use a lightweight bridge (e.g., `mcp-proxy`) or point a custom client at `POST /tools/call` until the FastMCP migration is complete.

### Example request body

```json
{
  "tool": "get_triage",
  "params": {
    "alert_id": "550e8400-e29b-41d4-a716-446655440000"
  }
}
```

---

## 5. Error handling

| Situation | HTTP status | Response |
|-----------|-------------|----------|
| Unknown tool | 400 | `{"detail":"Unknown tool: ..."}` |
| Missing required parameter | 400 | `{"detail":"alert_id required"}` |
| SOC API unreachable | 502 | `{"detail":"Unable to reach SOC API at ..."}` |
| Upstream API error | 4xx/5xx | Forwarded from backend |

---

## 6. Testing

Unit tests are in `tests/test_mcp_server.py` and cover:

- Tool discovery
- Request forwarding with correct `X-API-Key`
- POST body forwarding for `create_case`
- Unknown tool handling
- Missing parameter handling
- Upstream API error propagation
- Network unreachable handling

Run them with:

```bash
python -m pytest tests/test_mcp_server.py -q
```

---

## 7. Roadmap

| Step | Work | Status |
|------|------|--------|
| 1 | HTTP MCP-compatible server + tests | ✅ Done |
| 2 | Dedicated `services/mcp/Dockerfile` + compose service | ⏳ Pending |
| 3 | Add Wazuh API/Indexer tools (agents, rules, stats, logs) | ⏳ Pending |
| 4 | Migrate to `fastmcp.FastMCP` for native SSE/stdio transport | ⏳ Pending |
| 5 | Per-tool permission scopes | ⏳ Pending |

---

## 8. Related documents

- [VISION-AUTONOMOUS-SOC.md](VISION-AUTONOMOUS-SOC.md) — why MCP is the strategic foundation
- [MULTI-TOOL-PLAN.md](MULTI-TOOL-PLAN.md) — original MCP ownership and contracts
- [UNIFIED-ARCHITECTURE.md](UNIFIED-ARCHITECTURE.md) — platform architecture

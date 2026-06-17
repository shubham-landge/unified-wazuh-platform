# Task: Expand MCP Server with Wazuh Indexer and API tools

**Branch**: `tool/codex` — rebase onto latest `main` (`efd0635`) before starting.
**Owns**: `services/mcp/`, `shared/connectors/` (new connectors only), `tests/test_mcp_server.py`.

## Context

Current `services/mcp/server.py` proxies 8 tools through the SOC API. This works but is slow — every tool call goes SOC API → Wazuh API. Adding direct Wazuh API/Indexer tools makes the MCP layer useful even when the SOC API is down, and halves latency for Wazuh-native queries.

The existing `shared/connectors/wazuh_api.py` and `shared/connectors/wazuh_indexer.py` have circuit-breaker support. Use them directly.

Reference repos: `gensecaihq/Wazuh-MCP-Server` (48 Wazuh tools), `kortix-ai/suna` (3,000+ MCP connectors pattern).

## What to build

### 1. New MCP tools

Add 6 new tools to `TOOL_DEFINITIONS` and `call_tool()` in `services/mcp/server.py`:

| Tool | Source | Method | Params | Notes |
|------|--------|--------|--------|-------|
| `query_indexer` | `WazuhIndexerConnector.search` | POST | `query` (dict), `index` (str) | Ad-hoc ES queries against `wazuh-alerts-*` |
| `get_agent_info` | Wazuh API `/agents/:agent_id` | GET | `agent_id` (str) | Agent status, OS, IP, last seen |
| `list_agents` | Wazuh API `/agents` | GET | `status`, `limit` | Filter by status (active/disconnected) |
| `manager_status` | Wazuh API `/manager/status` | GET | (none) | Manager health, daemon status |
| `search_rules` | Wazuh API `/rules` | GET | `group`, `level`, `limit` | Search by group, level, or description |
| `get_syscollector` | Wazuh API `/syscollector/:agent_id` | GET | `agent_id` | Hardware/software inventory |

These tools call Wazuh directly — NOT through the SOC API. The auth uses `settings.wazuh_api_user` / `wazuh_api_password`, NOT the API key.

### 2. Circuit breaker

Wrap each Wazuh connector call in the existing `CircuitBreaker`. If Wazuh is down, return a fast 502 instead of 503 after a long timeout. The circuit breaker URL/host is `settings.wazuh_api_url`.

### 3. HTTP error handling

The current `call_tool` handler wraps httpx calls in try/except and returns 502 on network errors. This already works. Just follow the same pattern for the new tools.

### 4. Tests

Extend `tests/test_mcp_server.py` with:

- `test_query_indexer_returns_results` — mock `WazuhIndexerConnector.search`, verify response
- `test_list_agents_returns_filtered` — mock Wazuh API, verify status filter is passed
- `test_manager_status_returns_connected` — mock `/manager/status`
- `test_get_agent_info_requires_agent_id` — missing required param → 400
- `test_wazuh_api_unreachable_returns_502` — mock circuit breaker open → 502

Use `unittest.mock.patch` on `shared.connectors.wazuh_api.WazuhAPIConnector` and `shared.connectors.wazuh_indexer.WazuhIndexerConnector`.

### 5. STATUS.md

Update the "MCP Server + Connectors" row from "[ ] HTTP shim" to "[x] HTTP shim + 14 tools + direct Wazuh tools".

## Integration contracts (DO NOT BREAK)

- Tool signature: same `ToolRequest` model — `tool` (str) + `params` (dict)
- All tools respond via `POST /tools/call`
- `/tools` endpoint returns the union of SOC API tools + Wazuh tools
- Wazuh connector signatures remain unchanged
- `_first_api_key()` is for SOC API proxy; Wazuh tools use `settings.wazuh_api_user` / `wazuh_api_password`

## File ownership — only touch

- `services/mcp/server.py` — tool definitions + handler cases
- `tests/test_mcp_server.py` — new tests (append to existing file)
- `STATUS.md` — one status line update

## DO NOT touch

- `shared/config.py` — Claude-merged zone
- `docker-compose.yml` / `docker-compose.prod.yml` — Claude-merged zone
- `services/api/app/main.py` — Claude-merged zone
- `shared/connectors/wazuh_api.py` / `wazuh_indexer.py` — already have what you need

## Definition of done

- [ ] `python -m pytest tests/test_mcp_server.py -q` all green
- [ ] Only the 3 files above changed
- [ ] MCP server returns 14 tools total in `/tools`
- [ ] `curl -X POST localhost:9000/tools/call -d '{"tool":"list_agents","params":{"status":"active"}}'` returns agent list
- [ ] STATUS.md updated
- [ ] Push to `tool/codex`, open PR targeting `dev`

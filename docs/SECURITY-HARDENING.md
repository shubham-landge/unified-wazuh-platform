# Security Hardening Requirements

## 1. Wazuh Connection Security

### 1.1 Read-Only Credentials
- Create a dedicated Wazuh API user with **read-only** permissions
- Do NOT use admin/root-level Wazuh credentials
- Restrict Indexer access to read-only queries only
- Rotate credentials every 90 days

### 1.2 API Connection Safety
- Verify `WAZUH_API_URL` uses HTTPS
- Validate TLS certificate in production (set `VERIFY_SSL=true` in production)
- Set reasonable timeouts: connect=10s, read=30s
- Never expose Wazuh credentials in logs, errors, or responses

### 1.3 No Destructive Operations
The platform must NEVER:
- Execute Wazuh Active Response commands
- Delete or modify Wazuh agents
- Modify Wazuh configuration (`ossec.conf`)
- Change Wazuh rules or decoders
- Restart Wazuh services
- Disable or delete Wazuh users

## 2. Secrets Management

### 2.1 Environment Variables
- All secrets stored in `.env` file on EC2 filesystem
- `.env` file permissions: `600` (owner read/write only)
- `.env` listed in `.gitignore` — never committed
- Use `.env.example` as a template with placeholder values

### 2.2 Secret Masking
- Never log secrets (passwords, tokens, API keys)
- Never return secrets in API responses
- Mask secrets in error messages: `[REDACTED]`
- Use Pydantic `SecretStr` for password fields in config

### 2.3 API Keys
- Generate random 32+ character API keys
- Support multiple keys for different users/tenants
- Keys stored hashed in database (not plaintext)
- Rate limiting per key: 100 requests/minute
- Audit log every request

## 3. Infrastructure Security

### 3.1 EC2 Security Group Rules
```
| Direction | Protocol | Port | Source | Purpose |
|-----------|----------|------|--------|---------|
| Inbound   | TCP      | 80   | SOC/VPN CIDR | Dashboard |
| Inbound   | TCP      | 443  | SOC/VPN CIDR | Dashboard (TLS) |
| Inbound   | TCP      | 8000 | SOC/VPN CIDR | API (direct) |
| Outbound  | ALL      | ALL  | 0.0.0.0/0 | General |
```

### 3.2 Dashboard Access
- Restricted to SOC/VPN IP ranges via `DASHBOARD_ALLOWED_CIDRS`
- CIDR validation middleware on all dashboard routes
- 403 response for unauthorized IPs

### 3.3 Docker Security
- Containers run as non-root user
- No privileged containers
- Read-only root filesystem where possible
- Resource limits set per container
- Internal Docker network only (no port exposure to host unless needed)

## 4. LLM Security

### 4.1 Sensitive Data Masking
Before sending any data to an LLM (local or cloud), mask:

| Data Type | Masking Method |
|---|---|
| IP Addresses | Replace last octet with `x.x.x.0` or `x.x.x.x/24` |
| Internal IPs | Replace with `[internal-ip]` |
| Usernames | Replace with `[user]` (keep domain if present) |
| Passwords/Tokens | Replace with `[REDACTED]` |
| Private Keys | Replace with `[REDACTED]` |
| File Paths | Replace user home with `/home/[user]/` |
| Hostnames | Keep if internal, mask if external/PII |
| Email Addresses | Replace with `[email]` |
| API Keys | Replace with `[REDACTED]` |
| Session Tokens | Replace with `[REDACTED]` |
| Database Credentials | Replace with `[REDACTED]` |

### 4.2 Prompt Safety
- System prompt must prohibit destructive/offensive responses
- Every LLM response validated for JSON structure and field types
- Responses checked for secret leakage (regex patterns)
- Reject responses containing IPs, credentials, or commands that modify systems

### 4.3 LLM Provider Security
- Ollama runs on internal Docker network (not exposed to internet)
- Cloud LLM API keys stored in `.env` only
- All LLM API calls use HTTPS
- Token count and cost tracked per request

## 5. Database Security

### 5.1 PostgreSQL
- Strong password (32+ characters, mixed case + numbers + symbols)
- Connection via SSL (configure PostgreSQL with certificates in production)
- User has DML only on `soc_platform` database (no DDL except migrations)
- Regular automated backups via `deploy/backup.sh`
- Retention: daily backups for 30 days

### 5.2 Redis
- Password required (set in `.env`)
- Protected mode enabled (`protected-mode yes`)
- Bind to internal Docker network only

## 6. Audit Logging

### 6.1 What We Log
| Action | Logged Data |
|---|---|
| Alert polled | timestamp, alert count, success/failure |
| AI triage run | prompt (masked), response, model, latency, tokens |
| Case created/updated | case ID, action, actor (API key) |
| Analyst note added | case ID, note length |
| Dashboard access | IP, path, timestamp |
| API request | method, path, status, latency, API key owner |
| Error | error type, message (no secrets), stack trace |

### 6.2 What We Never Log
- Passwords, API keys, tokens
- Raw unredacted Wazuh alerts (masked version only)
- Personal contact information
- Full file contents
- Command outputs from agents

### 6.3 Log Retention
- Application logs: 30 days (Docker json-file driver, `max-size=10m`, `max-file=3`)
- Audit log in PostgreSQL: 1 year
- AI triage results: 1 year
- Old logs compressed and archived to S3 (Phase 2)

## 7. API Security

### 7.1 Authentication
- All API endpoints require `X-API-Key` header (except `/health`)
- Multiple valid API keys stored in `.env` or database
- Failed auth returns 401 with generic message

### 7.2 Rate Limiting
- 100 requests/minute per API key
- Burst limit: 20 requests in 1 second
- Rate limit headers in response: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`

### 7.3 Input Validation
- All request bodies validated via Pydantic schemas
- SQL injection prevention via SQLAlchemy parameterized queries
- No direct concatenation of user input into queries

## 8. Production Hardening (Future)

- TLS termination via nginx or ALB
- WAF for dashboard access
- VPC with private subnets for app and database
- AWS Secrets Manager instead of `.env`
- Regular security scanning of Docker images
- Penetration testing before Phase 2
- SOC 2 / ISO 27001 readiness for commercial deployment

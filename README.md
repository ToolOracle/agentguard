# 🛡️ AgentGuard MCP

**Security, Policy & Audit Layer for AI Agent Tool Execution** — 7 tools | Part of [FeedOracle](https://feedoracle.io) & [ToolOracle](https://tooloracle.io)

![Tools](https://img.shields.io/badge/MCP_Tools-7-10B898?style=flat-square)
![Status](https://img.shields.io/badge/Status-Live-00C853?style=flat-square)
![Backend](https://img.shields.io/badge/Backend-SQLite_WAL-4A90D9?style=flat-square)
![Tier](https://img.shields.io/badge/Tier-Free-2196F3?style=flat-square)

AgentGuard is the governance and security layer for AI agent workflows. Before any tool executes, AgentGuard evaluates policies, scores risk, detects secrets and injection attempts, logs to a tamper-evident audit trail, and explains every decision. Built for regulated environments, autonomous payments, and enterprise AI agent deployments.

## Quick Connect

```bash
# FeedOracle (compliance-focused)
npx -y mcp-remote https://feedoracle.io/guard/mcp/

# ToolOracle (agent-commerce focused)
npx -y mcp-remote https://tooloracle.io/guard/mcp/
```

```json
{
  "mcpServers": {
    "agentguard": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://feedoracle.io/guard/mcp/"]
    }
  }
}
```

## How It Works — The Agent Security Loop

```
Agent wants to call: payment_execute({amount: 5000})
         │
         ▼
   policy_preflight()         ← Check before execution
         │
   risk_score: 95             ← Critical
   matched: pol-001, pol-002  ← Payment + High-risk policies
   decision: require_approval ← Human gate triggered
         │
   approval_required()        ← Register pending approval
         │
   [Human approves]
         │
   tool executes
         │
   audit_log_write()          ← Record outcome with signature
         │
   decision_explain()         ← Exportable compliance evidence
```

## Tools — Welle 1: Core Security (7)


| Tool | Description |
|------|-------------|
| `policy_preflight` | Pre-flight check before any tool call. Evaluates 7 policies, computes risk score, detects threats, auto-logs. Returns `allowed`/`denied`/`require_approval`/`flagged`. |
| `tool_risk_score` | 0-100 risk score for tool + input. Detects secrets (API keys, passwords), prompt injection, high-value amounts. `eth_gas`→5, `payment_execute`→95+. |
| `approval_required` | Check if tool needs human approval. Optionally registers a pending approval request with tracking URL. |
| `audit_log_write` | Write tool execution to persistent, cryptographically-signed audit log (SQLite WAL). Call after execution to record outcome. |
| `audit_log_query` | Query audit trail. Filter by agent, tool, decision, time range. Paginated. Returns signed entries for tamper verification. |
| `decision_explain` | Human-readable explanation of any allow/deny decision. Pass `request_id` for stored entry or `tool_name` + `tool_args` for fresh analysis. |
| `rate_limit_check` | Check agent rate limits: 200/min, 5000/hr, 50000/day. Returns per-window usage with percentage. |


## Tools — Welle 2: Payment Controls & Safety

| Tool | Description |
|------|-------------|
| `payment_policy_check` | Validate payment against policy: amount limits (>100k warns, >1M blocks), recipient denylist, supported currencies/networks, AML thresholds (>10k fiat flagged), MiCA flags. |
| `spend_limit_check` | Check per-call/hour/day spend limits by trust level. Default: 10k/call, 50k/hr, 200k/day. Trusted: 100k/call, 500k/hr, 2M/day. |
| `secret_exposure_check` | Deep scan for 19 secret patterns: OpenAI/GitHub/AWS/Slack keys, Bearer/Basic auth, ETH private keys, Bitcoin WIF, credit cards, SSNs, emails. Returns severity + remediation. |
| `payload_safety_check` | 18-pattern safety scan: prompt injection, jailbreak/DAN, role hijacking, SQL (UNION/DROP/OR 1=1), XSS, Python/JS/Shell injection, path traversal, null bytes, oversized payloads. |
| `replay_guard_check` | Detect replay attacks via SHA256 fingerprint (agent+tool+args). Configurable window (default 5 min). Returns duplicate count + first/last seen. |



## Tools — Welle 3: Governance & Threat Intelligence (5)

| Tool | Description |
|------|-------------|
| `cross_tool_anomaly_check` | Detect anomalous patterns: risky combos (wallet-recon→transfer, AML→payment), high frequency, repeated denials (policy probing), broad reconnaissance, elevated avg risk score. |
| `scope_check` | Role-based scope control. Roles: admin, compliance_officer, trader, auditor, developer, readonly. Returns has_scope, missing scope, granting roles. Logs denials. |
| `session_validate` | Full session lifecycle: create (TTL + call budget), validate (increment counter), invalidate, info. Sessions carry role, scopes, tenant, expiry. |
| `tenant_policy_check` | Multi-tenant governance. Built-in tenants: default, fintech_eu (MiCA/DORA/AMLD6), defi_protocol, enterprise_read. Per-tenant blocklists, risk limits, spend caps. |
| `threat_intel_check` | Entity threat intelligence. Auto-detects ETH addresses, IPs, domains. Checks sanctions (Tornado Cash, mixers), disposable services, behavioral analysis from audit log. |

### Built-in Tenants

| Tenant | Max Risk | Spend/Day | Frameworks |
|--------|----------|-----------|------------|
| `default` | 70 | 100,000 | — |
| `fintech_eu` | 60 | 500,000 | MiCA, DORA, AMLD6 |
| `defi_protocol` | 80 | 10,000,000 | MiCA |
| `enterprise_read` | 30 | 0 | — |

### Built-in Roles & Scopes

| Role | Scopes |
|------|--------|
| `admin` | All scopes |
| `compliance_officer` | audit:read, compliance:read, blockchain:read, security:scan |
| `trader` | blockchain:read, payment:check, payment:execute, audit:read |
| `auditor` | audit:read, audit:write, compliance:read, monitor:read |
| `developer` | blockchain:read, security:scan, audit:read, monitor:read |
| `readonly` | blockchain:read, audit:read |


## Built-in Policies (7 Default)

| Policy | Condition | Action |
|--------|-----------|--------|
| pol-001 | Payment/transfer tools | `require_approval` |
| pol-002 | Risk score ≥ 80 | `require_approval` |
| pol-003 | Secret/key in payload | `deny` |
| pol-004 | Rate limit exceeded | `flag` |
| pol-005 | Risk score ≤ 20 | `allow` freely |
| pol-006 | Prompt injection detected | `deny` |
| pol-007 | Same tool > 50 calls/60s | `flag` |

## Risk Score Guide

| Score | Level | Action |
|-------|-------|--------|
| 0-14 | Minimal | Proceed freely |
| 15-39 | Low | Proceed, log for audit |
| 40-69 | Medium | Flag and proceed with caution |
| 70-89 | High | Require human approval |
| 90-100 | Critical | Block execution |

## Use Cases

- **Regulated AI Workflows**: MiCA/DORA compliance requires audit trails — AgentGuard provides them automatically
- **Autonomous Payments**: x402 agent payments run through `approval_required` gate before execution
- **Multi-tenant Platforms**: Rate limiting and policy scoping per agent/session
- **Security Monitoring**: Real-time detection of prompt injection and secret exposure in tool arguments
- **Compliance Reporting**: Export audit log with cryptographic signatures for regulatory review

## Backend: SQLite WAL-Mode

Persistent, stable, no daemon required. WAL-mode supports 1000+ writes/second. Shared between `feedoracle.io` and `tooloracle.io` — one source of truth.

## Links

- 🛡️ FeedOracle: `https://feedoracle.io/guard/mcp/`
- 🔧 ToolOracle: `https://tooloracle.io/guard/mcp/`
- 📚 Docs: [feedoracle.io](https://feedoracle.io)
- 🏠 Platform: [tooloracle.io](https://tooloracle.io)

---

*Built by [FeedOracle](https://feedoracle.io) — Evidence by Design*

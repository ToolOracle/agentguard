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

## Tools (7)

| Tool | Description |
|------|-------------|
| `policy_preflight` | Pre-flight check before any tool call. Evaluates 7 policies, computes risk score, detects threats, auto-logs. Returns `allowed`/`denied`/`require_approval`/`flagged`. |
| `tool_risk_score` | 0-100 risk score for tool + input. Detects secrets (API keys, passwords), prompt injection, high-value amounts. `eth_gas`→5, `payment_execute`→95+. |
| `approval_required` | Check if tool needs human approval. Optionally registers a pending approval request with tracking URL. |
| `audit_log_write` | Write tool execution to persistent, cryptographically-signed audit log (SQLite WAL). Call after execution to record outcome. |
| `audit_log_query` | Query audit trail. Filter by agent, tool, decision, time range. Paginated. Returns signed entries for tamper verification. |
| `decision_explain` | Human-readable explanation of any allow/deny decision. Pass `request_id` for stored entry or `tool_name` + `tool_args` for fresh analysis. |
| `rate_limit_check` | Check agent rate limits: 200/min, 5000/hr, 50000/day. Returns per-window usage with percentage. |

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

# AgentGuard MCP Server

**Runtime security, policy enforcement and audit governance for AI agents.**

Port 12001 | Part of [ToolOracle](https://tooloracle.io) Infrastructure

## What it does

AgentGuard sits between your AI agent and its tools. Before any tool executes, AgentGuard checks policies, scores risk, validates identity, and logs everything to a tamper-aware audit trail.

## 17 Tools — 3 Layers

### Layer 1: Pre-execution Gate
| Tool | Purpose |
|------|---------|
| `policy_preflight` | Check all policies before a tool call runs |
| `tool_risk_score` | 0-100 risk score for tool + input combination |
| `approval_required` | Human-in-the-loop gate check |
| `decision_explain` | Explain allow/deny with policy reference |
| `rate_limit_check` | Agent rate limit enforcement |

### Layer 2: Payload & Payment Security
| Tool | Purpose |
|------|---------|
| `payment_policy_check` | Validate payments against limits/sanctions/rules |
| `spend_limit_check` | Daily spend limit per agent |
| `secret_exposure_check` | Scan payloads for API keys, tokens, PII |
| `payload_safety_check` | Detect injection, XSS, SQL injection in payloads |
| `replay_guard_check` | Prevent duplicate/replay attacks |

### Layer 3: Advanced Governance
| Tool | Purpose |
|------|---------|
| `cross_tool_anomaly_check` | Detect suspicious tool usage patterns |
| `scope_check` | RBAC: verify agent has required role/scope |
| `session_validate` | Session lifecycle with TTL and call budgets |
| `tenant_policy_check` | Multi-tenant governance (4 preset tenants) |
| `threat_intel_check` | Check entities against threat intelligence feeds |
| `audit_log_write` | Write to persistent audit trail |
| `audit_log_query` | Query audit history with filters |

## Authentication

AgentGuard validates Bearer tokens against FeedOracle OAuth 2.1 infrastructure:

- **Public tools** (no auth): `policy_preflight`, `tool_risk_score`, `decision_explain`
- **All other tools**: Require valid Bearer token in `Authorization` header
- **KYA Trust Levels**: UNVERIFIED → KNOWN → TRUSTED → CERTIFIED (affects risk scoring)

Register at: `https://feedoracle.io/.well-known/oauth-authorization-server`

## Risk Scoring

Base risk (static per tool category) + contextual modifiers:

- Payload size, secret detection, injection patterns, high-value amounts
- **KYA trust adjustment**: CERTIFIED agents get -20, TRUSTED -10, KNOWN -5
- **Unauthenticated callers**: +5 penalty
- Final score 0-100, mapped to policies (allow/deny/flag/require_approval)

## Quick Start

```bash
# Connect via Claude Desktop
claude mcp add --transport http agentguard https://tooloracle.io/guard/mcp/

# Or via MCP remote
npx -y mcp-remote https://tooloracle.io/guard/mcp/
```

## Endpoints

- MCP: `https://tooloracle.io/guard/mcp/`
- Health: `https://tooloracle.io/guard/health`

## Built-in Policies

| ID | Name | Action |
|----|------|--------|
| pol-001 | Block payment tools without approval | require_approval |
| pol-002 | High risk score (≥80) requires approval | require_approval |
| pol-003 | Block secret/key exposure in payloads | deny |
| pol-005 | Allow read-only tools freely | allow |
| pol-006 | Deny prompt injection attempts | deny |
| pol-007 | Flag high-frequency same-tool calls | flag |

## Part of the ToolOracle Stack

AgentGuard works with the full ToolOracle autonomous agent stack:

- **SchedulerOracle** — Cron/interval task scheduling
- **Decision Preflight** — Paid evidence gate before action
- **TrustOracle** — Verifiable evidence & claim verification
- **MemoryOracle** — Persistent agent memory

## License

MIT

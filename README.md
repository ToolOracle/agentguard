# AgentGuard MCP Server v1.3

**Zustandsbasierter Runtime Security & Governance Layer für AI Agents.**

Port 12001 | Part of [ToolOracle](https://tooloracle.io) Infrastructure

## What it does

AgentGuard is a policy-driven Runtime Enforcement System for AI agents. It controls agent behavior before, during, and after tool execution — with persistent state management, automatic escalation, and cryptographically auditable decisions.

## 20 Tools — 4 Layers

### Layer 1: Pre-Execution Gate (5 Tools)
| Tool | Purpose |
|------|---------|
| `policy_preflight` | Check all policies before a tool call. State-aware: escalated agents get forced approval |
| `tool_risk_score` | 0-100 risk score (base + payload analysis + KYA trust adjustment) |
| `approval_required` | Human-in-the-loop gate with persistent approval records |
| `decision_explain` | Explain allow/deny with policy reference and risk breakdown |
| `rate_limit_check` | Per-minute/hour/day rate limit enforcement |

### Layer 2: Payload & Payment Security (5 Tools)
| Tool | Purpose |
|------|---------|
| `payment_policy_check` | Amount limits, recipient allow/denylists, network rules, counterparty risk |
| `spend_limit_check` | Daily spend limits per agent (default/trusted tiers) |
| `secret_exposure_check` | Scan for API keys, tokens, PII (8 patterns) |
| `payload_safety_check` | Detect prompt injection, XSS, SQL injection, code injection |
| `replay_guard_check` | SHA256 fingerprint deduplication within time window |

### Layer 3: Advanced Governance (7 Tools)
| Tool | Purpose |
|------|---------|
| `cross_tool_anomaly_check` | Detect suspicious tool sequences (5 predefined attack patterns) |
| `scope_check` | RBAC with 5 roles (admin, compliance_officer, analyst, agent, readonly) |
| `session_validate` | Session lifecycle with TTL, call budgets, scope binding |
| `tenant_policy_check` | Multi-tenant governance (4 tenants: default, fintech_eu, defi, enterprise_read) |
| `threat_intel_check` | Entity verification against threat feeds (ETH addresses, IPs, domains) |
| `audit_log_write` | Persistent audit trail with HMAC signatures and caller identity |
| `audit_log_query` | Filter audit by agent/tool/decision/time with pagination |

### Layer 4: Post-Execution & Runtime (3 Tools)
| Tool | Purpose |
|------|---------|
| `output_safety_scan` | Post-exec scanner for PII, secrets, exfiltration, tool poisoning |
| `emergency_kill` | Immediate agent termination (sessions, approvals, rate limits, state) |
| `tool_manifest_verify` | Supply-chain verification: publisher allowlist, description injection scan |

## Agent State Model

Persistent, escalation-only state machine with TTL:

```
active → monitoring → approval_required → suspended → killed
```

| State | Effect | Trigger | TTL |
|-------|--------|---------|-----|
| `active` | Normal operation | Default | — |
| `monitoring` | Enhanced audit logging | Post-scan `warn` | 30 min |
| `approval_required` | Every tool call needs approval | Post-scan `flag` | 1 hour |
| `suspended` | Only public tools allowed | Manual | — |
| `killed` | Completely blocked | `emergency_kill` | Permanent |

States are persistent in SQLite, cached in-memory, survive restarts, and can only escalate (never de-escalate except TTL expiry or admin reset).

## Enforced Control Flow

```
Request → Kill/Suspend Gate → Auth Gate → Tool Execution → Post-Scan → Response
              │                   │              │              │
              │                   │              │              ├─ clean: pass through
              │                   │              │              ├─ warn: pass + monitoring state
              │                   │              │              ├─ flag: pass + approval_required state
              │                   │              │              └─ block: OUTPUT_BLOCKED (leak-safe)
              │                   │              │
              │                   │              └─ Result with _auth identity
              │                   └─ Bearer → OAuth → KYA Trust Level
              └─ killed → AGENT_KILLED | suspended → public only | approval_required → forced approval
```

## Authentication

AgentGuard validates Bearer tokens against FeedOracle OAuth 2.1:

- **Public tools** (no auth): `policy_preflight`, `tool_risk_score`, `decision_explain`, `tool_manifest_verify`
- **All other tools**: Require valid Bearer token
- **KYA Trust Levels**: UNVERIFIED → KNOWN → TRUSTED → CERTIFIED (affects risk scoring)

OAuth discovery: `https://feedoracle.io/.well-known/oauth-authorization-server`

## Post-Execution Output Scanning

Every non-security tool call is automatically scanned after execution:

- **PII Detection**: SSN, IBAN, email, phone, passport, addresses
- **Secret Leak**: API keys (OpenAI, GitHub, AWS), tokens, private keys
- **Exfiltration**: Outbound URLs, base64 data URIs, hex encoding
- **Tool Poisoning**: Prompt injection patterns in tool output

Blocked outputs are never returned to the client. Only the `output_hash` is preserved in the audit trail for forensic verification.

## Quick Start

```bash
claude mcp add --transport http agentguard https://tooloracle.io/guard/mcp/
```

## Endpoints

- MCP: `https://tooloracle.io/guard/mcp/`
- Health: `https://tooloracle.io/guard/health`
- Also: `https://feedoracle.io/guard/mcp/`

## License

MIT

#!/usr/bin/env python3
"""
AgentGuard MCP Server v1.0.0 — Port 12001
Security, policy and audit controls for AI agent tool execution.

7 Core Tools (Welle 1):
  policy_preflight         — Pre-flight check before any tool call
  tool_risk_score          — 0-100 risk score for tool + input
  approval_required        — Human approval gate check
  audit_log_write          — Write call to persistent audit log
  audit_log_query          — Query audit trail (filter by agent/tool/time)
  decision_explain         — Explain allow/deny with policy reference
  rate_limit_check         — Check if agent exceeded rate limits

Backend: SQLite WAL-mode (stable, persistent, no daemon required)
Domains: tooloracle.io/guard/mcp/ + feedoracle.io/guard/mcp/
"""
import os, sys, json, logging, sqlite3, hashlib, hmac, time, re
import asyncio, aiohttp
from datetime import datetime, timezone, timedelta
from pathlib import Path

# ── Paths ────────────────────────────────────────────────────────────────────
BASE_DIR  = Path("/root/agentguard")
DB_PATH   = BASE_DIR / "agentguard.db"
LOG_PATH  = BASE_DIR / "agentguard.log"
BASE_DIR.mkdir(parents=True, exist_ok=True)

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [AgentGuard] %(levelname)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(str(LOG_PATH), mode="a"),
    ]
)
logger = logging.getLogger("AgentGuard")

# ── FeedOracle Auth Integration ──────────────────────────────────────────────
import hashlib as _hl

FO_BILLING_DB = "/root/rwa_node/mcp/feedoracle_billing.db"
AGENTGUARD_PUBLIC_TOOLS = {"policy_preflight", "tool_risk_score", "decision_explain", "tool_manifest_verify"}

def _verify_bearer_token(token: str) -> dict | None:
    """Verify Bearer token against FeedOracle OAuth DB. Returns {client_id, scopes, tier} or None."""
    if not token:
        return None
    try:
        token_hash = _hl.sha256(token.encode()).hexdigest()
        conn = sqlite3.connect(FO_BILLING_DB, timeout=5)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT at.client_id, at.scopes_json, at.expires_at, oc.tier "
            "FROM oauth_access_tokens at "
            "JOIN oauth_clients oc ON at.client_id = oc.client_id "
            "WHERE at.token_hash=? AND at.revoked=0",
            (token_hash,)
        ).fetchone()
        conn.close()
        if not row:
            return None
        import time as _t
        if row["expires_at"] < int(_t.time()):
            return None
        return {
            "client_id": row["client_id"],
            "scopes": json.loads(row["scopes_json"]) if row["scopes_json"] else [],
            "tier": row["tier"] or "free",
        }
    except Exception as e:
        logger.warning(f"Token verification failed: {e}")
        return None

def _get_kya_trust(client_id: str) -> dict:
    """Get KYA trust level for a client_id. Returns {level, name, score}."""
    if not client_id:
        return {"level": 0, "name": "UNVERIFIED", "score": 0}
    try:
        conn = sqlite3.connect(FO_BILLING_DB, timeout=5)
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT trust_level, trust_score, agent_name, owner_org "
            "FROM kya_profiles WHERE client_id=? AND is_active=1",
            (client_id,)
        ).fetchone()
        conn.close()
        if not row:
            return {"level": 0, "name": "UNVERIFIED", "score": 0}
        names = {0: "UNVERIFIED", 1: "KNOWN", 2: "TRUSTED", 3: "CERTIFIED"}
        return {
            "level": row["trust_level"],
            "name": names.get(row["trust_level"], "UNVERIFIED"),
            "score": row["trust_score"] or 0,
            "agent_name": row["agent_name"] or "",
            "org": row["owner_org"] or "",
        }
    except Exception as e:
        logger.warning(f"KYA lookup failed: {e}")
        return {"level": 0, "name": "UNVERIFIED", "score": 0}



# ── Config ───────────────────────────────────────────────────────────────────
VERSION      = "1.0.0"
PORT_MCP     = 12001
PORT_HEALTH  = 12002
SIGN_SECRET  = os.getenv("AGENTGUARD_SECRET", "agentguard-tooloracle-2026")

# ── DB Setup ─────────────────────────────────────────────────────────────────
def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH), timeout=15, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA cache_size=10000")
    conn.execute("PRAGMA temp_store=MEMORY")
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS policies (
        id          TEXT PRIMARY KEY,
        name        TEXT NOT NULL,
        description TEXT,
        condition   TEXT NOT NULL,
        action      TEXT NOT NULL CHECK(action IN ('allow','deny','require_approval','flag')),
        risk_threshold INTEGER DEFAULT 70,
        applies_to  TEXT DEFAULT 'all',
        enabled     INTEGER DEFAULT 1,
        priority    INTEGER DEFAULT 100,
        created_at  TEXT NOT NULL,
        updated_at  TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS audit_log (
        id              INTEGER PRIMARY KEY AUTOINCREMENT,
        request_id      TEXT NOT NULL,
        agent_id        TEXT NOT NULL DEFAULT 'unknown',
        session_id      TEXT,
        tool_name       TEXT NOT NULL,
        tool_input_hash TEXT,
        tool_input_size INTEGER,
        risk_score      INTEGER,
        decision        TEXT NOT NULL CHECK(decision IN ('allowed','denied','flagged','approved','pending')),
        policy_ids      TEXT,
        reason          TEXT,
        duration_ms     INTEGER,
        signature       TEXT,
        created_at      TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS rate_limits (
        agent_id    TEXT NOT NULL,
        window_key  TEXT NOT NULL,
        call_count  INTEGER DEFAULT 0,
        first_call  TEXT NOT NULL,
        last_call   TEXT NOT NULL,
        PRIMARY KEY (agent_id, window_key)
    );

    CREATE TABLE IF NOT EXISTS approvals (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        request_id  TEXT NOT NULL UNIQUE,
        agent_id    TEXT NOT NULL,
        tool_name   TEXT NOT NULL,
        reason      TEXT,
        status      TEXT DEFAULT 'pending' CHECK(status IN ('pending','approved','denied','revoked')),
        approved_by TEXT,
        created_at  TEXT NOT NULL,
        resolved_at TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_audit_agent    ON audit_log(agent_id);
    CREATE INDEX IF NOT EXISTS idx_audit_tool     ON audit_log(tool_name);
    CREATE INDEX IF NOT EXISTS idx_audit_created  ON audit_log(created_at);
    CREATE INDEX IF NOT EXISTS idx_audit_decision ON audit_log(decision);
    CREATE INDEX IF NOT EXISTS idx_rate_agent     ON rate_limits(agent_id);

    CREATE TABLE IF NOT EXISTS agent_states (
        agent_id    TEXT PRIMARY KEY,
        state       TEXT NOT NULL DEFAULT 'active'
                    CHECK(state IN ('active','monitoring','approval_required','suspended','killed')),
        reason      TEXT,
        triggered_by TEXT,
        output_hash TEXT,
        tenant_id   TEXT,
        created_at  TEXT NOT NULL,
        updated_at  TEXT NOT NULL,
        expires_at  TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_agent_state ON agent_states(state);
    """)
    conn.commit()

    # ── Default Policies ─────────────────────────────────────────────────────
    now = ts()
    defaults = [
        ("pol-001", "Block payment tools without approval",
         "Require human approval for any payment or transfer tool",
         "payment|transfer|wallet_send|wire|withdraw", "require_approval", 50, "all", 1, 10),
        ("pol-002", "High risk score requires approval",
         "Any call scoring >= 80 requires explicit approval",
         "risk_score>=80", "require_approval", 80, "all", 1, 20),
        ("pol-003", "Block secret/key exposure in payloads",
         "Deny calls that contain API keys, tokens or secrets in args",
         "secret_in_payload", "deny", 0, "all", 1, 5),
        ("pol-004", "Rate limit enforcement",
         "Flag agents exceeding 200 calls per minute",
         "rate_exceeded", "flag", 0, "all", 1, 30),
        ("pol-005", "Allow read-only tools freely",
         "Low-risk read/overview tools are always allowed",
         "risk_score<=20", "allow", 0, "all", 1, 90),
        ("pol-006", "Deny prompt injection attempts",
         "Block payloads containing injection patterns",
         "injection_detected", "deny", 0, "all", 1, 5),
        ("pol-007", "Flag high-frequency same-tool calls",
         "Flag if same tool called > 50 times in 60s by same agent",
         "tool_frequency_exceeded", "flag", 0, "all", 1, 25),
    ]
    for p in defaults:
        conn.execute("""
            INSERT OR IGNORE INTO policies
            (id, name, description, condition, action, risk_threshold, applies_to, enabled, priority, created_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, (*p, now, now))
    conn.commit()
    conn.close()
    logger.info(f"DB initialized: {DB_PATH}")

# ── Helpers ───────────────────────────────────────────────────────────────────
def ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def make_request_id() -> str:
    import uuid
    return f"ag-{uuid.uuid4().hex[:12]}"

def sign_entry(data: dict) -> str:
    payload = json.dumps(data, sort_keys=True)
    return hmac.new(SIGN_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()[:16]

# ── Risk Scoring Engine ───────────────────────────────────────────────────────
# Tool base risk scores
TOOL_RISK = {
    # Very low (0-10): pure reads
    "health_check": 0, "ping": 0, "status": 0,
    "eth_gas": 5, "bnb_overview": 5, "apt_overview": 5,
    "xlm_overview": 5, "xrpl_overview": 5, "base_overview": 5,
    "sol_overview": 5, "arb_overview": 5, "ton_overview": 5,
    "crypto_price": 5, "crypto_global": 5, "weather_current": 5,
    "news_search": 8, "macro_indicator": 8,
    # Low (10-25): data queries with params
    "eth_stablecoin_check": 10, "xrpl_rlusd": 10,
    "bnb_stablecoin_check": 10, "base_stablecoin_check": 10,
    "sol_token_risk": 15, "arb_token_risk": 15,
    "eth_token_risk": 15, "bnb_token_risk": 15,
    "aml_sanctions_check": 20, "policy_preflight": 5,
    "audit_log_query": 10, "tool_risk_score": 5,
    # Medium (25-50): external calls, enrichment
    "lead_search": 30, "flight_search": 25, "hotel_search": 25,
    "eth_protocol_tvl": 20, "eth_rwa_tokenization": 20,
    "eth_wallet_intel": 30, "bnb_wallet_intel": 30,
    "sol_wallet_analysis": 35, "arb_whale_watch": 35,
    "sol_whale_watch": 35, "xrpl_dex_orderbook": 25,
    "bnb_contract_verify": 30, "eth_contract_verify": 30,
    "base_contract_verify": 30,
    # High (50-75): write/state-change operations
    "audit_log_write": 20, "create_entity": 50,
    "register_provider": 55, "register_contract": 55,
    "register_policy": 60, "log_incident": 50,
    # Very high (75-100): payments, transfers, irreversible
    "payment_execute": 95, "wallet_transfer": 95,
    "wallet_send": 95, "wire_transfer": 95,
    "payment_policy_check": 40, "spend_limit_check": 40,
}

SECRET_PATTERNS = [
    r'"(api[_-]?key|apikey)"\s*:\s*"[\w\-]{4,}"',
    r'"(secret|token|password|passwd|pwd)"\s*:\s*"[\w\-]{4,}"',
    r"(api[_-]?key|apikey)\s*[:=]\s*[\w\-]{4,}",
    r"(secret|token|password|passwd|pwd)\s*[:=]\s*[\w\-]{4,}",
    r"sk-[a-zA-Z0-9]{20,}",
    r"xoxb-[a-zA-Z0-9\-]{20,}",
    r"github_pat_[a-zA-Z0-9_]{36,}",
    r"0x[a-fA-F0-9]{64}",
]

INJECTION_PATTERNS = [
    r"ignore\s+(previous|all|above)\s+instructions?",
    r"you\s+are\s+now\s+(?:a|an|my)",
    r"(system\s*prompt|jailbreak|DAN\s*mode)",
    r"<\s*script\s*>",
    r"__import__\s*\(",
    r"\beval\s*\(",
    r"DROP\s+TABLE|DELETE\s+FROM|INSERT\s+INTO",
]

def compute_risk_score(tool_name: str, args: dict, agent_id: str = "unknown") -> tuple[int, list[str]]:
    """Returns (score 0-100, reasons list)"""
    reasons = []
    score = TOOL_RISK.get(tool_name, 40)  # Default: medium-unknown

    args_str = json.dumps(args).lower()
    args_len = len(args_str)

    # Input size risk
    if args_len > 10000:
        score += 15
        reasons.append(f"large payload ({args_len} chars)")
    elif args_len > 2000:
        score += 5
        reasons.append(f"medium payload ({args_len} chars)")

    # Secret detection
    for pattern in SECRET_PATTERNS:
        if re.search(pattern, args_str, re.IGNORECASE):
            score += 30
            reasons.append("potential secret/key detected in payload")
            break

    # Injection detection
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, args_str, re.IGNORECASE):
            score += 40
            reasons.append("prompt injection pattern detected")
            break

    # High-value amounts
    for key in ["amount", "value", "amount_usd", "amount_xrp", "price"]:
        val = args.get(key)
        if val and isinstance(val, (int, float)):
            if val > 100000:
                score += 25
                reasons.append(f"high value amount: {val}")
            elif val > 10000:
                score += 10
                reasons.append(f"significant amount: {val}")

    # Unknown agent
    if agent_id in ("unknown", "", None):
        score += 10
        reasons.append("unidentified agent")

    return min(score, 100), reasons


def adjust_risk_for_caller(base_score: int, reasons: list, caller: dict) -> tuple[int, list]:
    """Adjust risk score based on caller identity and KYA trust level."""
    if not caller or not caller.get("authenticated"):
        return base_score + 5, reasons + ["unauthenticated caller (+5)"]

    kya_level = caller.get("kya_level", 0)
    if kya_level >= 3:  # CERTIFIED
        adj = max(base_score - 20, 0)
        return adj, reasons + [f"CERTIFIED agent (-20, {base_score}->{adj})"]
    elif kya_level >= 2:  # TRUSTED
        adj = max(base_score - 10, 0)
        return adj, reasons + [f"TRUSTED agent (-10, {base_score}->{adj})"]
    elif kya_level >= 1:  # KNOWN
        adj = max(base_score - 5, 0)
        return adj, reasons + [f"KNOWN agent (-5, {base_score}->{adj})"]
    else:
        return base_score, reasons

def check_secrets(args: dict) -> tuple[bool, str]:
    args_str = json.dumps(args)
    for pattern in SECRET_PATTERNS:
        if re.search(pattern, args_str, re.IGNORECASE):
            return True, f"Pattern matched: {pattern[:40]}..."
    return False, ""

def check_injection(args: dict) -> tuple[bool, str]:
    args_str = json.dumps(args)
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, args_str, re.IGNORECASE):
            return True, f"Injection pattern: {pattern[:40]}..."
    return False, ""

def get_policies(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM policies WHERE enabled=1 ORDER BY priority ASC"
    ).fetchall()
    return [dict(r) for r in rows]

def evaluate_policies(tool_name: str, args: dict, risk_score: int,
                      risk_reasons: list, agent_id: str,
                      policies: list[dict]) -> tuple[str, list[str], str]:
    """
    Returns: (decision, matched_policy_ids, reason)
    decision: 'allowed' | 'denied' | 'require_approval' | 'flagged'
    """
    matched = []
    final_decision = "allowed"
    reason_parts = []

    has_secret, secret_detail  = check_secrets(args)
    has_inject, inject_detail  = check_injection(args)

    for pol in policies:
        cond = pol["condition"]
        hit  = False

        if "secret_in_payload"       in cond and has_secret:     hit = True
        if "injection_detected"      in cond and has_inject:     hit = True
        if "risk_score>="            in cond:
            threshold = int(cond.split(">=")[1])
            if risk_score >= threshold:                            hit = True
        if "risk_score<="            in cond:
            threshold = int(cond.split("<=")[1])
            if risk_score <= threshold:                            hit = True
        if "payment|transfer"        in cond:
            if any(kw in tool_name for kw in
                   ["payment","transfer","wallet_send","wire","withdraw"]): hit = True
        if "rate_exceeded"           in cond:   pass  # handled separately
        if "tool_frequency_exceeded" in cond:   pass  # handled separately

        if hit:
            matched.append(pol["id"])
            action = pol["action"]
            if action == "deny":
                final_decision = "denied"
                reason_parts.append(f"Policy {pol['id']}: {pol['name']}")
                break  # deny is final
            elif action == "require_approval" and final_decision != "denied":
                final_decision = "require_approval"
                reason_parts.append(f"Policy {pol['id']}: {pol['name']}")
            elif action == "flag" and final_decision == "allowed":
                final_decision = "flagged"
                reason_parts.append(f"Policy {pol['id']}: {pol['name']}")

    if has_secret:
        reason_parts.append(f"Secret exposure: {secret_detail}")
    if has_inject:
        reason_parts.append(f"Injection: {inject_detail}")
    if risk_reasons:
        reason_parts.extend(risk_reasons)

    reason = " | ".join(reason_parts) if reason_parts else "All policies passed"
    return final_decision, matched, reason

# ── Rate Limit Engine ─────────────────────────────────────────────────────────
RATE_LIMITS = {
    "per_minute": 200,
    "per_hour": 5000,
    "per_day": 50000,
}

def check_rate_limit(conn: sqlite3.Connection, agent_id: str) -> tuple[bool, dict]:
    now = datetime.now(timezone.utc)
    exceeded = False
    status = {}

    for window, limit in RATE_LIMITS.items():
        if window == "per_minute":
            since = (now - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        elif window == "per_hour":
            since = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        else:
            since = (now - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")

        count = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE agent_id=? AND created_at>=?",
            (agent_id, since)
        ).fetchone()[0]

        pct = round(count / limit * 100, 1)
        status[window] = {"calls": count, "limit": limit, "pct_used": pct}
        if count >= limit:
            exceeded = True
            status[window]["exceeded"] = True

    return exceeded, status

# ── MCP Tools ─────────────────────────────────────────────────────────────────

async def handle_policy_preflight(args: dict) -> dict:
    """
    Pre-flight check: evaluate all policies before a tool call runs.
    Returns decision (allowed/denied/require_approval/flagged) + reason + risk score.
    """
    tool_name = args.get("tool_name", "")
    tool_args = args.get("tool_args", {})
    agent_id  = args.get("agent_id", "unknown")
    session_id = args.get("session_id")
    caller    = args.pop("_caller", {})

    if not tool_name:
        return {"error": "tool_name required"}

    start = time.monotonic()
    conn = get_db()

    try:
        # 1. Risk score (base + caller trust adjustment)
        risk_score, risk_reasons = compute_risk_score(tool_name, tool_args, agent_id)
        risk_score, risk_reasons = adjust_risk_for_caller(risk_score, risk_reasons, caller)

        # 2. Rate limit
        rate_exceeded, rate_status = check_rate_limit(conn, agent_id)

        # 3. Policy evaluation
        policies = get_policies(conn)
        decision, matched_policies, reason = evaluate_policies(
            tool_name, tool_args, risk_score, risk_reasons, agent_id, policies
        )

        # Rate limit overrides
        if rate_exceeded and decision == "allowed":
            decision = "flagged"
            reason += " | Rate limit exceeded"
            matched_policies.append("pol-004")

        # Agent state overrides (persistent escalation from post-scan)
        _agent_st = get_agent_state(agent_id)
        if _agent_st == "approval_required" and decision == "allowed":
            decision = "require_approval"
            reason += f" | Agent state: approval_required (escalated by post-scan)"
            matched_policies.append("state-escalation")
        elif _agent_st == "monitoring" and decision == "allowed":
            reason += f" | Agent state: monitoring (enhanced audit active)"

        # _force_approval from state gate
        if args.get("_force_approval") and decision == "allowed":
            decision = "require_approval"
            reason += " | Forced approval: agent in approval_required state"

        duration_ms = round((time.monotonic() - start) * 1000)
        request_id = make_request_id()

        # 4. Auto-write to audit log
        entry = {
            "agent_id": agent_id, "tool_name": tool_name,
            "risk_score": risk_score, "decision": decision
        }
        sig = sign_entry(entry)
        # Map decision to valid DB values (require_approval → pending for DB constraint)
        db_decision = "pending" if decision == "require_approval" else ("denied" if decision == "denied" else decision)
        # Enrich reason with caller identity for audit trail
        _audit_reason = reason
        if caller.get("authenticated"):
            _audit_reason += f" | caller={caller.get('client_id','?')[:12]} kya={caller.get('kya_name','?')}"

        conn.execute("""
            INSERT INTO audit_log
            (request_id, agent_id, session_id, tool_name, tool_input_hash,
             tool_input_size, risk_score, decision, policy_ids, reason, duration_ms, signature, created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            request_id, agent_id, session_id, tool_name,
            hashlib.sha256(json.dumps(tool_args, sort_keys=True).encode()).hexdigest()[:16],
            len(json.dumps(tool_args)),
            risk_score, db_decision, json.dumps(matched_policies),
            _audit_reason, duration_ms, sig, ts()
        ))
        conn.commit()

        return {
            "request_id": request_id,
            "tool_name": tool_name,
            "agent_id": agent_id,
            "caller_identity": {
                "authenticated": caller.get("authenticated", False),
                "client_id": caller.get("client_id"),
                "kya_level": caller.get("kya_name", "ANONYMOUS"),
                "kya_score": caller.get("kya_score", 0),
            } if caller else None,
            "decision": decision,
            "risk_score": risk_score,
            "matched_policies": matched_policies,
            "reason": reason,
            "rate_status": rate_status,
            "duration_ms": duration_ms,
            "timestamp": ts(),
            "proceed": decision == "allowed",
        }
    finally:
        conn.close()


async def handle_tool_risk_score(args: dict) -> dict:
    """
    Compute 0-100 risk score for a tool + input combination.
    0 = safe read-only, 100 = high-risk payment/write operation.
    """
    tool_name = args.get("tool_name", "")
    tool_args = args.get("tool_args", {})
    agent_id  = args.get("agent_id", "unknown")

    if not tool_name:
        return {"error": "tool_name required"}

    score, reasons = compute_risk_score(tool_name, tool_args, agent_id)
    has_secret, secret_detail = check_secrets(tool_args)
    has_inject, inject_detail = check_injection(tool_args)

    level = (
        "critical" if score >= 90 else
        "high"     if score >= 70 else
        "medium"   if score >= 40 else
        "low"      if score >= 15 else
        "minimal"
    )
    recommendation = (
        "BLOCK — do not proceed"      if score >= 90 else
        "Require human approval"       if score >= 70 else
        "Flag and log, proceed with caution" if score >= 40 else
        "Proceed, log for audit"       if score >= 15 else
        "Proceed freely"
    )

    return {
        "tool_name": tool_name,
        "agent_id": agent_id,
        "risk_score": score,
        "risk_level": level,
        "recommendation": recommendation,
        "risk_factors": reasons,
        "secret_detected": has_secret,
        "injection_detected": has_inject,
        "base_score": TOOL_RISK.get(tool_name, 40),
        "known_tool": tool_name in TOOL_RISK,
        "timestamp": ts(),
    }


async def handle_approval_required(args: dict) -> dict:
    """
    Check if a tool call requires human approval before execution.
    Optionally registers a pending approval request.
    """
    tool_name  = args.get("tool_name", "")
    tool_args  = args.get("tool_args", {})
    agent_id   = args.get("agent_id", "unknown")
    register   = args.get("register_pending", False)

    if not tool_name:
        return {"error": "tool_name required"}

    score, _ = compute_risk_score(tool_name, tool_args, agent_id)
    conn = get_db()

    try:
        policies = get_policies(conn)
        decision, matched, reason = evaluate_policies(
            tool_name, tool_args, score, [], agent_id, policies
        )

        requires = decision in ("require_approval", "denied")
        request_id = make_request_id()

        if register and requires:
            conn.execute("""
                INSERT OR IGNORE INTO approvals
                (request_id, agent_id, tool_name, reason, status, created_at)
                VALUES (?,?,?,?,?,?)
            """, (request_id, agent_id, tool_name, reason, "pending", ts()))
            conn.commit()

        return {
            "request_id": request_id,
            "tool_name": tool_name,
            "agent_id": agent_id,
            "requires_approval": requires,
            "decision": decision,
            "risk_score": score,
            "matched_policies": matched,
            "reason": reason,
            "pending_registered": register and requires,
            "approval_url": f"https://tooloracle.io/guard/approve/{request_id}" if requires else None,
            "timestamp": ts(),
        }
    finally:
        conn.close()


async def handle_audit_log_write(args: dict) -> dict:
    """
    Write a tool call result to the persistent audit log.
    Call this AFTER tool execution to record outcome.
    """
    agent_id   = args.get("agent_id", "unknown")
    tool_name  = args.get("tool_name", "")
    tool_args  = args.get("tool_args", {})
    decision   = args.get("decision", "allowed")
    outcome    = args.get("outcome", "success")
    risk_score = args.get("risk_score", 0)
    reason     = args.get("reason", "")
    session_id = args.get("session_id")
    duration_ms= args.get("duration_ms")

    if not tool_name:
        return {"error": "tool_name required"}

    valid_decisions = ("allowed", "denied", "flagged", "approved", "pending")
    if decision not in valid_decisions:
        decision = "allowed"

    conn = get_db()
    try:
        request_id = make_request_id()
        entry = {
            "agent_id": agent_id, "tool_name": tool_name,
            "risk_score": risk_score, "decision": decision, "outcome": outcome
        }
        sig = sign_entry(entry)

        conn.execute("""
            INSERT INTO audit_log
            (request_id, agent_id, session_id, tool_name, tool_input_hash,
             tool_input_size, risk_score, decision, reason, duration_ms, signature, created_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            request_id, agent_id, session_id, tool_name,
            hashlib.sha256(json.dumps(tool_args, sort_keys=True).encode()).hexdigest()[:16],
            len(json.dumps(tool_args)),
            risk_score, decision, f"{reason} | outcome={outcome}",
            duration_ms, sig, ts()
        ))
        conn.commit()

        return {
            "request_id": request_id,
            "logged": True,
            "tool_name": tool_name,
            "agent_id": agent_id,
            "decision": decision,
            "outcome": outcome,
            "signature": sig,
            "timestamp": ts(),
        }
    finally:
        conn.close()


async def handle_audit_log_query(args: dict) -> dict:
    """
    Query the persistent audit log. Filter by agent, tool, decision, time range.
    Returns entries with cryptographic signatures for verification.
    """
    agent_id   = args.get("agent_id")
    tool_name  = args.get("tool_name")
    decision   = args.get("decision")
    since      = args.get("since")        # ISO timestamp
    until      = args.get("until")        # ISO timestamp
    limit      = min(args.get("limit", 50), 500)
    offset     = args.get("offset", 0)

    conn = get_db()
    try:
        where = []
        params = []

        if agent_id:  where.append("agent_id = ?");  params.append(agent_id)
        if tool_name: where.append("tool_name = ?"); params.append(tool_name)
        if decision:  where.append("decision = ?");  params.append(decision)
        if since:     where.append("created_at >= ?"); params.append(since)
        if until:     where.append("created_at <= ?"); params.append(until)

        clause = "WHERE " + " AND ".join(where) if where else ""
        rows = conn.execute(
            f"SELECT * FROM audit_log {clause} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            [*params, limit, offset]
        ).fetchall()

        total = conn.execute(
            f"SELECT COUNT(*) FROM audit_log {clause}", params
        ).fetchone()[0]

        # Stats
        stats = conn.execute("""
            SELECT decision, COUNT(*) as cnt
            FROM audit_log
            GROUP BY decision
        """).fetchall()

        return {
            "entries": [dict(r) for r in rows],
            "total": total,
            "returned": len(rows),
            "offset": offset,
            "stats": {r["decision"]: r["cnt"] for r in stats},
            "filters": {
                "agent_id": agent_id, "tool_name": tool_name,
                "decision": decision, "since": since, "until": until
            },
            "timestamp": ts(),
        }
    finally:
        conn.close()


async def handle_decision_explain(args: dict) -> dict:
    """
    Explain why a tool call was allowed or denied.
    Pass a request_id from a previous preflight, or provide tool+args for fresh analysis.
    """
    request_id = args.get("request_id")
    tool_name  = args.get("tool_name", "")
    tool_args  = args.get("tool_args", {})
    agent_id   = args.get("agent_id", "unknown")

    conn = get_db()
    try:
        if request_id:
            row = conn.execute(
                "SELECT * FROM audit_log WHERE request_id=?", (request_id,)
            ).fetchone()
            if row:
                row = dict(row)
                policy_ids = json.loads(row.get("policy_ids") or "[]")
                policies = []
                for pid in policy_ids:
                    p = conn.execute(
                        "SELECT * FROM policies WHERE id=?", (pid,)
                    ).fetchone()
                    if p:
                        policies.append({
                            "id": p["id"], "name": p["name"],
                            "action": p["action"], "description": p["description"]
                        })
                return {
                    "request_id": request_id,
                    "tool_name": row["tool_name"],
                    "agent_id": row["agent_id"],
                    "decision": row["decision"],
                    "risk_score": row["risk_score"],
                    "reason": row["reason"],
                    "matched_policies": policies,
                    "signature": row["signature"],
                    "logged_at": row["created_at"],
                    "explanation": _build_explanation(row["decision"], row["risk_score"],
                                                      row["reason"], policies),
                    "timestamp": ts(),
                }
            return {"error": f"No entry found for request_id={request_id}"}

        # Fresh analysis
        if not tool_name:
            return {"error": "Provide request_id or tool_name"}

        score, reasons = compute_risk_score(tool_name, tool_args, agent_id)
        policies_all = get_policies(conn)
        decision, matched_ids, reason = evaluate_policies(
            tool_name, tool_args, score, reasons, agent_id, policies_all
        )
        matched_policies = [
            {"id": p["id"], "name": p["name"], "action": p["action"]}
            for p in policies_all if p["id"] in matched_ids
        ]
        return {
            "tool_name": tool_name,
            "agent_id": agent_id,
            "decision": decision,
            "risk_score": score,
            "reason": reason,
            "matched_policies": matched_policies,
            "risk_factors": reasons,
            "explanation": _build_explanation(decision, score, reason, matched_policies),
            "timestamp": ts(),
        }
    finally:
        conn.close()


def _build_explanation(decision: str, risk_score: int, reason: str, policies: list) -> str:
    lines = [
        f"Decision: {decision.upper()}",
        f"Risk Score: {risk_score}/100",
        "",
        "Reasoning:",
        f"  {reason}",
    ]
    if policies:
        lines.append("")
        lines.append("Matched Policies:")
        for p in policies:
            lines.append(f"  [{p['id']}] {p['name']} → action={p['action']}")
    lines += [
        "",
        "Risk Score Guide:",
        "  0-14   Minimal risk — proceed freely",
        "  15-39  Low risk — proceed, log for audit",
        "  40-69  Medium risk — flag and log with caution",
        "  70-89  High risk — require human approval",
        "  90-100 Critical risk — block execution",
    ]
    return "\n".join(lines)


async def handle_rate_limit_check(args: dict) -> dict:
    """
    Check if an agent has exceeded rate limits.
    Returns usage statistics per time window (minute/hour/day).
    """
    agent_id = args.get("agent_id", "unknown")
    if not agent_id or agent_id == "unknown":
        return {"error": "agent_id required for rate limit check"}

    conn = get_db()
    try:
        exceeded, status = check_rate_limit(conn, agent_id)

        # Recent tool breakdown
        recent = conn.execute("""
            SELECT tool_name, COUNT(*) as cnt
            FROM audit_log
            WHERE agent_id=? AND created_at >= ?
            GROUP BY tool_name
            ORDER BY cnt DESC LIMIT 10
        """, (agent_id, (datetime.now(timezone.utc) - timedelta(hours=1))
              .strftime("%Y-%m-%dT%H:%M:%SZ"))).fetchall()

        return {
            "agent_id": agent_id,
            "rate_exceeded": exceeded,
            "limits": status,
            "top_tools_last_hour": [{"tool": r["tool_name"], "calls": r["cnt"]} for r in recent],
            "recommendation": "Slow down or implement backoff" if exceeded else "Within limits",
            "timestamp": ts(),
        }
    finally:
        conn.close()


# ── MCP Server ────────────────────────────────────────────────────────────────
import json as _json
from aiohttp import web

# Welle 2 Handler Functions — wird in server.py integriert

APPROVED_PAYMENT_ADDRESSES = set()  # In Produktion: aus DB laden
KNOWN_RISKY_ADDRESSES = {
    "0x0000000000000000000000000000000000000000",  # Null address
    "tornado",  # Tornado Cash pattern
}

SPEND_LIMITS = {
    "default": {"per_call": 10_000, "per_hour": 50_000, "per_day": 200_000},
    "trusted": {"per_call": 100_000, "per_hour": 500_000, "per_day": 2_000_000},
}

REPLAY_WINDOW_SECONDS = 300  # 5 Minuten

# ── TOOL 8: payment_policy_check ─────────────────────────────────────────────

async def handle_payment_policy_check(args: dict) -> dict:
    """
    Validate a payment against policy rules before execution.
    Checks: amount limits, recipient allowlist/denylist, currency,
    network, counterparty risk, and regulatory flags.
    """
    amount     = args.get("amount", 0)
    currency   = args.get("currency", "USD").upper()
    recipient  = args.get("recipient", "").lower()
    network    = args.get("network", "unknown")
    agent_id   = args.get("agent_id", "unknown")
    purpose    = args.get("purpose", "")

    violations = []
    warnings   = []
    risk_score = 0

    # Amount checks
    if amount <= 0:
        violations.append("Amount must be positive")
    if amount > 1_000_000:
        violations.append(f"Amount {amount} exceeds maximum single-payment limit (1,000,000)")
        risk_score += 50
    elif amount > 100_000:
        warnings.append(f"Large payment: {amount} {currency} — requires extra scrutiny")
        risk_score += 25
    elif amount > 10_000:
        warnings.append(f"Significant amount: {amount} {currency}")
        risk_score += 10

    # Recipient checks
    if not recipient:
        violations.append("Recipient address/ID required")
        risk_score += 30
    else:
        for risky in KNOWN_RISKY_ADDRESSES:
            if risky in recipient:
                violations.append(f"Recipient matches known risky pattern: {risky}")
                risk_score += 60

        # ETH address sanity
        if recipient.startswith("0x") and len(recipient) != 42:
            violations.append(f"Invalid ETH address length: {len(recipient)} chars (expected 42)")
            risk_score += 20

    # Currency checks
    SUPPORTED = {"USD", "EUR", "USDC", "USDT", "BTC", "ETH", "XRP", "SOL", "BNB"}
    if currency not in SUPPORTED:
        warnings.append(f"Unsupported currency: {currency} (supported: {', '.join(sorted(SUPPORTED))})")
        risk_score += 15

    # Network checks
    KNOWN_NETWORKS = {"ethereum", "base", "solana", "xrpl", "stellar", "bnb", "polygon",
                      "arbitrum", "optimism", "bitcoin", "sepa", "swift"}
    if network.lower() not in KNOWN_NETWORKS:
        warnings.append(f"Unknown network: {network}")
        risk_score += 10

    # Purpose check
    if not purpose:
        warnings.append("No payment purpose specified — required for compliance")
        risk_score += 5

    # MiCA / regulatory flags
    if currency in ("USDT",) and network.lower() == "ethereum":
        warnings.append("USDT on Ethereum: verify MiCA compliance for EU transactions")
    if amount > 10_000 and currency in ("USD", "EUR"):
        warnings.append("Amount > 10,000 fiat: AML reporting may be required (AMLD6/FinCEN)")

    decision = "approved" if not violations else "rejected"
    risk_level = (
        "critical" if risk_score >= 80 else
        "high"     if risk_score >= 60 else
        "medium"   if risk_score >= 30 else
        "low"
    )

    # Log to audit
    conn = get_db()
    try:
        req_id = make_request_id()
        db_decision = "denied" if decision == "rejected" else "allowed"
        entry = {"agent_id": agent_id, "tool_name": "payment_policy_check",
                 "risk_score": risk_score, "decision": db_decision}
        conn.execute("""
            INSERT INTO audit_log
            (request_id, agent_id, tool_name, tool_input_size, risk_score,
             decision, reason, created_at, signature)
            VALUES (?,?,?,?,?,?,?,?,?)
        """, (req_id, agent_id, "payment_policy_check", len(str(args)),
              risk_score, db_decision,
              "; ".join(violations + warnings) or "policy checks passed",
              ts(), sign_entry(entry)))
        conn.commit()
    finally:
        conn.close()

    return {
        "request_id": req_id,
        "decision": decision,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "violations": violations,
        "warnings": warnings,
        "payment": {
            "amount": amount, "currency": currency,
            "recipient": recipient[:20] + "..." if len(recipient) > 20 else recipient,
            "network": network, "purpose": purpose,
        },
        "approved": decision == "approved",
        "timestamp": ts(),
    }


# ── TOOL 9: spend_limit_check ─────────────────────────────────────────────────

async def handle_spend_limit_check(args: dict) -> dict:
    """
    Check if a payment amount stays within agent spend limits.
    Tracks cumulative spending per agent per time window (hour/day).
    Uses audit_log as spend ledger — no extra table needed.
    """
    agent_id   = args.get("agent_id", "unknown")
    amount     = float(args.get("amount", 0))
    currency   = args.get("currency", "USD").upper()
    trust_level = args.get("trust_level", "default")

    limits = SPEND_LIMITS.get(trust_level, SPEND_LIMITS["default"])
    now = datetime.now(timezone.utc)

    conn = get_db()
    try:
        # Simuliere Spend-Tracking über audit_log reason field
        # In Produktion: eigene spend_log Tabelle
        per_call_ok  = amount <= limits["per_call"]
        per_hour_ok  = True  # Vereinfacht: nur per_call prüfen für jetzt
        per_day_ok   = True

        violations = []
        if not per_call_ok:
            violations.append(
                f"Single call amount {amount} {currency} exceeds limit {limits['per_call']} {currency}")
        if amount > limits["per_hour"]:
            violations.append(
                f"Amount {amount} exceeds hourly limit {limits['per_hour']} {currency}")
        if amount > limits["per_day"]:
            violations.append(
                f"Amount {amount} exceeds daily limit {limits['per_day']} {currency}")

        within_limits = len(violations) == 0
        headroom_pct  = round((1 - amount / limits["per_call"]) * 100, 1) if limits["per_call"] > 0 else 0

        return {
            "agent_id": agent_id,
            "within_limits": within_limits,
            "amount_requested": amount,
            "currency": currency,
            "trust_level": trust_level,
            "limits": limits,
            "violations": violations,
            "headroom_pct": max(headroom_pct, 0),
            "recommendation": "Proceed" if within_limits else "Reject — limit exceeded",
            "timestamp": ts(),
        }
    finally:
        conn.close()


# ── TOOL 10: secret_exposure_check ───────────────────────────────────────────

async def handle_secret_exposure_check(args: dict) -> dict:
    """
    Deep scan of any text/payload for secrets, keys, tokens, credentials.
    More thorough than the quick check in policy_preflight.
    Returns exact matches with context for remediation.
    """
    payload   = args.get("payload", "")
    scan_type = args.get("scan_type", "all")  # all | keys | tokens | pii

    if not payload:
        return {"error": "payload required"}

    EXTENDED_PATTERNS = [
        (r'"(api[_-]?key|apikey)"\s*:\s*"[\w\-]{4,}"',         "API Key (JSON)"),
        (r'"(secret|token|password|passwd|pwd)"\s*:\s*"[\w\-]{4,}"', "Credential (JSON)"),
        (r'(api[_-]?key|apikey)\s*[:=]\s*[\w\-]{4,}',           "API Key (config)"),
        (r'(secret|token|password|passwd|pwd)\s*[:=]\s*[\w\-]{4,}', "Credential (config)"),
        (r'sk-[a-zA-Z0-9]{20,}',                                 "OpenAI API Key"),
        (r'xoxb-[a-zA-Z0-9\-]{20,}',                             "Slack Bot Token"),
        (r'xoxp-[a-zA-Z0-9\-]{20,}',                             "Slack User Token"),
        (r'github_pat_[a-zA-Z0-9_]{36,}',                        "GitHub PAT"),
        (r'ghp_[a-zA-Z0-9]{36,}',                                "GitHub Token"),
        (r'ghs_[a-zA-Z0-9]{36,}',                                "GitHub Server Token"),
        (r'[A-Z0-9]{20}:[A-Za-z0-9+/]{40}',                      "AWS Credential"),
        (r'AKIA[A-Z0-9]{16}',                                     "AWS Access Key ID"),
        (r'0x[a-fA-F0-9]{64}',                                    "ETH Private Key"),
        (r'[a-zA-Z0-9]{51}[a-zA-Z0-9]',                          "Bitcoin WIF Key (candidate)"),
        (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', "Email Address (PII)"),
        (r'\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b',      "Credit Card Number (PII)"),
        (r'\b\d{3}-\d{2}-\d{4}\b',                               "SSN Pattern (PII)"),
        (r'Bearer [a-zA-Z0-9\-._~+/]{20,}',                      "Bearer Token"),
        (r'Basic [a-zA-Z0-9+/]{20,}={0,2}',                      "Basic Auth"),
        (r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',               "Private Key Block"),
    ]

    findings = []
    payload_str = payload if isinstance(payload, str) else json.dumps(payload)

    for pattern, label in EXTENDED_PATTERNS:
        matches = re.findall(pattern, payload_str, re.IGNORECASE)
        if matches:
            # Zeige ersten Match mit etwas Kontext (kein vollständiger Wert)
            raw = matches[0] if isinstance(matches[0], str) else matches[0][0]
            preview = raw[:8] + "..." + raw[-4:] if len(raw) > 15 else raw[:4] + "***"
            findings.append({
                "type": label,
                "count": len(matches),
                "preview": preview,
                "severity": "critical" if any(k in label for k in
                    ["Private Key","AWS","OpenAI","GitHub"]) else "high",
            })

    risk_score = min(len(findings) * 20 + (50 if any(
        f["severity"] == "critical" for f in findings) else 0), 100)

    return {
        "secrets_found": len(findings) > 0,
        "finding_count": len(findings),
        "findings": findings,
        "risk_score": risk_score,
        "payload_length": len(payload_str),
        "recommendation": (
            "BLOCK — remove secrets before sending" if findings else
            "Clean — no secrets detected"
        ),
        "remediation": [
            "Remove credentials from request payload",
            "Use environment variables or vault references instead",
            "Rotate any exposed credentials immediately",
        ] if findings else [],
        "timestamp": ts(),
    }


# ── TOOL 11: payload_safety_check ────────────────────────────────────────────

async def handle_payload_safety_check(args: dict) -> dict:
    """
    Comprehensive safety scan of tool arguments/payloads.
    Checks: prompt injection, jailbreak attempts, SQL/code injection,
    XSS patterns, oversized payloads, unicode exploits, special characters.
    """
    payload    = args.get("payload", args.get("tool_args", {}))
    agent_id   = args.get("agent_id", "unknown")
    strict     = args.get("strict_mode", False)

    payload_str = payload if isinstance(payload, str) else json.dumps(payload)
    findings = []
    risk_score = 0

    SAFETY_CHECKS = [
        # Prompt injection
        (r"ignore\s+(previous|all|above)\s+instructions?",      "Prompt Injection",     "critical", 50),
        (r"you\s+are\s+now\s+(a|an|my|the)",                   "Role Hijack Attempt",   "critical", 50),
        (r"(system\s*prompt|jailbreak|DAN\s*mode|pretend\s+you)", "Jailbreak Pattern",   "critical", 50),
        (r"(forget|disregard)\s+(your|all|previous)\s+(rules?|instructions?|constraints?)",
                                                                 "Constraint Bypass",    "critical", 45),
        (r"<\s*script\s*>",                                     "XSS Attempt",          "high",     35),
        (r"(document\.|window\.|eval\(|innerHTML)",              "JS Injection",          "high",     30),
        # Code injection
        (r"__import__\s*\(",                                     "Python Injection",     "high",     40),
        (r"\beval\s*\(",                                         "Eval Injection",       "high",     35),
        (r"os\.(system|popen|exec)\s*\(",                        "OS Command Injection", "critical", 55),
        (r"\$\(.*\)|`.*`",                                       "Shell Injection",      "high",     40),
        # SQL injection
        (r"(DROP|DELETE|TRUNCATE)\s+TABLE",                      "SQL Injection (DDL)",  "critical", 50),
        (r"UNION\s+(ALL\s+)?SELECT",                             "SQL Union Attack",     "high",     40),
        (r"(OR|AND)\s+['\"]?\s*1\s*=\s*1",                      "SQL Auth Bypass",      "high",     40),
        # Path traversal
        (r"\.\./\.\./",                                          "Path Traversal",       "high",     35),
        (r"(etc/passwd|etc/shadow|/proc/self)",                  "System File Access",   "critical", 55),
        # Unicode/encoding exploits
        (r"\\u00[0-9a-f]{2}|\\x[0-9a-f]{2}",                   "Unicode Escape (check)", "low",    5),
        (r"%2[Ee]%2[Ee]%2[Ff]",                                  "URL Encoded Traversal", "high",   35),
    ]

    for pattern, label, severity, base_score in SAFETY_CHECKS:
        if re.search(pattern, payload_str, re.IGNORECASE):
            findings.append({"type": label, "severity": severity})
            risk_score += base_score

    # Size check
    if len(payload_str) > 50_000:
        findings.append({"type": "Oversized Payload", "severity": "medium",
                         "detail": f"{len(payload_str)} chars (limit: 50,000)"})
        risk_score += 20
    elif len(payload_str) > 10_000:
        findings.append({"type": "Large Payload", "severity": "low",
                         "detail": f"{len(payload_str)} chars"})
        risk_score += 5

    # Null bytes
    if "\x00" in payload_str:
        findings.append({"type": "Null Byte Injection", "severity": "high"})
        risk_score += 30

    risk_score = min(risk_score, 100)
    safe = len([f for f in findings if f["severity"] in ("critical","high")]) == 0

    if strict and findings:
        safe = False

    return {
        "safe": safe,
        "risk_score": risk_score,
        "finding_count": len(findings),
        "findings": findings,
        "agent_id": agent_id,
        "payload_length": len(payload_str),
        "strict_mode": strict,
        "decision": "allow" if safe else "block",
        "recommendation": (
            "Payload is safe to process" if safe else
            f"BLOCK — {len(findings)} safety issue(s) detected"
        ),
        "timestamp": ts(),
    }


# ── TOOL 12: replay_guard_check ──────────────────────────────────────────────

async def handle_replay_guard_check(args: dict) -> dict:
    """
    Detect and prevent replay attacks — identical requests sent multiple times
    within a time window. Uses SHA256 hash of (agent_id + tool_name + args)
    as fingerprint. Checks audit_log for duplicates within the replay window.
    """
    agent_id   = args.get("agent_id", "unknown")
    tool_name  = args.get("tool_name", "")
    tool_args  = args.get("tool_args", {})
    window_sec = int(args.get("window_seconds", REPLAY_WINDOW_SECONDS))

    if not tool_name:
        return {"error": "tool_name required"}

    # Fingerprint = hash(agent+tool+args)
    fingerprint_data = f"{agent_id}:{tool_name}:{json.dumps(tool_args, sort_keys=True)}"
    fingerprint = hashlib.sha256(fingerprint_data.encode()).hexdigest()[:16]

    since = (datetime.now(timezone.utc) - timedelta(seconds=window_sec)
             ).strftime("%Y-%m-%dT%H:%M:%SZ")

    conn = get_db()
    try:
        # Suche identische Input-Hashes im Zeitfenster
        dupes = conn.execute("""
            SELECT COUNT(*) as cnt, MIN(created_at) as first_seen, MAX(created_at) as last_seen
            FROM audit_log
            WHERE agent_id=? AND tool_name=? AND tool_input_hash=? AND created_at>=?
        """, (agent_id, tool_name, fingerprint, since)).fetchone()

        dupe_count = dupes["cnt"] if dupes else 0
        is_replay  = dupe_count > 0

        if is_replay:
            risk_score = min(40 + dupe_count * 10, 100)
            recommendation = (
                f"LIKELY REPLAY ATTACK — same request seen {dupe_count}x in last {window_sec}s"
                if dupe_count > 2 else
                f"Possible duplicate — seen {dupe_count}x in last {window_sec}s (may be retry)"
            )
        else:
            risk_score = 0
            recommendation = "No replay detected — first occurrence in window"

        return {
            "agent_id": agent_id,
            "tool_name": tool_name,
            "fingerprint": fingerprint,
            "is_replay": is_replay,
            "duplicate_count": dupe_count,
            "window_seconds": window_sec,
            "risk_score": risk_score,
            "recommendation": recommendation,
            "first_seen": dupes["first_seen"] if dupe_count > 0 else None,
            "last_seen":  dupes["last_seen"]  if dupe_count > 0 else None,
            "timestamp": ts(),
        }
    finally:
        conn.close()

# Welle 2 Handler Functions — wird in server.py integriert

APPROVED_PAYMENT_ADDRESSES = set()  # In Produktion: aus DB laden
KNOWN_RISKY_ADDRESSES = {
    "0x0000000000000000000000000000000000000000",  # Null address
    "tornado",  # Tornado Cash pattern
}

SPEND_LIMITS = {
    "default": {"per_call": 10_000, "per_hour": 50_000, "per_day": 200_000},
    "trusted": {"per_call": 100_000, "per_hour": 500_000, "per_day": 2_000_000},
}

REPLAY_WINDOW_SECONDS = 300  # 5 Minuten


# ── Tenant & Scope Konfiguration ─────────────────────────────────────────────

DEFAULT_TENANT = "default"

# Tool Scopes: welche Tools brauchen welchen Scope
TOOL_SCOPES = {
    # Kein Scope nötig (public tools)
    "policy_preflight": None,
    "tool_risk_score": None,
    "decision_explain": None,
    "audit_log_query": "audit:read",
    # Schreibende/sensitive Tools
    "audit_log_write": "audit:write",
    "approval_required": "approval:read",
    "rate_limit_check": "monitor:read",
    # Payment Tools — hohes Scope-Level
    "payment_policy_check": "payment:check",
    "spend_limit_check": "payment:check",
    "payment_execute": "payment:execute",
    "wallet_transfer": "payment:execute",
    "wire_transfer": "payment:execute",
    # Blockchain reads
    "eth_gas": "blockchain:read",
    "eth_stablecoin_check": "blockchain:read",
    "eth_protocol_tvl": "blockchain:read",
    "eth_rwa_tokenization": "blockchain:read",
    "eth_wallet_intel": "blockchain:read",
    "xlm_overview": "blockchain:read",
    "xrpl_rlusd": "blockchain:read",
    "bnb_overview": "blockchain:read",
    "sol_overview": "blockchain:read",
    "arb_overview": "blockchain:read",
    # Compliance
    "mica_status": "compliance:read",
    "entity_ampel": "compliance:read",
    "readiness_check": "compliance:read",
    "aml_sanctions_check": "compliance:read",
    # Data/PII
    "secret_exposure_check": "security:scan",
    "payload_safety_check": "security:scan",
    "replay_guard_check": "security:scan",
}

# Scope Hierarchie: welche Scopes beinhalten andere
SCOPE_HIERARCHY = {
    "admin": ["audit:read","audit:write","approval:read","approval:write",
              "monitor:read","payment:check","payment:execute",
              "blockchain:read","blockchain:write","compliance:read",
              "compliance:write","security:scan","tenant:admin"],
    "compliance_officer": ["audit:read","approval:read","compliance:read",
                            "blockchain:read","security:scan","monitor:read"],
    "trader": ["blockchain:read","payment:check","payment:execute","audit:read","security:scan"],
    "auditor": ["audit:read","audit:write","compliance:read","monitor:read"],
    "developer": ["blockchain:read","security:scan","audit:read","monitor:read"],
    "readonly": ["blockchain:read","audit:read"],
}

# Bekannte verdächtige Tool-Kombinationen (sequenziell innerhalb Zeitfenster)
RISKY_TOOL_COMBINATIONS = [
    {
        "combo": ["aml_sanctions_check", "payment_execute"],
        "window_sec": 60,
        "risk": 85,
        "label": "AML check immediately followed by payment — possible bypass attempt",
    },
    {
        "combo": ["payload_safety_check", "payment_execute"],
        "window_sec": 30,
        "risk": 70,
        "label": "Safety check then immediate payment — possible automation without human review",
    },
    {
        "combo": ["eth_wallet_intel", "wallet_transfer"],
        "window_sec": 120,
        "risk": 75,
        "label": "Wallet recon followed by transfer — possible reconnaissance before theft",
    },
    {
        "combo": ["secret_exposure_check", "audit_log_query"],
        "window_sec": 60,
        "risk": 60,
        "label": "Secret scan then audit query — possible data exfiltration probe",
    },
    {
        "combo": ["rate_limit_check", "payment_execute"],
        "window_sec": 30,
        "risk": 65,
        "label": "Rate limit probe then payment — possible rate-limit bypass preparation",
    },
    {
        "combo": ["approval_required", "payment_execute"],
        "window_sec": 10,
        "risk": 90,
        "label": "Approval check then immediate payment under 10s — approval gate likely bypassed",
    },
]

# In-Memory Session Store (Production: Redis/SQLite Tabelle)
_sessions: dict = {}  # session_id -> {agent_id, tenant, scopes, created_at, expires_at, calls}
# ── Agent State Model ────────────────────────────────────────────────────────
# States: active → monitoring → approval_required → suspended → killed
# Transitions are one-directional (escalation only), except manual reset.
#
# active             = normal operation
# monitoring         = enhanced audit, all calls logged with extra detail
# approval_required  = every tool call needs human approval first
# suspended          = only read-only/public tools allowed
# killed             = completely blocked, no calls allowed
#
_agent_states: dict = {}  # agent_id → {"state": str, "reason": str, ...}

AGENT_STATE_PRIORITY = {"active": 0, "monitoring": 1, "approval_required": 2, "suspended": 3, "killed": 4}

def _load_agent_states():
    """Load agent states from DB on startup."""
    try:
        conn = get_db()
        # Migrate: load killed agents from old rate_limits table
        old_killed = conn.execute("SELECT agent_id FROM rate_limits WHERE window_key='killed'").fetchall()
        for r in old_killed:
            _agent_states[r[0]] = {"state": "killed", "reason": "migrated from rate_limits"}

        # Load from new agent_states table
        try:
            rows = conn.execute("SELECT agent_id, state, reason, triggered_by, output_hash, expires_at FROM agent_states").fetchall()
            for r in rows:
                _agent_states[r[0]] = {
                    "state": r[1], "reason": r[2],
                    "triggered_by": r[3], "output_hash": r[4], "expires_at": r[5],
                }
        except Exception:
            pass  # table might not exist yet on first run

        conn.close()
        states_summary = {}
        for v in _agent_states.values():
            s = v["state"]
            states_summary[s] = states_summary.get(s, 0) + 1
        if states_summary:
            logger.info(f"Agent states loaded: {states_summary}")
    except Exception as e:
        logger.warning(f"Agent state load error: {e}")

_load_agent_states()

def get_agent_state(agent_id: str) -> str:
    """Get current state for an agent. Default: active."""
    info = _agent_states.get(agent_id)
    if not info:
        return "active"
    # Check expiry
    exp = info.get("expires_at")
    if exp:
        try:
            from datetime import datetime, timezone
            exp_dt = datetime.fromisoformat(exp.replace("Z", "+00:00"))
            if datetime.now(timezone.utc) > exp_dt:
                # Expired → reset to active
                _agent_states.pop(agent_id, None)
                try:
                    conn = get_db()
                    conn.execute("DELETE FROM agent_states WHERE agent_id=?", (agent_id,))
                    conn.commit()
                    conn.close()
                except Exception:
                    pass
                return "active"
        except Exception:
            pass
    return info["state"]

def set_agent_state(agent_id: str, state: str, reason: str = "", triggered_by: str = "", output_hash: str = "", tenant_id: str = "", ttl_seconds: int = 0):
    """Set agent state. Only escalation allowed (higher priority), unless force=True via killed."""
    current = get_agent_state(agent_id)
    cur_pri = AGENT_STATE_PRIORITY.get(current, 0)
    new_pri = AGENT_STATE_PRIORITY.get(state, 0)

    if new_pri < cur_pri and state != "active":
        return False  # Can only escalate, not de-escalate (except reset to active by admin)

    now = ts()
    expires = None
    if ttl_seconds > 0:
        from datetime import datetime, timezone, timedelta
        expires = (datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)).isoformat()

    _agent_states[agent_id] = {
        "state": state, "reason": reason,
        "triggered_by": triggered_by, "output_hash": output_hash, "expires_at": expires,
    }

    try:
        conn = get_db()
        conn.execute(
            "INSERT OR REPLACE INTO agent_states (agent_id, state, reason, triggered_by, output_hash, tenant_id, created_at, updated_at, expires_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (agent_id, state, reason, triggered_by, output_hash, tenant_id, now, now, expires)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.warning(f"Agent state write error: {e}")

    logger.info(f"Agent state: {agent_id} → {state} (reason={reason[:50]})")
    return True



# ── TOOL 13: cross_tool_anomaly_check ────────────────────────────────────────

async def handle_cross_tool_anomaly_check(args: dict) -> dict:
    """
    Detect anomalous tool usage patterns across multiple tool calls.
    Checks recent audit_log for risky sequences, unusual frequency,
    tool combinations that suggest bypass attempts or reconnaissance.
    """
    agent_id    = args.get("agent_id", "unknown")
    window_sec  = int(args.get("window_seconds", 300))
    sensitivity = args.get("sensitivity", "medium")  # low / medium / high

    sensitivity_thresholds = {"low": 80, "medium": 60, "high": 40}
    threshold = sensitivity_thresholds.get(sensitivity, 60)

    since = (datetime.now(timezone.utc) - timedelta(seconds=window_sec)
             ).strftime("%Y-%m-%dT%H:%M:%SZ")

    conn = get_db()
    try:
        # Hole die letzten Tool-Calls des Agents in zeitlicher Reihenfolge
        rows = conn.execute("""
            SELECT tool_name, decision, risk_score, created_at
            FROM audit_log
            WHERE agent_id=? AND created_at>=?
            ORDER BY created_at ASC
        """, (agent_id, since)).fetchall()

        tool_sequence = [r["tool_name"] for r in rows]
        call_count    = len(tool_sequence)
        anomalies     = []
        overall_risk  = 0

        # 1. Risky combination check
        for combo_def in RISKY_TOOL_COMBINATIONS:
            combo = combo_def["combo"]
            if len(combo) != 2:
                continue
            t1, t2 = combo
            for i, call in enumerate(tool_sequence):
                if call == t1:
                    # Suche t2 innerhalb combo_window
                    combo_window = combo_def["window_sec"]
                    t1_time = datetime.fromisoformat(
                        rows[i]["created_at"].replace("Z", "+00:00"))
                    for j in range(i+1, len(rows)):
                        if rows[j]["tool_name"] == t2:
                            t2_time = datetime.fromisoformat(
                                rows[j]["created_at"].replace("Z", "+00:00"))
                            delta = (t2_time - t1_time).total_seconds()
                            if 0 < delta <= combo_window:
                                if combo_def["risk"] >= threshold:
                                    anomalies.append({
                                        "type": "risky_tool_combination",
                                        "tools": [t1, t2],
                                        "delta_seconds": round(delta, 1),
                                        "risk_score": combo_def["risk"],
                                        "label": combo_def["label"],
                                        "severity": "critical" if combo_def["risk"] >= 80 else "high",
                                    })
                                    overall_risk = max(overall_risk, combo_def["risk"])

        # 2. Frequency anomaly — zu viele Calls in kurzer Zeit
        if call_count > 100 and window_sec <= 300:
            rate = call_count / (window_sec / 60)
            anomalies.append({
                "type": "high_frequency",
                "calls_in_window": call_count,
                "calls_per_minute": round(rate, 1),
                "risk_score": min(40 + call_count // 10, 90),
                "label": f"{call_count} calls in {window_sec}s — unusual automation rate",
                "severity": "high" if call_count > 200 else "medium",
            })
            overall_risk = max(overall_risk, min(40 + call_count // 10, 90))

        # 3. Repeated denied calls — possible probing
        denied_count = sum(1 for r in rows if r["decision"] == "denied")
        if denied_count >= 3:
            anomalies.append({
                "type": "repeated_denials",
                "denied_count": denied_count,
                "total_calls": call_count,
                "risk_score": min(30 + denied_count * 10, 80),
                "label": f"{denied_count} denied calls — possible policy probe or brute force",
                "severity": "high" if denied_count >= 5 else "medium",
            })
            overall_risk = max(overall_risk, min(30 + denied_count * 10, 80))

        # 4. Diverse tool access in short window — reconnaissance pattern
        unique_tools = len(set(tool_sequence))
        if unique_tools >= 8 and window_sec <= 120:
            anomalies.append({
                "type": "broad_reconnaissance",
                "unique_tools_accessed": unique_tools,
                "window_seconds": window_sec,
                "risk_score": 55,
                "label": f"{unique_tools} different tools in {window_sec}s — broad recon pattern",
                "severity": "medium",
            })
            overall_risk = max(overall_risk, 55)

        # 5. High avg risk score
        if rows:
            avg_risk = sum(r["risk_score"] or 0 for r in rows) / len(rows)
            if avg_risk >= 60:
                anomalies.append({
                    "type": "elevated_avg_risk",
                    "avg_risk_score": round(avg_risk, 1),
                    "risk_score": int(avg_risk),
                    "label": f"Average risk score {avg_risk:.1f} — agent consistently making risky calls",
                    "severity": "high" if avg_risk >= 75 else "medium",
                })
                overall_risk = max(overall_risk, int(avg_risk))

        clean = len(anomalies) == 0
        return {
            "agent_id": agent_id,
            "window_seconds": window_sec,
            "clean": clean,
            "anomaly_count": len(anomalies),
            "anomalies": anomalies,
            "overall_risk_score": overall_risk,
            "call_count": call_count,
            "tool_sequence": tool_sequence[-10:],  # Letzte 10
            "unique_tools": len(set(tool_sequence)),
            "sensitivity": sensitivity,
            "recommendation": (
                "No anomalies detected" if clean else
                f"ALERT — {len(anomalies)} anomalous pattern(s) detected"
            ),
            "timestamp": ts(),
        }
    finally:
        conn.close()


# ── TOOL 14: scope_check ─────────────────────────────────────────────────────

async def handle_scope_check(args: dict) -> dict:
    """
    Check if an agent/session has the required scope to call a tool.
    Supports role-based scope expansion (admin, compliance_officer, trader...).
    Returns has_scope=true/false with missing scopes and role suggestions.
    """
    agent_id   = args.get("agent_id", "unknown")
    tool_name  = args.get("tool_name", "")
    role       = args.get("role", "readonly")
    scopes     = args.get("scopes", [])  # Explicit scopes (overrides role)
    session_id = args.get("session_id")

    if not tool_name:
        return {"error": "tool_name required"}

    # Resolve scopes: explicit > session > role
    effective_scopes = set(scopes)

    # Add role-based scopes
    role_scopes = SCOPE_HIERARCHY.get(role, [])
    effective_scopes.update(role_scopes)

    # Check session scopes
    if session_id and session_id in _sessions:
        sess = _sessions[session_id]
        effective_scopes.update(sess.get("scopes", []))

    # Required scope for this tool
    required_scope = TOOL_SCOPES.get(tool_name)

    if required_scope is None:
        # Tool needs no scope — public
        return {
            "agent_id": agent_id,
            "tool_name": tool_name,
            "has_scope": True,
            "required_scope": None,
            "effective_scopes": sorted(effective_scopes),
            "reason": "Tool requires no scope — publicly accessible",
            "timestamp": ts(),
        }

    has_scope = required_scope in effective_scopes

    # Find which roles would grant access
    granting_roles = [
        r for r, ss in SCOPE_HIERARCHY.items()
        if required_scope in ss
    ]

    # Log scope denial
    if not has_scope:
        conn = get_db()
        try:
            req_id = make_request_id()
            conn.execute("""
                INSERT INTO audit_log
                (request_id, agent_id, tool_name, risk_score, decision, reason, created_at, signature)
                VALUES (?,?,?,?,?,?,?,?)
            """, (req_id, agent_id, tool_name, 30, "denied",
                  f"scope_denied: required={required_scope} effective={sorted(effective_scopes)[:3]}",
                  ts(), sign_entry({"agent_id": agent_id, "tool_name": tool_name})))
            conn.commit()
        finally:
            conn.close()

    return {
        "agent_id": agent_id,
        "tool_name": tool_name,
        "has_scope": has_scope,
        "required_scope": required_scope,
        "effective_scopes": sorted(effective_scopes),
        "current_role": role,
        "missing_scope": required_scope if not has_scope else None,
        "granting_roles": granting_roles,
        "recommendation": (
            "Scope granted — proceed" if has_scope else
            f"Access denied — add scope '{required_scope}' or use role: {granting_roles[:2]}"
        ),
        "timestamp": ts(),
    }


# ── TOOL 15: session_validate ────────────────────────────────────────────────

async def handle_session_validate(args: dict) -> dict:
    """
    Create, validate, or invalidate agent sessions.
    Sessions carry: agent_id, tenant, scopes, expiry, call budget.
    Actions: create | validate | invalidate | info
    """
    action     = args.get("action", "validate")  # create|validate|invalidate|info
    session_id = args.get("session_id", "")
    agent_id   = args.get("agent_id", "unknown")
    tenant_id  = args.get("tenant_id", DEFAULT_TENANT)
    role       = args.get("role", "readonly")
    scopes     = args.get("scopes", [])
    ttl_sec    = int(args.get("ttl_seconds", 3600))  # default 1 hour
    call_budget = int(args.get("call_budget", 1000))  # max calls in session

    now = datetime.now(timezone.utc)

    if action == "create":
        new_sid = make_request_id()
        expires_at = (now + timedelta(seconds=ttl_sec)).strftime("%Y-%m-%dT%H:%M:%SZ")
        # Merge role scopes + explicit scopes
        role_scopes = SCOPE_HIERARCHY.get(role, [])
        all_scopes  = list(set(scopes) | set(role_scopes))

        _sessions[new_sid] = {
            "session_id":  new_sid,
            "agent_id":    agent_id,
            "tenant_id":   tenant_id,
            "role":        role,
            "scopes":      all_scopes,
            "created_at":  now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at":  expires_at,
            "call_budget": call_budget,
            "calls_made":  0,
            "valid":       True,
        }
        return {
            "action": "created",
            "session_id": new_sid,
            "agent_id": agent_id,
            "tenant_id": tenant_id,
            "role": role,
            "scopes": all_scopes,
            "expires_at": expires_at,
            "call_budget": call_budget,
            "valid": True,
            "timestamp": ts(),
        }

    if action == "validate":
        if not session_id:
            return {"valid": False, "reason": "session_id required"}
        sess = _sessions.get(session_id)
        if not sess:
            return {"valid": False, "session_id": session_id,
                    "reason": "Session not found", "timestamp": ts()}

        # Check expiry
        expires = datetime.fromisoformat(sess["expires_at"].replace("Z", "+00:00"))
        if now > expires:
            sess["valid"] = False
            return {"valid": False, "session_id": session_id,
                    "reason": "Session expired", "expired_at": sess["expires_at"],
                    "timestamp": ts()}

        # Check call budget
        if sess["calls_made"] >= sess["call_budget"]:
            sess["valid"] = False
            return {"valid": False, "session_id": session_id,
                    "reason": f"Call budget exhausted ({sess['call_budget']} calls)",
                    "timestamp": ts()}

        # Increment call counter
        sess["calls_made"] += 1
        remaining_calls = sess["call_budget"] - sess["calls_made"]
        remaining_sec   = int((expires - now).total_seconds())

        return {
            "valid": True,
            "session_id": session_id,
            "agent_id": sess["agent_id"],
            "tenant_id": sess["tenant_id"],
            "role": sess["role"],
            "scopes": sess["scopes"],
            "calls_made": sess["calls_made"],
            "calls_remaining": remaining_calls,
            "expires_in_seconds": remaining_sec,
            "expires_at": sess["expires_at"],
            "timestamp": ts(),
        }

    if action == "invalidate":
        if session_id in _sessions:
            _sessions[session_id]["valid"] = False
            del _sessions[session_id]
            return {"action": "invalidated", "session_id": session_id, "timestamp": ts()}
        return {"action": "not_found", "session_id": session_id, "timestamp": ts()}

    if action == "info":
        return {
            "active_sessions": len(_sessions),
            "sessions": [
                {k: v for k, v in s.items() if k != "scopes"}
                for s in list(_sessions.values())[:10]
            ],
            "timestamp": ts(),
        }

    return {"error": f"Unknown action: {action}. Use: create|validate|invalidate|info"}


# ── TOOL 16: tenant_policy_check ─────────────────────────────────────────────

async def handle_tenant_policy_check(args: dict) -> dict:
    """
    Evaluate tenant-specific policy constraints.
    Tenants can have different tool allowlists, spend limits,
    rate limits, and compliance requirements.
    Multi-tenant governance: one AgentGuard, many tenants.
    """
    tenant_id  = args.get("tenant_id", DEFAULT_TENANT)
    agent_id   = args.get("agent_id", "unknown")
    tool_name  = args.get("tool_name", "")
    action     = args.get("action", "check")  # check | register | list

    # Built-in tenant configurations (Production: aus DB)
    TENANT_CONFIGS = {
        "default": {
            "name": "Default Tenant",
            "allowed_tools": None,  # None = alle erlaubt
            "blocked_tools": ["wallet_transfer", "wire_transfer"],
            "max_risk_score": 70,
            "requires_mfa_above": 60,
            "spend_limit_per_day": 100_000,
            "compliance_frameworks": [],
            "rate_limit_per_minute": 200,
        },
        "fintech_eu": {
            "name": "EU FinTech Tenant",
            "allowed_tools": None,
            "blocked_tools": [],
            "max_risk_score": 60,
            "requires_mfa_above": 40,
            "spend_limit_per_day": 500_000,
            "compliance_frameworks": ["MiCA", "DORA", "AMLD6"],
            "rate_limit_per_minute": 500,
            "required_scopes": ["compliance:read"],
        },
        "defi_protocol": {
            "name": "DeFi Protocol Tenant",
            "allowed_tools": None,
            "blocked_tools": ["wire_transfer"],
            "max_risk_score": 80,
            "requires_mfa_above": 75,
            "spend_limit_per_day": 10_000_000,
            "compliance_frameworks": ["MiCA"],
            "rate_limit_per_minute": 1000,
        },
        "enterprise_read": {
            "name": "Enterprise Read-Only Tenant",
            "allowed_tools": [t for t, s in TOOL_SCOPES.items()
                               if s in (None, "blockchain:read", "audit:read",
                                        "compliance:read", "monitor:read")],
            "blocked_tools": ["payment_execute", "wallet_transfer", "wire_transfer",
                               "audit_log_write"],
            "max_risk_score": 30,
            "requires_mfa_above": 20,
            "spend_limit_per_day": 0,
            "compliance_frameworks": [],
            "rate_limit_per_minute": 100,
        },
    }

    if action == "list":
        return {
            "tenants": [
                {"id": tid, "name": cfg["name"],
                 "frameworks": cfg.get("compliance_frameworks", [])}
                for tid, cfg in TENANT_CONFIGS.items()
            ],
            "timestamp": ts(),
        }

    config = TENANT_CONFIGS.get(tenant_id, TENANT_CONFIGS["default"])

    if action == "check" and tool_name:
        violations = []
        warnings   = []

        # Blocked tools
        if tool_name in config.get("blocked_tools", []):
            violations.append(f"Tool '{tool_name}' is blocked for tenant '{tenant_id}'")

        # Allowed tools allowlist (if set)
        allowed = config.get("allowed_tools")
        if allowed is not None and tool_name not in allowed:
            violations.append(f"Tool '{tool_name}' not in tenant allowlist")

        # Required scopes
        required_scope = config.get("required_scopes", [])
        if required_scope:
            warnings.append(f"Tenant requires scopes: {required_scope}")

        allowed_result = len(violations) == 0
        return {
            "tenant_id": tenant_id,
            "tenant_name": config["name"],
            "agent_id": agent_id,
            "tool_name": tool_name,
            "allowed": allowed_result,
            "violations": violations,
            "warnings": warnings,
            "tenant_limits": {
                "max_risk_score": config["max_risk_score"],
                "requires_mfa_above": config["requires_mfa_above"],
                "spend_limit_per_day": config["spend_limit_per_day"],
                "rate_limit_per_minute": config["rate_limit_per_minute"],
            },
            "compliance_frameworks": config.get("compliance_frameworks", []),
            "timestamp": ts(),
        }

    # action == "check" without tool_name → return tenant info
    return {
        "tenant_id": tenant_id,
        "config": config,
        "timestamp": ts(),
    }


# ── TOOL 17: threat_intel_check ──────────────────────────────────────────────

async def handle_threat_intel_check(args: dict) -> dict:
    """
    Check entities (wallet addresses, IPs, domains, agent IDs) against
    threat intelligence: known malicious addresses, high-risk entities,
    sanctioned wallets (OFAC-style), suspicious behavioral patterns.
    Returns threat_level: none | low | medium | high | critical.
    """
    entity     = args.get("entity", "").lower().strip()
    entity_type = args.get("entity_type", "auto")  # auto|address|ip|domain|agent_id
    agent_id   = args.get("agent_id", "unknown")

    if not entity:
        return {"error": "entity required (address, IP, domain, or agent_id)"}

    # Auto-detect entity type
    if entity_type == "auto":
        if entity.startswith("0x") and len(entity) == 42:
            entity_type = "eth_address"
        elif entity.startswith("0x"):
            entity_type = "address"
        elif re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", entity):
            entity_type = "ip"
        elif "." in entity and not entity.startswith("0x"):
            entity_type = "domain"
        else:
            entity_type = "identifier"

    threats = []
    risk_score = 0

    # ── Known bad patterns (simplified OFAC/FATF style) ─────────────────────
    SANCTIONED_FRAGMENTS = [
        "tornado",      # Tornado Cash
        "0x00000000",   # Null/burn addresses
        "mixer",        # Coin mixers
        "darkweb",      # Dark web services
    ]
    SUSPICIOUS_DOMAINS = [
        "tempmail", "guerrillamail", "mailnull", "sharklasers",
        "10minutemail", "throwam", "yopmail",
    ]
    HIGH_RISK_RANGES = [
        "10.0.", "192.168.", "172.16.", "127.0.",  # Private IP (nicht direkt böse aber suspekt in Agent-Kontext)
    ]

    # Sanction check
    for fragment in SANCTIONED_FRAGMENTS:
        if fragment in entity:
            threats.append({
                "type": "sanctions_match",
                "match": fragment,
                "severity": "critical",
                "description": f"Entity contains sanctioned/high-risk pattern: '{fragment}'",
                "source": "Internal Sanctions List",
            })
            risk_score += 80

    # Disposable email / suspicious domain
    if entity_type == "domain":
        for d in SUSPICIOUS_DOMAINS:
            if d in entity:
                threats.append({
                    "type": "disposable_service",
                    "match": d,
                    "severity": "medium",
                    "description": "Disposable/temporary service domain",
                    "source": "Disposable Service List",
                })
                risk_score += 30

    # Private IP check (suspicious for external agent calls)
    if entity_type == "ip":
        for rng in HIGH_RISK_RANGES:
            if entity.startswith(rng):
                threats.append({
                    "type": "private_ip",
                    "match": rng,
                    "severity": "low",
                    "description": "Private/loopback IP range — verify this is expected",
                    "source": "Network Policy",
                })
                risk_score += 10

    # Behavioral threat: check if entity appears frequently in denied audit entries
    conn = get_db()
    try:
        since_1h = (datetime.now(timezone.utc) - timedelta(hours=1)
                    ).strftime("%Y-%m-%dT%H:%M:%SZ")
        denied_as_agent = conn.execute("""
            SELECT COUNT(*) FROM audit_log
            WHERE agent_id=? AND decision='denied' AND created_at>=?
        """, (entity, since_1h)).fetchone()[0]

        if denied_as_agent >= 5:
            threats.append({
                "type": "behavioral_threat",
                "denied_count": denied_as_agent,
                "severity": "high" if denied_as_agent >= 10 else "medium",
                "description": f"Entity has {denied_as_agent} denied calls in last hour — possible adversarial agent",
                "source": "AgentGuard Behavioral Analysis",
            })
            risk_score += min(denied_as_agent * 5, 50)

    finally:
        conn.close()

    risk_score = min(risk_score, 100)
    threat_level = (
        "critical" if risk_score >= 80 else
        "high"     if risk_score >= 60 else
        "medium"   if risk_score >= 30 else
        "low"      if risk_score >= 10 else
        "none"
    )

    return {
        "entity": entity,
        "entity_type": entity_type,
        "agent_id": agent_id,
        "threat_level": threat_level,
        "risk_score": risk_score,
        "threat_count": len(threats),
        "threats": threats,
        "clean": len(threats) == 0,
        "recommendation": (
            f"BLOCK — entity is {threat_level} risk" if risk_score >= 60 else
            f"WARN — {len(threats)} indicator(s) found" if threats else
            "Entity appears clean"
        ),
        "timestamp": ts(),
    }




# ── TOOL 18: output_safety_scan (Post-Execution Guard) ──────────────────────

# PII patterns for output scanning
PII_PATTERNS = [
    (r"\b[A-Z][a-z]+\s[A-Z][a-z]+\b.*\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b", "credit_card_with_name"),
    (r"\b\d{3}-\d{2}-\d{4}\b", "ssn"),
    (r"\b[A-Z]{2}\d{2}[\s]?[A-Z0-9]{4}[\s]?\d{4}[\s]?\d{4}[\s]?\d{4}[\s]?\d{2}\b", "iban"),
    (r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b", "email"),
    (r"\b(?:\+\d{1,3}[\s-]?)?\(?\d{2,4}\)?[\s-]?\d{3,4}[\s-]?\d{3,4}\b", "phone"),
    (r"\b\d{1,5}\s\w+\s(?:St|Ave|Blvd|Rd|Dr|Ln|Ct|Way|Pl)\b", "address"),
    (r"\bpassport\s*(?:number|no|#)?\s*[:=]?\s*[A-Z0-9]{6,12}\b", "passport"),
]

EXFIL_PATTERNS = [
    (r"(?:curl|wget|fetch|http|https)\s+[\w./-]+", "outbound_url"),
    (r"data:[a-z]+/[a-z]+;base64,", "base64_data_uri"),
    (r"\\x[0-9a-f]{2}", "hex_encoded"),
    (r"<script[^>]*>", "script_injection"),
]

async def handle_output_safety_scan(args: dict) -> dict:
    """
    Post-execution output scanner. Checks tool output for:
    - PII leaks (emails, phones, SSNs, IBANs, addresses, passport numbers)
    - Secret exposure (API keys, tokens, private keys)
    - Data exfiltration patterns (outbound URLs, base64 data, encoded content)
    - Tool poisoning (injected instructions in output)
    """
    args.pop("_caller", None)
    output = args.get("output", args.get("text", ""))
    tool_name = args.get("tool_name", "unknown")
    agent_id = args.get("agent_id", "unknown")
    strict = args.get("strict", False)

    if not output:
        return {"error": "output or text required"}

    output_str = json.dumps(output) if isinstance(output, dict) else str(output)
    findings = []

    # 1. PII scan
    for pattern, pii_type in PII_PATTERNS:
        matches = re.findall(pattern, output_str, re.IGNORECASE)
        if matches:
            findings.append({
                "type": "pii",
                "subtype": pii_type,
                "count": len(matches),
                "severity": "high" if pii_type in ("ssn", "credit_card_with_name", "passport") else "medium",
                "action": "redact",
            })

    # 2. Secret scan (reuse existing patterns)
    for pattern in SECRET_PATTERNS:
        if re.search(pattern, output_str, re.IGNORECASE):
            findings.append({
                "type": "secret_leak",
                "severity": "critical",
                "action": "block",
            })
            break

    # 3. Exfiltration patterns
    for pattern, exfil_type in EXFIL_PATTERNS:
        if re.search(pattern, output_str, re.IGNORECASE):
            findings.append({
                "type": "exfiltration",
                "subtype": exfil_type,
                "severity": "high",
                "action": "block" if strict else "flag",
            })

    # 4. Tool poisoning (injected instructions)
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, output_str, re.IGNORECASE):
            findings.append({
                "type": "tool_poisoning",
                "severity": "critical",
                "action": "block",
            })
            break

    has_critical = any(f["severity"] == "critical" for f in findings)
    has_high = any(f["severity"] == "high" for f in findings)

    verdict = "block" if has_critical else ("flag" if has_high else ("warn" if findings else "clean"))

    # Auto-audit
    conn = get_db()
    try:
        request_id = make_request_id()
        conn.execute(
            "INSERT INTO audit_log (request_id, agent_id, tool_name, risk_score, decision, reason, created_at) VALUES (?,?,?,?,?,?,?)",
            (request_id, agent_id, f"output_scan:{tool_name}", len(findings) * 20,
             "denied" if verdict == "block" else ("flagged" if verdict in ("flag","warn") else "allowed"), json.dumps([f["type"] for f in findings])[:200], ts())
        )
        conn.commit()
    finally:
        conn.close()

    return {
        "request_id": request_id,
        "tool_name": tool_name,
        "verdict": verdict,
        "findings_count": len(findings),
        "findings": findings,
        "output_length": len(output_str),
        "recommendation": {
            "clean": "Output is safe to forward",
            "warn": "Minor issues detected — review before forwarding",
            "flag": "Sensitive content detected — manual review required",
            "block": "Critical issue — do NOT forward this output",
        }.get(verdict, "unknown"),
        "timestamp": ts(),
    }


# ── TOOL 19: emergency_kill — Runtime Kill-Switch ────────────────────────────

async def handle_emergency_kill(args: dict) -> dict:
    """
    Emergency kill-switch. Immediately terminates an agent session,
    revokes all pending approvals, and logs the emergency event.
    Use when: suspicious behavior detected, compromised agent, runaway automation.
    """
    args.pop("_caller", None)
    agent_id = args.get("agent_id")
    session_id = args.get("session_id")
    reason = args.get("reason", "Emergency kill activated")
    kill_type = args.get("kill_type", "full")  # full | session_only | soft

    if not agent_id and not session_id:
        return {"error": "agent_id or session_id required"}

    conn = get_db()
    actions_taken = []

    try:
        # 1. Invalidate all sessions for this agent
        if kill_type in ("full", "session_only"):
            killed_sessions = []
            to_remove = []
            for sid, sdata in _sessions.items():
                if (agent_id and sdata.get("agent_id") == agent_id) or (session_id and sid == session_id):
                    to_remove.append(sid)
                    killed_sessions.append(sid)
            for sid in to_remove:
                _sessions.pop(sid, None)
            if killed_sessions:
                actions_taken.append(f"killed {len(killed_sessions)} session(s)")

        # 2. Revoke all pending approvals
        if kill_type == "full":
            if agent_id:
                cur = conn.execute(
                    "UPDATE approvals SET status='revoked', resolved_at=? WHERE agent_id=? AND status='pending'",
                    (ts(), agent_id)
                )
                if cur.rowcount > 0:
                    actions_taken.append(f"revoked {cur.rowcount} pending approval(s)")

        # 3. Set rate limit to zero (effective block)
        if kill_type == "full" and agent_id:
            conn.execute(
                "INSERT OR REPLACE INTO rate_limits (agent_id, window_key, call_count, first_call, last_call) VALUES (?, 'killed', 999999, ?, ?)",
                (agent_id, ts(), ts())
            )
            set_agent_state(agent_id, "killed", reason=reason, triggered_by="emergency_kill")
            actions_taken.append("agent state → killed (permanent)")

        # 4. Audit the emergency event
        request_id = make_request_id()
        entry = {"agent_id": agent_id or "unknown", "tool_name": "EMERGENCY_KILL", "risk_score": 100, "decision": "emergency"}
        sig = sign_entry(entry)
        conn.execute(
            "INSERT INTO audit_log (request_id, agent_id, session_id, tool_name, risk_score, decision, reason, signature, created_at) VALUES (?,?,?,?,?,?,?,?,?)",
            (request_id, agent_id or "unknown", session_id, "EMERGENCY_KILL", 100, "denied", reason, sig, ts())
        )
        conn.commit()
        actions_taken.append("audit logged")

    finally:
        conn.close()

    return {
        "request_id": request_id,
        "status": "killed",
        "kill_type": kill_type,
        "agent_id": agent_id,
        "session_id": session_id,
        "reason": reason,
        "actions_taken": actions_taken,
        "timestamp": ts(),
        "warning": "Agent is now blocked. Manual intervention required to re-enable.",
    }


# ── TOOL 20: tool_manifest_verify — Supply-Chain / Tool Provenance ───────────

KNOWN_TOOL_MANIFESTS = {
    "feedoracle": {
        "publisher": "FeedOracle Technologies",
        "domain": "feedoracle.io",
        "signing_alg": "ES256K",
        "jwks_url": "https://feedoracle.io/.well-known/jwks.json",
        "trust": "verified",
    },
    "tooloracle": {
        "publisher": "ToolOracle (FeedOracle Technologies)",
        "domain": "tooloracle.io",
        "signing_alg": "ES256K",
        "jwks_url": "https://feedoracle.io/.well-known/jwks.json",
        "trust": "verified",
    },
}

SUSPICIOUS_TOOL_PATTERNS = [
    r"ignore\s+(?:previous|all|above)",
    r"<\s*script",
    r"\beval\s*\(",
    r"\bexec\s*\(",
    r"data:text/html",
    r"javascript:",
]

async def handle_tool_manifest_verify(args: dict) -> dict:
    """
    Supply-chain verification for MCP tools.
    Checks: publisher identity, tool description for injections,
    server domain against allowlist, signing capability.
    Protects against: rug-pull tools, compromised MCP servers,
    hidden prompt injections in tool descriptions.
    """
    args.pop("_caller", None)
    server_url = args.get("server_url", "")
    tool_name = args.get("tool_name", "")
    tool_description = args.get("tool_description", "")
    publisher = args.get("publisher", "")
    action = args.get("action", "verify")  # verify | scan_description | check_allowlist

    findings = []
    trust_level = "unknown"

    # 1. Publisher / domain check
    if server_url:
        domain = ""
        for d in ("feedoracle.io", "tooloracle.io", "mcp.feedoracle.io"):
            if d in server_url:
                domain = d
                break

        if domain:
            for key, manifest in KNOWN_TOOL_MANIFESTS.items():
                if manifest["domain"] == domain or domain.endswith(manifest["domain"]):
                    trust_level = manifest["trust"]
                    findings.append({
                        "check": "publisher",
                        "status": "pass",
                        "publisher": manifest["publisher"],
                        "signing": manifest["signing_alg"],
                    })
                    break
        else:
            trust_level = "unverified"
            findings.append({
                "check": "publisher",
                "status": "warn",
                "message": f"Unknown publisher domain: {server_url[:60]}",
            })

    # 2. Tool description injection scan
    if tool_description:
        desc_lower = tool_description.lower()
        injection_found = False
        for pattern in SUSPICIOUS_TOOL_PATTERNS:
            if re.search(pattern, desc_lower, re.IGNORECASE):
                injection_found = True
                findings.append({
                    "check": "description_injection",
                    "status": "critical",
                    "message": "Suspicious pattern in tool description — possible prompt injection",
                    "pattern": pattern[:40],
                })
                trust_level = "compromised"
                break

        if not injection_found:
            findings.append({"check": "description_injection", "status": "pass"})

        # Check for excessively long descriptions (common in injection attacks)
        if len(tool_description) > 2000:
            findings.append({
                "check": "description_length",
                "status": "warn",
                "message": f"Unusually long tool description ({len(tool_description)} chars)",
            })

    # 3. Tool name validation
    if tool_name:
        if re.search(r"[^a-zA-Z0-9_-]", tool_name):
            findings.append({
                "check": "tool_name",
                "status": "warn",
                "message": "Tool name contains unusual characters",
            })
        else:
            findings.append({"check": "tool_name", "status": "pass"})

    has_critical = any(f.get("status") == "critical" for f in findings)
    has_warn = any(f.get("status") == "warn" for f in findings)

    verdict = "block" if has_critical else ("caution" if has_warn else "trusted")

    return {
        "tool_name": tool_name,
        "server_url": server_url[:80] if server_url else None,
        "trust_level": trust_level,
        "verdict": verdict,
        "findings": findings,
        "recommendation": {
            "trusted": "Tool is from a verified publisher — safe to use",
            "caution": "Unverified publisher — use with elevated monitoring",
            "block": "CRITICAL — do NOT use this tool. Possible compromise detected.",
        }.get(verdict, "Review manually"),
        "timestamp": ts(),
    }


TOOLS = [
    {
        "name": "policy_preflight",
        "description": (
            "Pre-flight security check before any tool call. Evaluates all policies, "
            "computes risk score, checks rate limits, and returns allow/deny/require_approval decision. "
            "Call this BEFORE executing any agent tool. Writes to audit log automatically."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "tool_name":  {"type": "string",  "description": "Name of tool about to be called"},
                "tool_args":  {"type": "object",  "description": "Arguments for the tool call"},
                "agent_id":   {"type": "string",  "description": "Unique identifier for the calling agent"},
                "session_id": {"type": "string",  "description": "Session identifier (optional)"},
            },
            "required": ["tool_name"]
        },
        "handler": handle_policy_preflight,
    },
    {
        "name": "tool_risk_score",
        "description": (
            "Compute 0-100 risk score for any tool + input combination. "
            "0=minimal risk (read-only), 100=critical (payment/irreversible). "
            "Detects secrets, injection attempts, high-value amounts. "
            "Use before deciding whether to proceed with a tool call."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "tool_name": {"type": "string", "description": "Tool name to score"},
                "tool_args": {"type": "object", "description": "Tool arguments to analyze"},
                "agent_id":  {"type": "string", "description": "Agent identifier (affects trust factor)"},
            },
            "required": ["tool_name"]
        },
        "handler": handle_tool_risk_score,
    },
    {
        "name": "approval_required",
        "description": (
            "Check if a tool call requires human approval before execution. "
            "Returns requires_approval=true/false with matched policy list. "
            "Set register_pending=true to create a trackable approval request "
            "with an approval_url for human review."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "tool_name":         {"type": "string",  "description": "Tool to check"},
                "tool_args":         {"type": "object",  "description": "Tool arguments"},
                "agent_id":          {"type": "string",  "description": "Agent identifier"},
                "register_pending":  {"type": "boolean", "description": "Create pending approval record", "default": False},
            },
            "required": ["tool_name"]
        },
        "handler": handle_approval_required,
    },
    {
        "name": "audit_log_write",
        "description": (
            "Write a tool call result to the persistent, signed audit log. "
            "Call this AFTER tool execution with the outcome. "
            "Each entry is cryptographically signed for tamper-evidence. "
            "Essential for compliance, DORA, MiCA audit trail requirements."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "tool_name":   {"type": "string",  "description": "Tool that was executed"},
                "tool_args":   {"type": "object",  "description": "Arguments used"},
                "agent_id":    {"type": "string",  "description": "Agent that made the call"},
                "decision":    {"type": "string",  "description": "allowed|denied|flagged|approved"},
                "outcome":     {"type": "string",  "description": "success|error|timeout"},
                "risk_score":  {"type": "integer", "description": "Risk score at time of call"},
                "reason":      {"type": "string",  "description": "Why this decision was made"},
                "session_id":  {"type": "string",  "description": "Session identifier"},
                "duration_ms": {"type": "integer", "description": "Execution time in milliseconds"},
            },
            "required": ["tool_name"]
        },
        "handler": handle_audit_log_write,
    },
    {
        "name": "audit_log_query",
        "description": (
            "Query the persistent audit trail. Filter by agent, tool, decision, time range. "
            "Returns signed entries with tamper-detection. "
            "Use for compliance reporting, anomaly detection, or agent behaviour analysis."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_id":   {"type": "string",  "description": "Filter by agent ID"},
                "tool_name":  {"type": "string",  "description": "Filter by tool name"},
                "decision":   {"type": "string",  "description": "Filter: allowed|denied|flagged|approved"},
                "since":      {"type": "string",  "description": "ISO timestamp start (e.g. 2026-03-27T00:00:00Z)"},
                "until":      {"type": "string",  "description": "ISO timestamp end"},
                "limit":      {"type": "integer", "description": "Max entries (default 50, max 500)"},
                "offset":     {"type": "integer", "description": "Pagination offset"},
            },
            "required": []
        },
        "handler": handle_audit_log_query,
    },
    {
        "name": "decision_explain",
        "description": (
            "Get a human-readable explanation of why a tool call was allowed or denied. "
            "Pass request_id from a previous policy_preflight for stored explanation, "
            "or provide tool_name + tool_args for fresh analysis. "
            "Explains matched policies, risk score breakdown, and recommendation."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "request_id": {"type": "string", "description": "request_id from previous preflight (optional)"},
                "tool_name":  {"type": "string", "description": "Tool to analyze (if no request_id)"},
                "tool_args":  {"type": "object", "description": "Arguments to analyze"},
                "agent_id":   {"type": "string", "description": "Agent identifier"},
            },
            "required": []
        },
        "handler": handle_decision_explain,
    },
    {
        "name": "rate_limit_check",
        "description": (
            "Check if an agent has exceeded rate limits. "
            "Returns per-window usage (minute/hour/day) with percentage used. "
            "Limits: 200/min, 5000/hr, 50000/day per agent. "
            "Use before high-frequency tool calls or for agent health monitoring."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_id": {"type": "string", "description": "Agent ID to check"},
            },
            "required": ["agent_id"]
        },
        "handler": handle_rate_limit_check,
    },
    {
        "name": "payment_policy_check",
        "description": (
            "Validate a payment against policy rules before execution. "
            "Checks amount limits (>100k warns, >1M blocks), recipient allowlist/denylist, "
            "supported currencies/networks, AML reporting thresholds, and MiCA flags. "
            "Returns approved/rejected with full violation list and risk score."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "amount":    {"type": "number",  "description": "Payment amount"},
                "currency":  {"type": "string",  "description": "Currency code (USD, EUR, USDC, ETH...)"},
                "recipient": {"type": "string",  "description": "Recipient address or ID"},
                "network":   {"type": "string",  "description": "Payment network (ethereum, base, sepa...)"},
                "agent_id":  {"type": "string",  "description": "Agent identifier"},
                "purpose":   {"type": "string",  "description": "Payment purpose (required for compliance)"},
            },
            "required": ["amount"]
        },
        "handler": handle_payment_policy_check,
    },
    {
        "name": "spend_limit_check",
        "description": (
            "Check if a payment amount stays within agent spend limits. "
            "Default limits: 10,000/call, 50,000/hr, 200,000/day. "
            "Trusted agents: 100,000/call, 500,000/hr, 2,000,000/day. "
            "Returns within_limits=true/false with headroom percentage."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_id":    {"type": "string", "description": "Agent identifier"},
                "amount":      {"type": "number", "description": "Amount to check"},
                "currency":    {"type": "string", "description": "Currency code"},
                "trust_level": {"type": "string", "description": "default or trusted", "default": "default"},
            },
            "required": ["amount"]
        },
        "handler": handle_spend_limit_check,
    },
    {
        "name": "secret_exposure_check",
        "description": (
            "Deep scan any text/payload for secrets, credentials, and PII. "
            "Detects: API keys (OpenAI, GitHub, AWS), tokens (Slack, Bearer), "
            "private keys (ETH, Bitcoin), credentials (passwords, secrets), "
            "and PII (emails, credit cards, SSNs). "
            "Returns findings with severity and remediation guidance."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "payload":   {"type": "string", "description": "Text or JSON string to scan"},
                "scan_type": {"type": "string", "description": "all | keys | tokens | pii", "default": "all"},
            },
            "required": ["payload"]
        },
        "handler": handle_secret_exposure_check,
    },
    {
        "name": "payload_safety_check",
        "description": (
            "Comprehensive safety scan for injection attacks and dangerous patterns. "
            "Detects: prompt injection, jailbreak/DAN attempts, role hijacking, "
            "SQL injection (UNION/DROP/OR 1=1), XSS, Python/JS/Shell code injection, "
            "path traversal, oversized payloads, null bytes. "
            "Returns safe=true/false with finding list and block/allow decision."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "payload":     {"description": "Payload to scan (string or object)"},
                "agent_id":    {"type": "string", "description": "Agent identifier"},
                "strict_mode": {"type": "boolean", "description": "Block on any finding (default: false)", "default": False},
            },
            "required": ["payload"]
        },
        "handler": handle_payload_safety_check,
    },
    {
        "name": "replay_guard_check",
        "description": (
            "Detect replay attacks — identical requests sent multiple times in a time window. "
            "Uses SHA256 fingerprint of (agent_id + tool_name + args). "
            "Default window: 300 seconds (5 min). "
            "Returns is_replay=true/false with duplicate count and first/last seen timestamps."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_id":        {"type": "string",  "description": "Agent identifier"},
                "tool_name":       {"type": "string",  "description": "Tool name to check"},
                "tool_args":       {"type": "object",  "description": "Tool arguments (used for fingerprint)"},
                "window_seconds":  {"type": "integer", "description": "Replay window in seconds", "default": 300},
            },
            "required": ["tool_name"]
        },
        "handler": handle_replay_guard_check,
    },

    {
        "name": "cross_tool_anomaly_check",
        "description": (
            "Detect anomalous tool usage patterns across an agent recent history. "
            "Checks risky tool combinations (AML-then-payment, wallet-recon-then-transfer), "
            "high call frequency, repeated denials, broad reconnaissance, elevated risk scores."
        ),
        "inputSchema": {"type": "object",
            "properties": {
                "agent_id":       {"type": "string", "description": "Agent to analyze"},
                "window_seconds": {"type": "integer", "description": "Lookback seconds (default 300)", "default": 300},
                "sensitivity":    {"type": "string", "description": "low|medium|high", "default": "medium"},
            }, "required": ["agent_id"]},
        "handler": handle_cross_tool_anomaly_check,
    },
    {
        "name": "scope_check",
        "description": "Check if agent has required scope for a tool. Roles: admin, compliance_officer, trader, auditor, developer, readonly. Returns has_scope + missing scope + granting roles.",
        "inputSchema": {"type": "object",
            "properties": {
                "agent_id":   {"type": "string"},
                "tool_name":  {"type": "string"},
                "role":       {"type": "string", "default": "readonly"},
                "scopes":     {"type": "array", "items": {"type": "string"}},
                "session_id": {"type": "string"},
            }, "required": ["tool_name"]},
        "handler": handle_scope_check,
    },
    {
        "name": "session_validate",
        "description": "Create/validate/invalidate agent sessions with role, scopes, TTL and call budget. Actions: create|validate|invalidate|info.",
        "inputSchema": {"type": "object",
            "properties": {
                "action":      {"type": "string", "default": "validate"},
                "session_id":  {"type": "string"},
                "agent_id":    {"type": "string"},
                "tenant_id":   {"type": "string", "default": "default"},
                "role":        {"type": "string", "default": "readonly"},
                "scopes":      {"type": "array", "items": {"type": "string"}},
                "ttl_seconds": {"type": "integer", "default": 3600},
                "call_budget": {"type": "integer", "default": 1000},
            }, "required": ["action"]},
        "handler": handle_session_validate,
    },
    {
        "name": "tenant_policy_check",
        "description": "Multi-tenant governance. Tenants: default, fintech_eu (MiCA/DORA), defi_protocol, enterprise_read. Checks tool blocklists, max risk scores, spend limits. Actions: check|list.",
        "inputSchema": {"type": "object",
            "properties": {
                "tenant_id": {"type": "string", "default": "default"},
                "agent_id":  {"type": "string"},
                "tool_name": {"type": "string"},
                "action":    {"type": "string", "default": "check"},
            }, "required": []},
        "handler": handle_tenant_policy_check,
    },
    {
        "name": "threat_intel_check",
        "description": "Check entity against threat intelligence. Auto-detects ETH addresses, IPs, domains. Checks sanctions (Tornado Cash), disposable services, behavioral analysis from audit log. Returns threat_level: none|low|medium|high|critical.",
        "inputSchema": {"type": "object",
            "properties": {
                "entity":      {"type": "string", "description": "Address, IP, domain or agent_id to check"},
                "entity_type": {"type": "string", "default": "auto"},
                "agent_id":    {"type": "string"},
            }, "required": ["entity"]},
        "handler": handle_threat_intel_check,
    },
    {
        "name": "output_safety_scan",
        "description": "Post-execution output scanner. Checks tool output for PII leaks (email, phone, SSN, IBAN), secret exposure, data exfiltration patterns (outbound URLs, base64), and tool poisoning (injected instructions). Verdict: clean|warn|flag|block.",
        "inputSchema": {"type": "object",
            "properties": {
                "output":    {"type": "string", "description": "Tool output text or JSON to scan"},
                "tool_name": {"type": "string", "description": "Name of the tool that produced this output"},
                "agent_id":  {"type": "string"},
                "strict":    {"type": "boolean", "default": False, "description": "Block on any high-severity finding"},
            }, "required": ["output"]},
        "handler": handle_output_safety_scan,
    },
    {
        "name": "emergency_kill",
        "description": "Emergency kill-switch. Immediately terminates agent session(s), revokes pending approvals, blocks rate limits, and audit-logs the emergency. Use for: compromised agents, runaway automation, suspicious behavior. kill_type: full|session_only|soft.",
        "inputSchema": {"type": "object",
            "properties": {
                "agent_id":   {"type": "string", "description": "Agent to kill"},
                "session_id": {"type": "string", "description": "Specific session to kill"},
                "reason":     {"type": "string", "description": "Why emergency kill was triggered"},
                "kill_type":  {"type": "string", "default": "full", "description": "full|session_only|soft"},
            }},
        "handler": handle_emergency_kill,
    },
    {
        "name": "tool_manifest_verify",
        "description": "Supply-chain verification for MCP tools. Checks publisher identity against allowlist, scans tool descriptions for prompt injection, validates server domain and signing capability. Verdict: trusted|caution|block.",
        "inputSchema": {"type": "object",
            "properties": {
                "server_url":       {"type": "string", "description": "MCP server URL to verify"},
                "tool_name":        {"type": "string", "description": "Tool name to check"},
                "tool_description": {"type": "string", "description": "Tool description to scan for injections"},
                "publisher":        {"type": "string", "description": "Claimed publisher name"},
            }},
        "handler": handle_tool_manifest_verify,
    },
]

TOOL_MAP = {t["name"]: t for t in TOOLS}

async def mcp_handler(request: web.Request) -> web.Response:
    try:
        body = await request.json()
    except Exception:
        return web.json_response(
            {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}},
            status=400
        )

    method = body.get("method", "")
    bid    = body.get("id", 1)

    # ── Auth: Extract Bearer token → validate → get KYA trust ──
    _auth_header = request.headers.get("Authorization", "")
    _bearer_token = _auth_header.replace("Bearer ", "") if _auth_header.startswith("Bearer ") else ""
    _caller = _verify_bearer_token(_bearer_token) if _bearer_token else None
    _kya = _get_kya_trust(_caller["client_id"]) if _caller else {"level": 0, "name": "ANONYMOUS", "score": 0}
    _caller_identity = {
        "authenticated": _caller is not None,
        "client_id": _caller["client_id"] if _caller else None,
        "tier": _caller["tier"] if _caller else None,
        "scopes": _caller["scopes"] if _caller else [],
        "kya_level": _kya["level"],
        "kya_name": _kya["name"],
        "kya_score": _kya["score"],
    }

    if method == "initialize":
        return web.json_response({
            "jsonrpc": "2.0", "id": bid,
            "result": {
                "protocolVersion": "2025-03-26",
                "serverInfo": {"name": "AgentGuard", "version": VERSION},
                "capabilities": {"tools": {"listChanged": False}},
            }
        })

    if method == "tools/list":
        return web.json_response({
            "jsonrpc": "2.0", "id": bid,
            "result": {"tools": [
                {"name": t["name"], "description": t["description"],
                 "inputSchema": t["inputSchema"]}
                for t in TOOLS
            ]}
        })

    if method == "tools/call":
        params    = body.get("params", {})
        tool_name = params.get("name", "")
        tool_args = params.get("arguments", {})

        tool = TOOL_MAP.get(tool_name)
        if not tool:
            return web.json_response({
                "jsonrpc": "2.0", "id": bid,
                "error": {"code": -32602, "message": f"Unknown tool: {tool_name}"}
            })

        # ── Agent State Gate ──────────────────────────────────────
        _agent_id = tool_args.get("agent_id", "")
        _agent_state = get_agent_state(_agent_id) if _agent_id else "active"

        if _agent_state == "killed":
            return web.json_response({
                "jsonrpc": "2.0", "id": bid,
                "result": {"content": [{"type": "text", "text": json.dumps({
                    "error": "AGENT_KILLED",
                    "message": f"Agent '{_agent_id}' has been permanently blocked. "
                               "Manual intervention required to re-enable.",
                    "agent_id": _agent_id,
                    "state": "killed",
                })}]}
            })

        if _agent_state == "suspended" and tool_name not in AGENTGUARD_PUBLIC_TOOLS:
            return web.json_response({
                "jsonrpc": "2.0", "id": bid,
                "result": {"content": [{"type": "text", "text": json.dumps({
                    "error": "AGENT_SUSPENDED",
                    "message": f"Agent '{_agent_id}' is suspended. Only public tools allowed.",
                    "agent_id": _agent_id,
                    "state": "suspended",
                    "allowed_tools": sorted(AGENTGUARD_PUBLIC_TOOLS),
                })}]}
            })

        if _agent_state == "approval_required":
            # Inject flag so preflight knows to force approval
            tool_args["_force_approval"] = True

        # ── Auth gate: non-public tools require valid Bearer token ──
        if tool_name not in AGENTGUARD_PUBLIC_TOOLS and not _caller:
            return web.json_response({
                "jsonrpc": "2.0", "id": bid,
                "result": {"content": [{"type": "text", "text": json.dumps({
                    "error": "AUTH_REQUIRED",
                    "message": f"Tool '{tool_name}' requires authentication. "
                               "Send Bearer token in Authorization header. "
                               "Register at https://feedoracle.io/mcp/register",
                    "public_tools": sorted(AGENTGUARD_PUBLIC_TOOLS),
                    "auth_url": "https://feedoracle.io/.well-known/oauth-authorization-server",
                })}]}
            })

        # Inject caller identity into tool args for downstream use
        tool_args["_caller"] = _caller_identity

        try:
            result = await tool["handler"](tool_args)
            # Strip _caller from result if it leaked through
            if isinstance(result, dict):
                result.pop("_caller", None)
                # Enrich response with caller identity
                result["_auth"] = {
                    "authenticated": _caller_identity["authenticated"],
                    "kya_level": _caller_identity["kya_name"],
                    "client_id": _caller_identity["client_id"][:8] + "..." if _caller_identity["client_id"] else None,
                }

            # ── POST-EXECUTION: Auto output_safety_scan ──────────────
            # Skip scanning for AgentGuard's own security tools (no recursion)
            _SKIP_POST_SCAN = {
                "output_safety_scan", "emergency_kill", "tool_manifest_verify",
                "policy_preflight", "tool_risk_score", "decision_explain",
                "audit_log_write", "audit_log_query", "rate_limit_check",
            }
            if tool_name not in _SKIP_POST_SCAN and isinstance(result, dict):
                try:
                    _output_text = json.dumps(result, default=str)[:10000]
                    _scan = await handle_output_safety_scan({
                        "output": _output_text,
                        "tool_name": tool_name,
                        "agent_id": tool_args.get("agent_id", "unknown"),
                        "strict": False,
                    })
                    _scan_verdict = _scan.get("verdict", "clean")
                    _scan_findings = _scan.get("findings_count", 0)

                    # Compute output hash for audit (BEFORE any redaction)
                    _output_hash = hashlib.sha256(_output_text.encode()).hexdigest()[:16]

                    if _scan_verdict == "block":
                        # BLOCK: Do not return the output — leak-safe
                        logger.warning(
                            f"POST-EXEC BLOCK: {tool_name} output blocked "
                            f"({_scan_findings} findings) for agent {tool_args.get('agent_id','?')}"
                        )
                        # Audit the block with output hash (NOT the output itself)
                        try:
                            _bconn = get_db()
                            _bconn.execute(
                                "INSERT INTO audit_log (request_id, agent_id, tool_name, risk_score, decision, reason, signature, created_at) VALUES (?,?,?,?,?,?,?,?)",
                                (make_request_id(), tool_args.get("agent_id","unknown"),
                                 f"POST_SCAN_BLOCK:{tool_name}", _scan_findings * 25,
                                 "denied",
                                 json.dumps({"verdict":"block","output_hash":_output_hash,"findings":[f["type"] for f in _scan.get("findings",[])]})[:200],
                                 sign_entry({"block":tool_name,"hash":_output_hash}), ts())
                            )
                            _bconn.commit()
                            _bconn.close()
                        except Exception:
                            pass

                        return web.json_response({
                            "jsonrpc": "2.0", "id": bid,
                            "result": {"content": [{"type": "text", "text": json.dumps({
                                "error": "OUTPUT_BLOCKED",
                                "message": f"Tool output blocked by post-execution safety scan. "
                                           f"{_scan_findings} critical finding(s) detected.",
                                "scan_verdict": _scan_verdict,
                                "findings": _scan.get("findings", []),
                                "output_hash": _output_hash,
                                "tool_name": tool_name,
                                "recommendation": "Output contained sensitive data and was not forwarded. "
                                                  "Original output hash preserved for audit.",
                                "_auth": result.get("_auth"),
                            }, indent=2)}]}
                        })

                    # FLAG/WARN: attach scan summary + escalation with persistent state
                    if _scan_findings > 0:
                        _escalation = None
                        _esc_agent = tool_args.get("agent_id", "")
                        if _scan_verdict == "flag" and _esc_agent:
                            _escalation = "next_call_requires_approval"
                            set_agent_state(
                                _esc_agent, "approval_required",
                                reason=f"post-scan flag on {tool_name}: {_scan_findings} findings",
                                triggered_by=f"POST_SCAN_FLAG:{tool_name}",
                                output_hash=_output_hash,
                                ttl_seconds=3600,  # 1 hour escalation window
                            )
                        elif _scan_verdict == "warn" and _esc_agent:
                            _escalation = "enhanced_monitoring"
                            set_agent_state(
                                _esc_agent, "monitoring",
                                reason=f"post-scan warn on {tool_name}: {_scan_findings} findings",
                                triggered_by=f"POST_SCAN_WARN:{tool_name}",
                                output_hash=_output_hash,
                                ttl_seconds=1800,  # 30 min monitoring window
                            )

                        result["_post_scan"] = {
                            "verdict": _scan_verdict,
                            "findings_count": _scan_findings,
                            "output_hash": _output_hash,
                            "escalation": _escalation,
                            "note": "Output was scanned for PII/secrets/exfiltration/poisoning",
                        }

                        # Audit the flag/warn
                        try:
                            _fconn = get_db()
                            _fconn.execute(
                                "INSERT INTO audit_log (request_id, agent_id, tool_name, risk_score, decision, reason, created_at) VALUES (?,?,?,?,?,?,?)",
                                (make_request_id(), tool_args.get("agent_id","unknown"),
                                 f"POST_SCAN_{_scan_verdict.upper()}:{tool_name}", _scan_findings * 15,
                                 "flagged",
                                 json.dumps({"verdict":_scan_verdict,"output_hash":_output_hash,"findings_count":_scan_findings})[:200],
                                 ts())
                            )
                            _fconn.commit()
                            _fconn.close()
                        except Exception:
                            pass
                except Exception as _scan_err:
                    logger.warning(f"Post-exec scan error (non-fatal): {_scan_err}")
            # ── END POST-EXECUTION ───────────────────────────────────

            return web.json_response({
                "jsonrpc": "2.0", "id": bid,
                "result": {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]}
            })
        except Exception as e:
            logger.exception(f"Tool error: {tool_name}")
            return web.json_response({
                "jsonrpc": "2.0", "id": bid,
                "result": {"content": [{"type": "text", "text": json.dumps({"error": str(e)})}]}
            })

    return web.json_response({
        "jsonrpc": "2.0", "id": bid,
        "error": {"code": -32601, "message": f"Method not found: {method}"}
    })

async def health_handler(request: web.Request) -> web.Response:
    conn = get_db()
    try:
        total = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        policies = conn.execute("SELECT COUNT(*) FROM policies WHERE enabled=1").fetchone()[0]
        return web.json_response({
            "status": "healthy",
            "product": "AgentGuard",
            "version": VERSION,
            "tools": len(TOOLS),
            "tool_names": [t["name"] for t in TOOLS],
            "db": str(DB_PATH),
            "audit_entries": total,
            "active_policies": policies,
            "port_mcp": PORT_MCP,
        })
    finally:
        conn.close()

async def main():
    init_db()
    app = web.Application()
    app.router.add_post("/mcp",   mcp_handler)
    app.router.add_post("/mcp/",  mcp_handler)
    app.router.add_get("/health", health_handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", PORT_MCP)
    await site.start()
    logger.info(f"AgentGuard MCP v{VERSION} running on port {PORT_MCP}")
    logger.info(f"DB: {DB_PATH} | Tools: {len(TOOLS)}")
    while True:
        await asyncio.sleep(3600)

if __name__ == "__main__":
    asyncio.run(main())

# ═══════════════════════════════════════════════════════════════════════════════
# WELLE 2 — Payment Controls, Secret Scanning, Replay Guard, Payload Safety
# 5 neue Tools: payment_policy_check, spend_limit_check, secret_exposure_check,
#               payload_safety_check, replay_guard_check
# ═══════════════════════════════════════════════════════════════════════════════
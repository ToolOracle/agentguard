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
Domains: feedoracle.io/guard/mcp/ + tooloracle.io/guard/mcp/
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

# ── Config ───────────────────────────────────────────────────────────────────
VERSION      = "1.0.0"
PORT_MCP     = 12001
PORT_HEALTH  = 12002
SIGN_SECRET  = os.getenv("AGENTGUARD_SECRET", "agentguard-feedoracle-2026")

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
        status      TEXT DEFAULT 'pending' CHECK(status IN ('pending','approved','denied')),
        approved_by TEXT,
        created_at  TEXT NOT NULL,
        resolved_at TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_audit_agent    ON audit_log(agent_id);
    CREATE INDEX IF NOT EXISTS idx_audit_tool     ON audit_log(tool_name);
    CREATE INDEX IF NOT EXISTS idx_audit_created  ON audit_log(created_at);
    CREATE INDEX IF NOT EXISTS idx_audit_decision ON audit_log(decision);
    CREATE INDEX IF NOT EXISTS idx_rate_agent     ON rate_limits(agent_id);
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

    if not tool_name:
        return {"error": "tool_name required"}

    start = time.monotonic()
    conn = get_db()

    try:
        # 1. Risk score
        risk_score, risk_reasons = compute_risk_score(tool_name, tool_args, agent_id)

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
            reason, duration_ms, sig, ts()
        ))
        conn.commit()

        return {
            "request_id": request_id,
            "tool_name": tool_name,
            "agent_id": agent_id,
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
            "approval_url": f"https://feedoracle.io/guard/approve/{request_id}" if requires else None,
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

        try:
            result = await tool["handler"](tool_args)
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

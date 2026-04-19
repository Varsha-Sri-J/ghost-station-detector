"""
signal_monitor.py  —  Runtime Signal Intelligence Layer.

Simulates post-authentication message traffic and runs behavioural
anomaly detection. Returns signal_penalty, runtime_status, and
session_integrity for dynamic trust degradation in ev_sentinel.py.
"""

import random
import time as _time

# ── Thresholds ────────────────────────────────────────────────────────────────
RTT_SUSPICIOUS_MS = 120
RTT_ATTACK_MS     = 180
FREQ_WINDOW_MS    = 500
FREQ_MAX_MSGS     = 4

SUSPICIOUS_TYPES = {"firmware_update", "config_change"}
BLOCKED_TYPES    = {"emergency_stop_override", "contactor_open", "raw_can_inject"}

PENALTY_SUSPICIOUS = 5
PENALTY_ATTACK     = 30


# ── Message simulator ─────────────────────────────────────────────────────────
def _simulate_messages(mode: str) -> list[dict]:
    # Start from realistic offset so timestamps never obviously begin at 0
    base_ms = int(_time.time() * 1000) % 100_000
    now     = base_ms
    normal_types = [
        "power_request", "power_request", "power_request",
        "status_update", "status_update",
        "pricing", "session_keepalive",
    ]
    messages = []
    n = random.randint(12, 15)

    for i in range(n):
        if mode == "rogue" and i > 6:
            gap = random.randint(40, 100)
        else:
            gap = random.randint(150, 600) + random.randint(0, 80)
        now += gap

        if mode == "rogue":
            if i == 5:   msg_type = "firmware_update"
            elif i == 9: msg_type = "raw_can_inject"
            elif i == 11:msg_type = "emergency_stop_override"
            else:         msg_type = random.choice(normal_types)
        elif mode == "suspicious":
            if i == 4:   msg_type = "firmware_update"
            elif i == 8: msg_type = "config_change"
            else:         msg_type = random.choice(normal_types)
        else:
            msg_type = random.choice(normal_types)

        if mode == "rogue":
            rtt = random.randint(160, 220) if i > 4 else random.randint(10, 30)
        elif mode == "suspicious":
            rtt = random.randint(90, 145) if i % 3 == 0 else random.randint(10, 50)
        else:
            rtt = random.randint(8, 35)

        messages.append({
            "seq": i + 1,
            "type": msg_type,
            "timestamp_ms": now,
            "response_time_ms": rtt,
        })

    return messages


# ── Detection engine ──────────────────────────────────────────────────────────
def _analyse(messages: list[dict]) -> tuple[list[dict], bool, str, int, bool]:
    """
    Returns: (annotated_messages, anomaly_detected, anomaly_reason,
               total_penalty, attack_fired)
    """
    annotated     = []
    reasons       = []
    total_penalty = 0
    attack_fired  = False

    for i, msg in enumerate(messages):
        status = "ACCEPTED"
        reason = ""
        rtt    = msg["response_time_ms"]
        mtype  = msg["type"]
        ts     = msg["timestamp_ms"]

        # 1. Type check (highest priority)
        if mtype in BLOCKED_TYPES:
            status = "BLOCKED"
            reason = f"Unauthorised command '{mtype}' detected"
            attack_fired = True
            total_penalty += PENALTY_ATTACK
        elif mtype in SUSPICIOUS_TYPES:
            status = "SUSPICIOUS"
            reason = f"Unexpected message '{mtype}' during active session"
            total_penalty += min(PENALTY_SUSPICIOUS, 20)

        # 2. Timing check
        if status == "ACCEPTED":
            if rtt >= RTT_ATTACK_MS:
                status = "BLOCKED"
                reason = f"Slow response — {rtt}ms (possible relay attack)"
                attack_fired = True
                total_penalty += PENALTY_ATTACK
            elif rtt >= RTT_SUSPICIOUS_MS:
                status = "SUSPICIOUS"
                reason = f"Slow response — {rtt}ms (above normal)"
                total_penalty += min(PENALTY_SUSPICIOUS, 20)

        # 3. Frequency check
        if status == "ACCEPTED":
            window_start   = ts - FREQ_WINDOW_MS
            msgs_in_window = sum(
                1 for m in messages[:i + 1]
                if m["timestamp_ms"] >= window_start
            )
            if msgs_in_window > FREQ_MAX_MSGS:
                status = "SUSPICIOUS"
                reason = f"Message flood — {msgs_in_window} requests in {FREQ_WINDOW_MS}ms"
                total_penalty += min(PENALTY_SUSPICIOUS, 20)

        if status != "ACCEPTED" and reason:
            reasons.append(reason)

        annotated.append({**msg, "status": status, "reason": reason})

    anomaly_detected = any(m["status"] != "ACCEPTED" for m in annotated)
    anomaly_reason   = reasons[0] if reasons else "No suspicious activity detected"
    total_penalty    = min(total_penalty, 40)

    return annotated, anomaly_detected, anomaly_reason, total_penalty, attack_fired


# ── Runtime classification ────────────────────────────────────────────────────
def _classify_runtime(anomaly: bool, attack_fired: bool, penalty: int) -> tuple[str, str]:
    """
    Maps detection outcome to runtime_status and session_integrity labels.

    runtime_status:   CLEAN | WARNING | ATTACK
    session_integrity: STABLE | DEGRADING | COMPROMISED
    """
    if attack_fired or penalty >= 30:
        return "ATTACK", "COMPROMISED"
    elif anomaly or penalty >= 10:
        return "WARNING", "DEGRADING"
    else:
        return "CLEAN", "STABLE"


# ── Public API ────────────────────────────────────────────────────────────────
def run_signal_monitor(mode: str, initial_trust_score: int) -> dict:
    """
    Args:
        mode:                station mode ("legit" / "suspicious" / "rogue")
        initial_trust_score: trust score from pre-auth phase (0–100)

    Returns dict to merge into run_evaluation() result:
        signal_messages      list[dict]
        signal_anomaly       bool
        signal_reason        str
        signal_penalty       int
        runtime_status       str  — CLEAN | WARNING | ATTACK
        session_integrity    str  — STABLE | DEGRADING | COMPROMISED
        current_trust_score  int  — initial_trust_score minus penalty
        trust_score          int  — alias of current_trust_score (for dashboard compat)
        decision             str
        reason               str
    """
    messages, anomaly, reason, penalty, attack_fired = _analyse(
        _simulate_messages(mode)
    )

    runtime_status, session_integrity = _classify_runtime(anomaly, attack_fired, penalty)

    # Apply penalty — cert kill switch (score=0) is never overridden
    current_trust = initial_trust_score
    if initial_trust_score > 0:
        current_trust = max(0, initial_trust_score - penalty)

    # Derive updated decision — only escalate, never de-escalate
    if initial_trust_score == 0:
        new_decision = "BLOCKED"
        new_reason   = "Invalid certificate — kill switch triggered"
    elif current_trust >= 80 and not anomaly:
        new_decision = "ALLOWED"
        new_reason   = "All pre-connection and runtime signals within normal bounds"
    elif current_trust >= 50:
        new_decision = "SAFE MODE"
        new_reason   = (
            f"Runtime anomaly detected — {reason}"
            if anomaly
            else "Anomalies detected — 3 kW cap, data pins isolated"
        )
    else:
        new_decision = "BLOCKED"
        new_reason   = f"Trust degraded to {current_trust}/100 after runtime penalty — {reason}"

    return {
        "signal_messages":     messages,
        "signal_anomaly":      anomaly,
        "signal_reason":       reason,
        "signal_penalty":      penalty,
        "runtime_status":      runtime_status,
        "session_integrity":   session_integrity,
        "current_trust_score": current_trust,
        "trust_score":         current_trust,   # keeps dashboard reads consistent
        "decision":            new_decision,
        "reason":              new_reason,
    }

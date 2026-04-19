"""
ev_sentinel.py  —  EV-side trust evaluation engine.

Handshake sequence:
  Phase 1  — Station cert validation (EV withholds identity)
  Phase 2  — Mutual authentication (EV presents its cert to station)
  Phase 3  — RTT latency measurement
  Phase 4  — Voltage probe phase
  Phase 5  — Initial trust score (weighted formula + kill switch)
  Phase 5b — Runtime signal monitoring → dynamic trust degradation
  Phase 6  — Conditional identity disclosure (Contract Certificate)

New in this version:
  - initial_trust_score  — score after pre-connection checks only
  - current_trust_score  — score after runtime signal penalty
  - runtime_status       — CLEAN | WARNING | ATTACK
  - session_integrity    — STABLE | DEGRADING | COMPROMISED
  - phase_outcomes       — per-phase pass/fail for breadcrumb rendering
"""

import socket, json, time, statistics, os
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
import datetime
from signal_monitor import run_signal_monitor

HOST = "127.0.0.1"
PORT = 9876
PING_COUNT   = 5
RTT_BLOCK_MS = 120.0
RTT_WARN_MS  = 60.0
VAR_BLOCK    = 100.0
VAR_WARN     = 20.0
WEIGHTS      = {"cert": 0.50, "latency": 0.25, "probe": 0.25}


# ── Simulated TEE ─────────────────────────────────────────────────────────────
class SimulatedTEE:
    """
    Private key sealed at load time.
    Only sign() and the public cert are accessible externally.
    Simulates ARM TrustZone TEE / HSM key isolation.
    """
    def __init__(self):
        with open("certs/ev.key", "rb") as f:
            self._key = serialization.load_pem_private_key(f.read(), password=None)
        with open("certs/ev.pem") as f:
            self.cert_pem = f.read()

    def sign(self, data: bytes) -> bytes:
        return self._key.sign(data, padding.PKCS1v15(), hashes.SHA256())

    # raw key bytes intentionally never exposed


# ── Certificate validation ────────────────────────────────────────────────────
def validate_station_cert(cert_pem: str, logs: list) -> tuple[float, str]:
    try:
        with open("certs/root_ca.pem", "rb") as f:
            root = x509.load_pem_x509_certificate(f.read())
        station = x509.load_pem_x509_certificate(cert_pem.encode())

        now = datetime.datetime.utcnow()
        exp = station.not_valid_after_utc.replace(tzinfo=None)
        if now > exp:
            logs.append(f"[CERT] FAIL — Expired at {exp}")
            return 0.0, f"Expired ({exp.date()})"

        root.public_key().verify(
            station.signature,
            station.tbs_certificate_bytes,
            padding.PKCS1v15(),
            station.signature_hash_algorithm,
        )
        cn = station.subject.get_attributes_for_oid(
            x509.oid.NameOID.COMMON_NAME
        )[0].value
        logs.append(f"[CERT] PASS — Chain valid. CN={cn}, expires {exp.date()}")
        return 1.0, f"Valid — {cn}"

    except Exception as e:
        logs.append(f"[CERT] FAIL — {e}")
        return 0.0, "Untrusted (self-signed or chain broken)"


# ── Mutual auth ───────────────────────────────────────────────────────────────
def send_ev_cert(conn: socket.socket, tee: SimulatedTEE, logs: list) -> tuple[bool, str]:
    logs.append("[MUTUAL AUTH] Sending EV certificate to station for verification...")
    conn.sendall(json.dumps({"type": "EV_CERT", "ev_cert_pem": tee.cert_pem}).encode())
    resp = json.loads(conn.recv(4096).decode())
    if resp.get("verified"):
        logs.append(f"[MUTUAL AUTH] Station verified EV cert: {resp.get('ev_cn', '')}")
        return True, "EV identity verified by station"
    else:
        logs.append(f"[MUTUAL AUTH] Station rejected EV cert: {resp.get('error', '')}")
        return False, f"EV cert rejected: {resp.get('error', '')}"


# ── RTT measurement ───────────────────────────────────────────────────────────
def measure_rtt(conn: socket.socket, logs: list) -> tuple[float, float, str]:
    rtts = []
    for i in range(PING_COUNT):
        try:
            t0 = time.perf_counter()
            conn.sendall(json.dumps({"type": "PING"}).encode())
            conn.recv(256)
            rtts.append((time.perf_counter() - t0) * 1000)
        except Exception as e:
            logs.append(f"[RTT] Ping {i+1} failed: {e}")

    if not rtts:
        return 0.0, 9999.0, "All pings failed"

    avg = statistics.mean(rtts)
    std = statistics.stdev(rtts) if len(rtts) > 1 else 0.0
    logs.append(f"[RTT] {len(rtts)} pings — avg {avg:.1f}ms, std {std:.1f}ms")

    if avg > RTT_BLOCK_MS:
        score  = 0.0
        detail = f"ANOMALOUS — {avg:.1f}ms (threshold {RTT_BLOCK_MS}ms)"
    elif avg > RTT_WARN_MS:
        score  = round(1.0 - (avg - RTT_WARN_MS) / (RTT_BLOCK_MS - RTT_WARN_MS), 3)
        detail = f"ELEVATED — {avg:.1f}ms (penalised)"
    else:
        score  = 1.0
        detail = f"Normal — {avg:.1f}ms"

    logs.append(f"[RTT] Score: {score:.3f} — {detail}")
    return score, round(avg, 2), detail


# ── Probe phase ───────────────────────────────────────────────────────────────
def run_probe(conn: socket.socket, logs: list) -> tuple[float, list, str]:
    logs.append("[PROBE] Requesting voltage probe (low-current test)...")
    conn.sendall(json.dumps({"type": "PROBE_REQUEST"}).encode())
    resp = json.loads(conn.recv(4096).decode())

    if resp.get("type") != "PROBE_RESPONSE":
        logs.append("[PROBE] No probe response.")
        return 0.0, [], "No response"

    readings  = resp["voltage_readings"]
    requested = resp.get("requested_voltage", 400.0)
    var       = statistics.variance(readings)
    mean_v    = statistics.mean(readings)
    dev_pct   = abs(mean_v - requested) / requested * 100

    logs.append(f"[PROBE] Mean {mean_v:.2f}V, variance {var:.3f}, deviation {dev_pct:.2f}%")

    if var > VAR_BLOCK:
        score, detail = 0.0, f"UNSAFE — variance {var:.1f}"
    elif var > VAR_WARN:
        score  = round(1.0 - (var - VAR_WARN) / (VAR_BLOCK - VAR_WARN), 3)
        detail = f"Unstable — variance {var:.1f} (penalised)"
    else:
        score, detail = 1.0, f"Stable — variance {var:.3f}"

    logs.append(f"[PROBE] Score: {score:.3f} — {detail}")
    return score, readings, detail


# ── Initial trust score ───────────────────────────────────────────────────────
def compute_trust(cert: float, latency: float, probe: float, logs: list) -> tuple[int, str, str]:
    """
    Computes the pre-connection trust score from the three signal weights.
    Kill switch: cert == 0.0 forces score to 0 regardless of other signals.
    This score is stored as initial_trust_score and is never modified after.
    """
    if cert == 0.0:
        logs.append("[TRUST] KILL SWITCH — cert=0, blocking regardless of other signals.")
        return 0, "BLOCKED", "Invalid certificate — kill switch triggered"

    score = round(
        (cert * WEIGHTS["cert"] + latency * WEIGHTS["latency"] + probe * WEIGHTS["probe"]) * 100
    )

    if score >= 80:
        return score, "ALLOWED",   "All signals within normal bounds"
    elif score >= 50:
        return score, "SAFE MODE", "Anomalies detected — 3 kW cap, data pins isolated"
    else:
        return score, "BLOCKED",   f"Trust score {score}/100 below minimum threshold"


# ── Main evaluation ───────────────────────────────────────────────────────────
def run_evaluation() -> dict:
    logs = []
    result = {
        # Pre-connection signal scores
        "cert_score":    0.0,
        "latency_score": 0.0,
        "probe_score":   0.0,
        "cert_detail":   "",
        "latency_detail":"",
        "probe_detail":  "",
        "avg_rtt_ms":    None,
        "voltage_readings": [],

        # Trust scores — two distinct values
        "initial_trust_score": 0,    # set after Phase 5, never modified again
        "current_trust_score": 0,    # set after Phase 5b (may be lower than initial)
        "trust_score":         0,    # alias of current_trust_score for dashboard reads

        # Decision
        "decision": "BLOCKED",
        "reason":   "Not evaluated",

        # Authentication
        "mutual_auth_passed": False,
        "mutual_auth_detail": "",
        "identity_shared":    False,

        # Runtime signal intelligence
        "signal_messages":   [],
        "signal_anomaly":    False,
        "signal_reason":     "",
        "signal_penalty":    0,
        "runtime_status":    "CLEAN",      # CLEAN | WARNING | ATTACK
        "session_integrity": "STABLE",     # STABLE | DEGRADING | COMPROMISED

        # Phase outcomes for breadcrumb rendering
        # Each value: "pass" | "fail" | "warn" | "pending"
        "phase_outcomes": {
            "CERT":        "pending",
            "MUTUAL AUTH": "pending",
            "RTT":         "pending",
            "PROBE":       "pending",
            "DECISION":    "pending",
            "RUNTIME":     "pending",
        },

        "logs":  logs,
        "error": None,
    }

    po = result["phase_outcomes"]   # shorthand

    try:
        tee = SimulatedTEE()
        logs.append("[EV] TEE initialised — EV private key sealed.")
        logs.append("[EV] Connecting to charging station...")

        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.settimeout(6.0)
        conn.connect((HOST, PORT))
        logs.append(f"[EV] Connected to {HOST}:{PORT}")

        # ── Phase 1 — Station cert ────────────────────────────────────────────
        logs.append("[EV] Phase 1 — Requesting station certificate (pseudonym only, identity withheld)...")
        conn.sendall(json.dumps({"type": "CERT_REQUEST", "pseudonym": "EV-SESSION-7f3a"}).encode())
        resp      = json.loads(conn.recv(8192).decode())
        cert_pem  = resp.get("cert_pem", "")
        station_id = resp.get("station_id", "UNKNOWN")
        logs.append(f"[EV] Received cert from: {station_id}")

        cert_score, cert_detail = validate_station_cert(cert_pem, logs)
        result.update(cert_score=cert_score, cert_detail=cert_detail)
        po["CERT"] = "pass" if cert_score == 1.0 else "fail"

        # ── Phase 2 — Mutual auth ─────────────────────────────────────────────
        logs.append("[EV] Phase 2 — Mutual authentication (presenting EV certificate)...")
        ma_passed, ma_detail = send_ev_cert(conn, tee, logs)
        result.update(mutual_auth_passed=ma_passed, mutual_auth_detail=ma_detail)
        po["MUTUAL AUTH"] = "pass" if ma_passed else "warn"

        # ── Phase 3 — RTT ─────────────────────────────────────────────────────
        logs.append("[EV] Phase 3 — RTT measurement...")
        lat_score, avg_rtt, lat_detail = measure_rtt(conn, logs)
        result.update(latency_score=lat_score, avg_rtt_ms=avg_rtt, latency_detail=lat_detail)
        po["RTT"] = "pass" if lat_score == 1.0 else "warn" if lat_score > 0 else "fail"

        # ── Phase 4 — Probe ───────────────────────────────────────────────────
        logs.append("[EV] Phase 4 — Voltage probe phase...")
        probe_score, readings, probe_detail = run_probe(conn, logs)
        result.update(probe_score=probe_score, voltage_readings=readings, probe_detail=probe_detail)
        po["PROBE"] = "pass" if probe_score == 1.0 else "warn" if probe_score > 0 else "fail"

        # ── Phase 5 — Initial trust score ─────────────────────────────────────
        initial_score, decision, reason = compute_trust(cert_score, lat_score, probe_score, logs)
        result["initial_trust_score"] = initial_score
        result["current_trust_score"] = initial_score   # will be updated by Phase 5b
        result["trust_score"]         = initial_score
        result["decision"]            = decision
        result["reason"]              = reason
        po["DECISION"] = "pass" if decision == "ALLOWED" else "warn" if decision == "SAFE MODE" else "fail"
        logs.append(f"[TRUST] Initial trust score: {initial_score}/100 → {decision}")

        # ── Phase 5b — Runtime signal monitoring ──────────────────────────────
        logs.append("[EV] Phase 5b — Runtime signal monitoring (post-auth behavioural analysis)...")
        try:
            with open("station_mode.txt") as f:
                station_mode = f.read().strip()
        except FileNotFoundError:
            station_mode = "legit"

        signal_result = run_signal_monitor(station_mode, initial_score)
        result.update(signal_result)

        # Phase 5b sets current_trust_score and trust_score via signal_result
        # Ensure both fields are consistent
        result["current_trust_score"] = signal_result["current_trust_score"]

        if signal_result["signal_anomaly"]:
            logs.append(f"[SIGNAL] {signal_result['runtime_status']} — {signal_result['signal_reason']}")
            logs.append(
                f"[SIGNAL] Trust degraded: {initial_score} → "
                f"{signal_result['current_trust_score']} "
                f"(penalty -{signal_result['signal_penalty']})"
            )
            logs.append(f"[SIGNAL] Session integrity: {signal_result['session_integrity']}")
        else:
            logs.append(
                f"[SIGNAL] {len(signal_result['signal_messages'])} runtime messages — "
                f"all clean. Session integrity: STABLE"
            )

        po["RUNTIME"] = {
            "CLEAN":  "pass",
            "WARNING":"warn",
            "ATTACK": "fail",
        }.get(signal_result["runtime_status"], "pass")

        # ── Phase 6 — Conditional identity disclosure ─────────────────────────
        # Use the original pre-runtime decision for identity disclosure —
        # a session that passes pre-auth should still share identity even if
        # runtime anomalies push it to SAFE MODE (data pins are isolated anyway)
        if decision == "ALLOWED":
            logs.append("[EV] Trust established — transmitting Contract Certificate.")
            conn.sendall(json.dumps({
                "type":        "IDENTITY",
                "contract_id": "EV-CONTRACT-VIN-001-DEMO",
            }).encode())
            conn.recv(256)
            result["identity_shared"] = True
        else:
            logs.append("[EV] Identity withheld — Contract Certificate NOT transmitted.")

        conn.close()

    except ConnectionRefusedError:
        msg = f"Cannot connect to station on {HOST}:{PORT} — is station_sim.py running?"
        logs.append(f"[EV] ERROR — {msg}")
        result["reason"] = msg
        result["error"]  = msg
        for k in po:
            if po[k] == "pending":
                po[k] = "fail"

    except Exception as e:
        logs.append(f"[EV] Unexpected error: {e}")
        result["reason"] = str(e)
        result["error"]  = str(e)
        for k in po:
            if po[k] == "pending":
                po[k] = "fail"

    return result

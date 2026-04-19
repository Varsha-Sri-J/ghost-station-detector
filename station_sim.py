import socket, threading, time, random, json, os

HOST = "127.0.0.1"
PORT = 9876
MODE_FILE = "station_mode.txt"

def get_mode():
    try:
        with open(MODE_FILE) as f:
            return f.read().strip()
    except FileNotFoundError:
        return "legit"

def load_cert(mode):
    path = "certs/rogue_station.pem" if mode == "rogue" else "certs/legit_station.pem"
    with open(path) as f:
        return f.read()

def voltage_readings(mode, n=10):
    # 🔥 UPDATED spreads (more realistic variability)
    spreads = {
        "legit":      (0.2,  2.0),   # was too perfect before
        "suspicious": (5.0, 25.0),   # wider → more variation
        "rogue":     (25.0, 45.0),   # slightly harsher
    }
    lo, hi = spreads.get(mode, (0.5, 2.0))
    spread = random.uniform(lo, hi)
    return [round(400 + random.uniform(-spread, spread), 2) for _ in range(n)]

def rtt_delay(mode):
    # 🔥 UPDATED delays (adds slight jitter for realism)
    delays = {
        "legit":      (0.008, 0.045),   # occasionally spikes near threshold
        "suspicious": (0.055, 0.130),   # overlaps warn/block zone
        "rogue":      (0.130, 0.220),   # clearly malicious
    }
    lo, hi = delays.get(mode, (0.008, 0.030))
    time.sleep(random.uniform(lo, hi))

def handle(conn, addr):
    mode = get_mode()
    print(f"[Station:{mode.upper()}] ← {addr}")
    ev_authenticated = False

    try:
        while True:
            raw = conn.recv(8192)
            if not raw:
                break
            msg = json.loads(raw.decode())
            t = msg.get("type")
            rtt_delay(mode)

            if t == "PING":
                conn.sendall(json.dumps({"type": "PONG"}).encode())

            elif t == "CERT_REQUEST":
                conn.sendall(json.dumps({
                    "type": "CERT_RESPONSE",
                    "cert_pem": load_cert(mode),
                    "station_id": f"STATION-{mode.upper()}-001",
                }).encode())

            elif t == "EV_CERT":
                ev_cert_pem = msg.get("ev_cert_pem", "")
                try:
                    from cryptography import x509
                    from cryptography.hazmat.primitives.asymmetric import padding
                    from cryptography.hazmat.primitives import hashes
                    with open("certs/root_ca.pem", "rb") as f:
                        root_cert = x509.load_pem_x509_certificate(f.read())
                    ev_cert = x509.load_pem_x509_certificate(ev_cert_pem.encode())
                    root_cert.public_key().verify(
                        ev_cert.signature,
                        ev_cert.tbs_certificate_bytes,
                        padding.PKCS1v15(),
                        ev_cert.signature_hash_algorithm,
                    )
                    ev_authenticated = True
                    print(f"[Station] EV cert verified: {ev_cert.subject.rfc4514_string()}")
                    conn.sendall(json.dumps({
                        "type": "EV_AUTH_RESULT",
                        "verified": True,
                        "ev_cn": ev_cert.subject.rfc4514_string(),
                    }).encode())
                except Exception as e:
                    print(f"[Station] EV cert FAILED: {e}")
                    conn.sendall(json.dumps({
                        "type": "EV_AUTH_RESULT",
                        "verified": False,
                        "error": str(e),
                    }).encode())

            elif t == "PROBE_REQUEST":
                conn.sendall(json.dumps({
                    "type": "PROBE_RESPONSE",
                    "voltage_readings": voltage_readings(mode),
                    "requested_voltage": 400.0,
                }).encode())

            elif t == "IDENTITY":
                contract_id = msg.get("contract_id", "UNKNOWN")
                print(f"[Station] Received Contract ID: {contract_id}")
                conn.sendall(json.dumps({"type": "ACK"}).encode())

            else:
                conn.sendall(json.dumps({"type": "UNKNOWN"}).encode())

    except Exception as e:
        print(f"[Station] Error: {e}")
    finally:
        conn.close()

def run():
    if not os.path.exists(MODE_FILE):
        with open(MODE_FILE, "w") as f:
            f.write("legit")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen(10)
        print(f"[Station] Listening on {HOST}:{PORT}  (mode file: {MODE_FILE})")
        print("[Station] Switch mode by changing station_mode.txt — dashboard does this for you.\n")
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=handle, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    run()
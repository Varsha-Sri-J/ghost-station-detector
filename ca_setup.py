"""
ca_setup.py
Run ONCE before starting the demo.
Generates:
  - Root CA (certs/root_ca.pem)
  - Legitimate station cert signed by root CA (certs/legit_station.pem)
  - Rogue station cert — self-signed, NOT trusted (certs/rogue_station.pem)
"""

import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

os.makedirs("certs", exist_ok=True)

def make_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def save_cert(cert, path):
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def save_key(key, path):
    with open(path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ))

now = datetime.datetime.utcnow()

# ── Root CA ──────────────────────────────────────────────────────────────────
root_key = make_key()
root_name = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "V2G-Root-CA"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SentinelCharge PKI"),
])
root_cert = (
    x509.CertificateBuilder()
    .subject_name(root_name)
    .issuer_name(root_name)
    .public_key(root_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now)
    .not_valid_after(now + datetime.timedelta(days=3650))
    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    .sign(root_key, hashes.SHA256())
)
save_cert(root_cert, "certs/root_ca.pem")
save_key(root_key, "certs/root_ca.key")
print("[CA] Root CA generated → certs/root_ca.pem")

# ── Legitimate Station Cert (signed by root CA) ───────────────────────────────
legit_key = make_key()
legit_name = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "LegitStation-001"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "TrustCharge Inc."),
])
legit_cert = (
    x509.CertificateBuilder()
    .subject_name(legit_name)
    .issuer_name(root_name)
    .public_key(legit_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now)
    .not_valid_after(now + datetime.timedelta(days=365))
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .sign(root_key, hashes.SHA256())
)
save_cert(legit_cert, "certs/legit_station.pem")
save_key(legit_key, "certs/legit_station.key")
print("[CA] Legit station cert generated → certs/legit_station.pem")

# ── Rogue Station Cert (self-signed — NOT trusted by our root CA) ─────────────
rogue_key = make_key()
rogue_name = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, "RogueStation-Evil"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "EvilCorp"),
])
rogue_cert = (
    x509.CertificateBuilder()
    .subject_name(rogue_name)
    .issuer_name(rogue_name)          # self-signed = not anchored to our CA
    .public_key(rogue_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now)
    .not_valid_after(now + datetime.timedelta(days=365))
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .sign(rogue_key, hashes.SHA256())
)
save_cert(rogue_cert, "certs/rogue_station.pem")
save_key(rogue_key, "certs/rogue_station.key")
print("[CA] Rogue station cert generated → certs/rogue_station.pem")

print("\n[CA] All certs ready. Run station_sim.py next.")

"""
tests/test_session_security.py

Unit tests for dynamic session key derivation, certificate binding,
genesis block ledger integrity, and key mismatch tamper detection.
"""

import datetime
import json
import pytest
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from cryptography.hazmat.backends import default_backend

from custody.ledger import ChainOfCustodyLedger, generate_session_key


def create_self_signed_cert(cert_path: Path) -> Path:
    """Generate temporary self-signed X.509 certificate for examiner testing."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Garud FX Forensic Cell"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Examiner Patil"),
    ])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256(), default_backend())
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path


def test_generate_ephemeral_session_key():
    key, meta = generate_session_key(examiner_cert_path=None)
    assert len(key) == 32
    assert meta["key_type"] == "EPHEMERAL"
    assert meta["kdf"] == "SECRETS_TOKEN_BYTES_256"
    assert "cert_fingerprint" in meta


def test_generate_certificate_bound_session_key(tmp_path):
    cert_p = create_self_signed_cert(tmp_path / "examiner.pem")
    key1, meta1 = generate_session_key(examiner_cert_path=cert_p)
    key2, meta2 = generate_session_key(examiner_cert_path=cert_p)

    assert len(key1) == 32
    assert meta1["key_type"] == "CERTIFICATE_BOUND"
    assert meta1["kdf"] == "HKDF-HMAC-SHA256"
    assert meta1["cert_fingerprint"] == meta2["cert_fingerprint"]
    # Salt is unique per derivation
    assert meta1["salt_hex"] != meta2["salt_hex"]


def test_genesis_block_binding(tmp_path):
    cert_p = create_self_signed_cert(tmp_path / "examiner.pem")
    ledger_p = tmp_path / "chain_of_custody.jsonl"

    ledger = ChainOfCustodyLedger(ledger_p, examiner_cert_path=cert_p)
    evidence = tmp_path / "evidence.dat"
    evidence.write_bytes(b"UAV Flight Controller Log")

    ledger.record(actor="Examiner Patil", action="ACQUIRE", target_path=evidence)

    # Verify genesis binding exists in index 0 notes
    lines = ledger_p.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1

    genesis_entry = json.loads(lines[0])
    assert genesis_entry["index"] == 0
    assert genesis_entry["action"] == "ACQUIRE"
    assert "CERTIFICATE_BOUND" in genesis_entry["notes"]

    ok, broken_at = ledger.verify_chain()
    assert ok is True
    assert broken_at is None



def test_session_key_mismatch_tamper_detection(tmp_path):
    ledger_p = tmp_path / "chain_of_custody.jsonl"
    key1 = b"SESSION_KEY_ONE_32_BYTES_LONG_!?"
    key2 = b"SESSION_KEY_TWO_32_BYTES_LONG_!?"

    ledger1 = ChainOfCustodyLedger(ledger_p, session_key=key1)
    evidence = tmp_path / "evidence.dat"
    evidence.write_bytes(b"UAV Telemetry Data")
    ledger1.record(actor="investigator_1", action="ACQUIRE", target_path=evidence)

    # Verify with correct session key passes
    ok, broken = ledger1.verify_chain()
    assert ok is True

    # Reloading ledger with a different session key fails verification due to HMAC signature mismatch
    ledger2 = ChainOfCustodyLedger(ledger_p, session_key=key2)
    ok2, broken2 = ledger2.verify_chain()
    assert ok2 is False
    assert broken2 == 0  # Fails at genesis or first entry

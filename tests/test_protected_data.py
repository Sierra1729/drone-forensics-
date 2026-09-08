"""
tests/test_protected_data.py

Unit and integration tests for Protected-Data Analysis, Forensic Decryption,
and Key Event Detection.
Compliant with ISO/IEC 27037:2012 (Preservation of Digital Evidence).
"""

from __future__ import annotations

import os
import zipfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
import pytest

from crypto.protected_data import (
    EncryptionType,
    calculate_entropy,
    identify_encryption,
    find_keys,
    decrypt_artifact,
    _xor_decrypt,
    _aes_decrypt,
)
from custody.ledger import ChainOfCustodyLedger, hash_file
from analytics.correlation import (
    ForensicCorrelationEngine,
    FlightPhase,
    FlightKeyEvent,
)
from normalize.schema import NormalizedEvent, EventType


def test_calculate_entropy():
    # Zero bytes -> 0.0
    assert calculate_entropy(b"") == 0.0

    # Repeating single byte -> 0.0
    zero_entropy = calculate_entropy(b"A" * 1000)
    assert zero_entropy == 0.0

    # Plain text ASCII -> typically between 3.0 and 5.0
    text_entropy = calculate_entropy(b"The quick brown fox jumps over the lazy dog 1234567890")
    assert 3.0 < text_entropy < 5.5

    # Uniform random / pseudo-random bytes -> high entropy close to 8.0
    random_bytes = bytes((i * 37 + 13) % 256 for i in range(2048))
    assert calculate_entropy(random_bytes) > 7.5


def test_identify_encryption_plaintext(tmp_path: Path):
    # PX4 magic
    px4_file = tmp_path / "test_px4.ulg"
    px4_file.write_bytes(b"\x55\x4c\x6f\x67\x46\x69\x6c\x65\x01\x02\x03\x04")
    enc_type, entropy, meta = identify_encryption(px4_file)
    assert enc_type == EncryptionType.PLAINTEXT_OPEN

    # ArduPilot magic
    ardu_file = tmp_path / "test_ardu.bin"
    ardu_file.write_bytes(b"\xa3\x95\x80\x89\x01\x02\x03")
    enc_type, entropy, meta = identify_encryption(ardu_file)
    assert enc_type == EncryptionType.PLAINTEXT_OPEN

    # Plaintext DJI DAT
    dji_file = tmp_path / "test_dji.dat"
    dji_file.write_bytes(b"\x55\x10\x00\x00\x01\x02\x03\x04")
    enc_type, entropy, meta = identify_encryption(dji_file)
    assert enc_type == EncryptionType.PLAINTEXT_OPEN


def test_identify_encryption_xor_and_protected(tmp_path: Path):
    # DJI Legacy XOR scrambled: 0x55 ^ 0x77 = 0x22
    xor_file = tmp_path / "scrambled_dji.dat"
    xor_file.write_bytes(b"\x22\x67\x77\x77" + b"\x00" * 32)
    enc_type, entropy, meta = identify_encryption(xor_file)
    assert enc_type == EncryptionType.XOR_SCRAMBLE
    assert meta.get("detected_vendor") == "DJI_LEGACY_XOR"

    # Protected ZIP container
    zip_path = tmp_path / "protected_box.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.setpassword(b"investigator_secret")
        zf.writestr("flight_log.csv", "timestamp,lat,lon\n1,19.0,72.0\n")
    
    enc_type, entropy, meta = identify_encryption(zip_path)
    assert enc_type in (EncryptionType.PASSWORD_ZIP, EncryptionType.PLAINTEXT_OPEN)


def test_find_keys():
    # Static XOR mask lookup
    key_bytes, src = find_keys(EncryptionType.XOR_SCRAMBLE)
    assert key_bytes == bytes([0x77])
    assert "VENDOR_STATIC_XOR_MASK" in src

    # Investigator hex key (32 hex = 16 bytes)
    hex_key = "0123456789abcdef0123456789abcdef"
    key_bytes, src = find_keys(EncryptionType.AES_128_CBC, user_key=hex_key)
    assert key_bytes == bytes.fromhex(hex_key)
    assert "INVESTIGATOR_HEX_KEY" in src

    # Investigator passphrase derivation
    key_bytes, src = find_keys(EncryptionType.AES_256_CBC, user_key="MissionPassword2026")
    assert len(key_bytes) == 32
    assert "INVESTIGATOR_PASSPHRASE" in src

    # No key provided
    key_bytes, src = find_keys(EncryptionType.AES_128_CBC)
    assert key_bytes is None
    assert src == "NO_KEY_FOUND"


def test_decrypt_artifact_xor_pipeline(tmp_path: Path):
    # Prepare mock scrambled DJI evidence
    original_plaintext = b"\x55\x10\x00\x00FlightRecordLog_Version_1.0_GPS_Lat_19.0760_Lon_72.8777"
    xor_key = bytes([0x77])
    scrambled_bytes = _xor_decrypt(original_plaintext, xor_key)

    evidence_file = tmp_path / "scrambled_flight.dat"
    evidence_file.write_bytes(scrambled_bytes)

    out_dir = tmp_path / "case_output"
    ledger_file = out_dir / "chain_of_custody.jsonl"
    ledger = ChainOfCustodyLedger(ledger_file)

    # Ingest through decrypt_artifact
    report = decrypt_artifact(
        file_path=evidence_file,
        output_dir=out_dir,
        ledger=ledger,
        investigator_id="INSP-PATIL-07",
    )

    assert report.is_protected is True
    assert report.encryption_type == EncryptionType.XOR_SCRAMBLE.value
    assert report.decrypted is True
    assert report.decrypted_file is not None

    # Verify recovered plaintext
    recovered = Path(report.decrypted_file).read_bytes()
    assert recovered == original_plaintext

    # Verify Merkle Chain-of-Custody integrity
    intact, broken_at = ledger.verify_chain()
    assert intact is True
    assert broken_at is None

    # Verify ledger recorded PROTECTED_DATA_DECRYPT
    entries = ledger._read_all()
    decrypt_entries = [e for e in entries if e.action == "PROTECTED_DATA_DECRYPT"]
    assert len(decrypt_entries) == 1
    assert "Authorized Decryption" in decrypt_entries[0].notes


def test_decrypt_artifact_plaintext_passthrough(tmp_path: Path):
    plain_file = tmp_path / "open_flight.ulg"
    plain_file.write_bytes(b"\x55\x4c\x6f\x67\x46\x69\x6c\x65" + b"\x00" * 64)

    out_dir = tmp_path / "case_output_plain"
    report = decrypt_artifact(file_path=plain_file, output_dir=out_dir)

    assert report.is_protected is False
    assert report.decrypted is True
    assert report.decrypted_file == str(plain_file)


def test_key_event_detection_milestones():
    engine = ForensicCorrelationEngine()
    t0 = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)

    events = [
        # Arm event
        NormalizedEvent(
            timestamp_utc=t0,
            source_platform="px4",
            event_type=EventType.ARM_DISARM.value,
            source_file="f.ulg",
            source_file_sha256="0" * 64,
            payload={"arming_state": "ARMED"},
        ),
        # Ground stationary point
        NormalizedEvent(
            timestamp_utc=t0 + timedelta(seconds=1),
            source_platform="px4",
            event_type=EventType.GPS_FIX.value,
            source_file="f.ulg",
            source_file_sha256="0" * 64,
            latitude=19.0760,
            longitude=72.8777,
            altitude_m=10.0,
            ground_speed_mps=0.1,
        ),
        # Liftoff / Takeoff point
        NormalizedEvent(
            timestamp_utc=t0 + timedelta(seconds=5),
            source_platform="px4",
            event_type=EventType.GPS_FIX.value,
            source_file="f.ulg",
            source_file_sha256="0" * 64,
            latitude=19.0761,
            longitude=72.8778,
            altitude_m=14.5,
            ground_speed_mps=2.4,
        ),
        # Hover points (speed <= 0.4 m/s, alt > baseline + 1.0m, duration >= 3s)
        NormalizedEvent(
            timestamp_utc=t0 + timedelta(seconds=10),
            source_platform="px4",
            event_type=EventType.GPS_FIX.value,
            source_file="f.ulg",
            source_file_sha256="0" * 64,
            latitude=19.0765,
            longitude=72.8780,
            altitude_m=25.0,
            ground_speed_mps=0.2,
        ),
        NormalizedEvent(
            timestamp_utc=t0 + timedelta(seconds=12),
            source_platform="px4",
            event_type=EventType.GPS_FIX.value,
            source_file="f.ulg",
            source_file_sha256="0" * 64,
            latitude=19.0765,
            longitude=72.8780,
            altitude_m=25.0,
            ground_speed_mps=0.1,
        ),
        NormalizedEvent(
            timestamp_utc=t0 + timedelta(seconds=14),
            source_platform="px4",
            event_type=EventType.GPS_FIX.value,
            source_file="f.ulg",
            source_file_sha256="0" * 64,
            latitude=19.0765,
            longitude=72.8780,
            altitude_m=25.0,
            ground_speed_mps=0.2,
        ),
        # Touchdown / landing point
        NormalizedEvent(
            timestamp_utc=t0 + timedelta(seconds=30),
            source_platform="px4",
            event_type=EventType.GPS_FIX.value,
            source_file="f.ulg",
            source_file_sha256="0" * 64,
            latitude=19.0760,
            longitude=72.8777,
            altitude_m=10.2,
            ground_speed_mps=0.1,
        ),
        # Disarm event
        NormalizedEvent(
            timestamp_utc=t0 + timedelta(seconds=32),
            source_platform="px4",
            event_type=EventType.ARM_DISARM.value,
            source_file="f.ulg",
            source_file_sha256="0" * 64,
            payload={"arming_state": "DISARMED"},
        ),
    ]

    key_events = engine.detect_flight_key_events(events)
    phases = [k.phase for k in key_events]

    assert FlightPhase.ARMED.value in phases
    assert FlightPhase.TAKEOFF.value in phases
    assert FlightPhase.HOVER.value in phases
    assert FlightPhase.LANDING.value in phases
    assert FlightPhase.DISARMED.value in phases

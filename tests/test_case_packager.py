"""
tests/test_case_packager.py

Unit tests for Garud FX SQLite case packager (.garud_db) and custody digital signature sealing.
"""

import json
import sqlite3
import tempfile
from pathlib import Path
from datetime import datetime, timezone

from normalize.schema import NormalizedEvent, EventType
from custody.ledger import ChainOfCustodyLedger
from custody.case_packager import package_case_to_garud_db, GarudCasePackager


def test_normalized_event_raw_hex_offset():
    ev = NormalizedEvent(
        timestamp_utc=datetime.now(timezone.utc),
        source_platform="px4",
        event_type=EventType.GPS_FIX.value,
        source_file="test.ulg",
        source_file_sha256="a" * 64,
        byte_offset="00014B20",
    )
    d = ev.to_dict()
    assert "raw_hex_offset" in d
    assert d["raw_hex_offset"] == "0x00014B20"
    assert ev.raw_hex_offset == "0x00014B20"


def test_custody_ledger_digital_signature(tmp_path: Path):
    ledger_file = tmp_path / "chain_of_custody.jsonl"
    dummy_target = tmp_path / "dummy_evidence.bin"
    dummy_target.write_bytes(b"TEST_EVIDENCE_STREAM")

    ledger = ChainOfCustodyLedger(ledger_file)
    entry = ledger.record("Lead Architect", "ACQUIRE", dummy_target)

    assert entry.digital_signature != ""
    assert len(entry.digital_signature) == 64

    is_valid, broken_idx = ledger.verify_chain()
    assert is_valid is True
    assert broken_idx is None

    # Test tampering detection
    lines = ledger_file.read_text().splitlines()
    tampered_data = json.loads(lines[0])
    tampered_data["actor"] = "Malicious Attacker"
    ledger_file.write_text(json.dumps(tampered_data) + "\n")

    ledger_tampered = ChainOfCustodyLedger(ledger_file)
    is_valid, broken_idx = ledger_tampered.verify_chain()
    assert is_valid is False
    assert broken_idx == 0


def test_case_packager_to_garud_db(tmp_path: Path):
    case_dir = tmp_path / "case_001"
    case_dir.mkdir()

    # Create dummy events.jsonl
    ev1 = NormalizedEvent(
        timestamp_utc=datetime.now(timezone.utc),
        source_platform="dji",
        event_type=EventType.GPS_FIX.value,
        source_file="FLY001.DAT",
        source_file_sha256="b" * 64,
        latitude=19.0760,
        longitude=72.8777,
        altitude_m=120.5,
        byte_offset="0x0002A100",
    )
    events_file = case_dir / "events.jsonl"
    events_file.write_text(ev1.to_json() + "\n")

    # Create dummy chain_of_custody.jsonl
    dummy_target = case_dir / "FLY001.DAT"
    dummy_target.write_bytes(b"DJI_LOG_V3_TEST_DATA")

    ledger = ChainOfCustodyLedger(case_dir / "chain_of_custody.jsonl")
    ledger.record("Inspector Patil", "PARSED_TELEMETRY", dummy_target)

    # Create dummy evidence_exhibits.json
    exhibits_file = case_dir / "evidence_exhibits.json"
    exhibits_file.write_text(json.dumps([
        {
            "exhibit_id": "EX-01",
            "name": "Seized Drone MicroSD Card",
            "type": "physical",
            "file_path": str(dummy_target),
            "sha256_hash": "c" * 64,
            "description": "Seized at scene"
        }
    ]))

    # Package into .garud_db
    db_path = package_case_to_garud_db(case_dir)
    assert db_path.exists()
    assert db_path.suffix == ".garud_db"

    # Query SQLite database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT count(*) FROM telemetry")
    assert cursor.fetchone()[0] == 1

    cursor.execute("SELECT raw_hex_offset, latitude, longitude FROM telemetry")
    offset, lat, lon = cursor.fetchone()
    assert offset == "0x0002A100"
    assert lat == 19.0760
    assert lon == 72.8777

    cursor.execute("SELECT count(*) FROM custody_ledger")
    assert cursor.fetchone()[0] == 1

    cursor.execute("SELECT digital_signature FROM custody_ledger")
    sig = cursor.fetchone()[0]
    assert len(sig) == 64

    cursor.execute("SELECT count(*) FROM exhibits")
    assert cursor.fetchone()[0] == 1

    conn.close()

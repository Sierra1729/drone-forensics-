"""
tests/test_dji.py

Comprehensive test suite for the DJI Flight Log forensic parser.
Validates:
1. Magic header signature detection (can_parse).
2. Aircraft metadata and serial number identification.
3. High-rate OSD and battery telemetry extraction.
4. Chain of custody integration and cryptographic hash linkage.
5. Resilience against corrupt frame segments.
"""

import pytest
from pathlib import Path

from custody.ledger import ChainOfCustodyLedger
from normalize.schema import EventType, NormalizedEventStore
from parsers.base import get_parser_for_file, list_registered_parsers
from parsers.dji import DJIFlightLogParser
from tests.synthetic_dji import generate_synthetic_dji_log


@pytest.fixture
def sample_dji(tmp_path) -> Path:
    log_path = tmp_path / "dji_flight_record.txt"
    return generate_synthetic_dji_log(log_path)


def test_dji_parser_registration(sample_dji):
    registered = list_registered_parsers()
    assert "dji_flight_log" in registered

    parser = get_parser_for_file(sample_dji)
    assert parser is not None
    assert isinstance(parser, DJIFlightLogParser)


def test_can_parse_dji_header(tmp_path, sample_dji):
    parser = DJIFlightLogParser()
    assert parser.can_parse(sample_dji) is True

    # Empty file
    empty = tmp_path / "empty.txt"
    empty.write_bytes(b"")
    assert parser.can_parse(empty) is False

    # Irrelevant file
    other = tmp_path / "other.txt"
    other.write_bytes(b"Regular log file without DJI header")
    assert parser.can_parse(other) is False


def test_dji_metadata_and_telemetry_extraction(sample_dji):
    parser = DJIFlightLogParser()
    events = parser.parse(sample_dji)
    assert len(events) > 0

    store = NormalizedEventStore()
    for ev in events:
        store.add(ev)

    # 1. Aircraft Metadata
    params = store.by_type(EventType.CONFIG_PARAM.value)
    assert len(params) >= 1
    meta = params[0]
    assert meta.payload.get("aircraft_model") == "DJI Mavic 3 Enterprise"
    assert meta.payload.get("serial_number") == "1581F4GBD210001"

    # 2. OSD Trajectory records
    gps_fixes = store.by_type(EventType.GPS_FIX.value)
    assert len(gps_fixes) == 10
    first_gps = gps_fixes[0]
    assert pytest.approx(first_gps.latitude, 0.0001) == 19.0760
    assert pytest.approx(first_gps.longitude, 0.0001) == 72.8777
    assert pytest.approx(first_gps.altitude_m, 0.01) == 5.0
    assert pytest.approx(first_gps.ground_speed_mps, 0.01) == 14.2
    assert first_gps.satellites_visible == 18
    assert pytest.approx(first_gps.hdop, 0.01) == 0.6
    assert first_gps.source_platform == "dji"
    assert pytest.approx(first_gps.pitch_deg, 0.01) == -2.5
    assert pytest.approx(first_gps.roll_deg, 0.01) == 1.0
    assert pytest.approx(first_gps.yaw_deg, 0.01) == 89.8

    # 3. Battery telemetry
    bats = store.by_type(EventType.BATTERY_STATE.value)
    assert len(bats) == 10
    assert pytest.approx(bats[0].battery_voltage_v, 0.01) == 15.4
    assert pytest.approx(bats[0].battery_current_a, 0.01) == 14.5
    assert bats[-1].battery_voltage_v < bats[0].battery_voltage_v

    # 4. Critical events (Arming and RTH trigger)
    arms = store.by_type(EventType.ARM_DISARM.value)
    assert len(arms) >= 1

    rths = store.by_type(EventType.RTH_TRIGGER.value)
    assert len(rths) >= 1
    assert "Return-To-Home" in rths[0].payload.get("message", "")


def test_dji_custody_ledger_integration(tmp_path, sample_dji):
    ledger_path = tmp_path / "custody_ledger.jsonl"
    ledger = ChainOfCustodyLedger(ledger_path)

    parser = DJIFlightLogParser()
    events = parser.parse(sample_dji, custody_ledger=ledger, actor="inspector_deshmukh")

    assert len(ledger) == 1
    ok, broken_at = ledger.verify_chain()
    assert ok is True
    assert broken_at is None

    entry = ledger._entries[0]
    assert entry.action == "PARSE"
    assert entry.actor == "inspector_deshmukh"
    assert entry.target_sha256 is not None
    assert entry.target_blake3 is not None

    for ev in events:
        assert ev.source_file_sha256 == entry.target_sha256


def test_dji_resilience_to_corrupted_stream(tmp_path, sample_dji):
    valid_bytes = sample_dji.read_bytes()
    # Insert 50 corrupted bytes after frame 3
    corrupted_bytes = valid_bytes[:200] + (b"\xDE\xAD\xBE\xEF" * 12) + valid_bytes[200:]

    damaged_file = tmp_path / "damaged_dji.txt"
    damaged_file.write_bytes(corrupted_bytes)

    parser = DJIFlightLogParser()
    events = parser.parse(damaged_file)
    assert len(events) > 0
    gps_fixes = [e for e in events if e.event_type == EventType.GPS_FIX.value]
    assert len(gps_fixes) >= 5

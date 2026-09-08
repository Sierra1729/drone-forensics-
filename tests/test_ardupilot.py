"""
tests/test_ardupilot.py

Comprehensive test suite for ArduPilot DataFlash (.BIN) forensic parser.
Validates:
1. Magic byte detection (can_parse).
2. End-to-end telemetry and event extraction.
3. UTC GPS clock synchronization.
4. Custody ledger integration and cryptographic hash binding.
5. Stream resynchronization over corrupt/tampered byte spans.
"""

import pytest
from datetime import timezone
from pathlib import Path

from custody.ledger import ChainOfCustodyLedger
from normalize.schema import EventType, NormalizedEventStore
from parsers.ardupilot import ArduPilotDataFlashParser
from parsers.base import get_parser_for_file, list_registered_parsers
from tests.synthetic_ardupilot import generate_synthetic_ardupilot_bin


@pytest.fixture
def sample_bin(tmp_path) -> Path:
    bin_path = tmp_path / "flight_test.bin"
    return generate_synthetic_ardupilot_bin(bin_path)


def test_parser_registry_discovery(sample_bin):
    registered = list_registered_parsers()
    assert "ardupilot_dataflash_bin" in registered

    parser = get_parser_for_file(sample_bin)
    assert parser is not None
    assert isinstance(parser, ArduPilotDataFlashParser)


def test_can_parse_validation(tmp_path, sample_bin):
    parser = ArduPilotDataFlashParser()
    assert parser.can_parse(sample_bin) is True

    # Non-existent file
    assert parser.can_parse(tmp_path / "missing.bin") is False

    # Empty file
    empty = tmp_path / "empty.bin"
    empty.write_bytes(b"")
    assert parser.can_parse(empty) is False

    # Invalid header
    bogus = tmp_path / "bogus.bin"
    bogus.write_bytes(b"PK\x03\x04not_a_bin")
    assert parser.can_parse(bogus) is False


def test_full_extraction_and_telemetry(sample_bin):
    parser = ArduPilotDataFlashParser()
    events = parser.parse(sample_bin)
    assert len(events) > 0

    store = NormalizedEventStore()
    for ev in events:
        store.add(ev)

    # 1. Parameter events
    params = store.by_type(EventType.CONFIG_PARAM.value)
    assert len(params) == 2
    param_names = [p.payload.get("Name") for p in params]
    assert "PILOT_SPEED_UP" in param_names
    assert "RTL_ALT" in param_names

    # 2. Flight mode transitions
    modes = store.by_type(EventType.MODE_CHANGE.value)
    assert len(modes) == 2
    mode_names = [m.flight_mode for m in modes]
    assert "AUTO" in mode_names
    assert "RTL" in mode_names

    # 3. GPS telemetry records
    gps_fixes = store.by_type(EventType.GPS_FIX.value)
    assert len(gps_fixes) == 10
    first_gps = gps_fixes[0]
    assert pytest.approx(first_gps.latitude, 0.0001) == 19.0760
    assert pytest.approx(first_gps.longitude, 0.0001) == 72.8777
    assert first_gps.altitude_m == 10.0
    assert first_gps.ground_speed_mps == 12.5
    assert first_gps.heading_deg == 45.0
    assert first_gps.satellites_visible == 14
    assert pytest.approx(first_gps.hdop, 0.01) == 0.8
    assert first_gps.timestamp_utc.tzinfo == timezone.utc

    # 4. IMU attitude samples
    att_samples = store.by_type(EventType.IMU_SAMPLE.value)
    assert len(att_samples) == 10
    assert pytest.approx(att_samples[0].roll_deg, 0.01) == 1.2
    assert pytest.approx(att_samples[0].pitch_deg, 0.01) == -0.8

    # 5. Battery telemetry
    bats = store.by_type(EventType.BATTERY_STATE.value)
    assert len(bats) == 10
    assert pytest.approx(bats[0].battery_voltage_v, 0.01) == 12.6
    assert bats[0].battery_current_a == 18.5
    assert bats[-1].battery_voltage_v < bats[0].battery_voltage_v  # Discharged

    # 6. Critical safety events (Arming and RTH Trigger)
    arms = store.by_type(EventType.ARM_DISARM.value)
    assert len(arms) >= 1

    rths = store.by_type(EventType.RTH_TRIGGER.value)
    assert len(rths) >= 1
    assert "Low Battery" in rths[0].payload.get("Message", "")


def test_custody_ledger_integration(tmp_path, sample_bin):
    ledger_path = tmp_path / "chain_of_custody.jsonl"
    ledger = ChainOfCustodyLedger(ledger_path)

    parser = ArduPilotDataFlashParser()
    events = parser.parse(sample_bin, custody_ledger=ledger, actor="investigator_patil")

    # Ledger must have 1 entry for the PARSE action
    assert len(ledger) == 1
    ok, broken_at = ledger.verify_chain()
    assert ok is True
    assert broken_at is None

    entry = ledger._entries[0]
    assert entry.action == "PARSE"
    assert entry.actor == "investigator_patil"
    assert entry.target_sha256 is not None
    assert entry.target_blake3 is not None

    # Every event's source_file_sha256 must match the ledger entry
    for ev in events:
        assert ev.source_file_sha256 == entry.target_sha256


def test_resilience_to_corrupted_byte_stream(tmp_path, sample_bin):
    """Forensic Soundness: A damaged log must not crash the parser;

    the parser must resync and recover surrounding valid frames.
    """
    valid_bytes = sample_bin.read_bytes()
    # Inject 100 bytes of garbage noise right in the middle
    midpoint = len(valid_bytes) // 2
    corrupted_bytes = valid_bytes[:midpoint] + (b"\xFF\x00\xAA\x55" * 25) + valid_bytes[midpoint:]

    corrupt_file = tmp_path / "damaged_flight.bin"
    corrupt_file.write_bytes(corrupted_bytes)

    parser = ArduPilotDataFlashParser()
    # Must not raise exceptions
    events = parser.parse(corrupt_file)
    assert len(events) > 0
    # Must still extract multiple valid GPS frames from uncorrupted regions
    gps_fixes = [e for e in events if e.event_type == EventType.GPS_FIX.value]
    assert len(gps_fixes) >= 5

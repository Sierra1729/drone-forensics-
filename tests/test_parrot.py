"""
tests/test_parrot.py

Comprehensive test suite for the Parrot UAV (ANAFI Series) forensic parser.
Validates:
1. Format identification and magic signature detection.
2. Dual-entity metadata extraction (Drone + Skycontroller serials).
3. Telemetry and flight dynamics normalization.
4. Operational safety events (Takeoff, RTH, Landing).
5. Chain of custody hash-chain integration.
6. Error handling on malformed JSON logs.
"""

from pathlib import Path
import pytest

from custody.ledger import ChainOfCustodyLedger
from normalize.schema import EventType, NormalizedEventStore
from parsers.base import get_parser_for_file, list_registered_parsers
from parsers.parrot import ParrotFlightLogParser
from tests.synthetic_parrot import generate_synthetic_parrot_log


@pytest.fixture
def sample_parrot(tmp_path) -> Path:
    json_path = tmp_path / "parrot_flight_log.json"
    return generate_synthetic_parrot_log(json_path)


def test_parrot_parser_registration(sample_parrot):
    registered = list_registered_parsers()
    assert "parrot_anafi_json" in registered

    parser = get_parser_for_file(sample_parrot)
    assert parser is not None
    assert isinstance(parser, ParrotFlightLogParser)


def test_can_parse_parrot_signatures(tmp_path, sample_parrot):
    parser = ParrotFlightLogParser()
    assert parser.can_parse(sample_parrot) is True

    # Empty file
    empty = tmp_path / "empty.json"
    empty.write_text("")
    assert parser.can_parse(empty) is False

    # Random JSON without Parrot metadata
    other_json = tmp_path / "other.json"
    other_json.write_text('{"app": "notes", "version": 1}')
    assert parser.can_parse(other_json) is False


def test_parrot_extraction_and_telemetry(sample_parrot):
    parser = ParrotFlightLogParser()
    events = parser.parse(sample_parrot)
    assert len(events) > 0

    store = NormalizedEventStore()
    for ev in events:
        store.add(ev)

    # 1. Identity & Metadata
    params = store.by_type(EventType.CONFIG_PARAM.value)
    assert len(params) >= 1
    meta = params[0]
    assert meta.payload.get("aircraft_model") == "Parrot ANAFI USA"
    assert meta.payload.get("serial_number") == "PI040384AA9J123456"
    assert meta.payload.get("controller_model") == "Skycontroller 3"
    assert meta.payload.get("controller_serial") == "PI020184AA9J654321"

    # 2. GPS & Telemetry
    gps_fixes = store.by_type(EventType.GPS_FIX.value)
    assert len(gps_fixes) == 10
    first_gps = gps_fixes[0]
    assert pytest.approx(first_gps.latitude, 0.0001) == 19.0760
    assert pytest.approx(first_gps.longitude, 0.0001) == 72.8777
    assert first_gps.altitude_m == 5.0
    assert first_gps.ground_speed_mps == 13.5
    assert first_gps.satellites_visible == 17
    assert first_gps.source_platform == "parrot"
    assert pytest.approx(first_gps.pitch_deg, 0.01) == -2.0
    assert pytest.approx(first_gps.roll_deg, 0.01) == 1.2
    assert pytest.approx(first_gps.battery_voltage_v, 0.01) == 11.4

    # 3. Events (Takeoff, RTH, Landing)
    arms = store.by_type(EventType.ARM_DISARM.value)
    assert len(arms) >= 2  # Takeoff and Landing

    rths = store.by_type(EventType.RTH_TRIGGER.value)
    assert len(rths) >= 1
    assert "Low battery" in rths[0].payload.get("message", "")


def test_parrot_custody_ledger_integration(tmp_path, sample_parrot):
    ledger_path = tmp_path / "parrot_custody.jsonl"
    ledger = ChainOfCustodyLedger(ledger_path)

    parser = ParrotFlightLogParser()
    events = parser.parse(sample_parrot, custody_ledger=ledger, actor="inspector_deshmukh")

    assert len(ledger) == 1
    ok, broken_at = ledger.verify_chain()
    assert ok is True
    assert broken_at is None

    entry = ledger._entries[0]
    assert entry.action == "PARSE"
    assert entry.actor == "inspector_deshmukh"
    for ev in events:
        assert ev.source_file_sha256 == entry.target_sha256


def test_parrot_malformed_json(tmp_path):
    broken_file = tmp_path / "broken_parrot.json"
    broken_file.write_text('{"drone_model": "Parrot ANAFI", "telemetry": [ { incomplete')

    parser = ParrotFlightLogParser()
    # can_parse returns True because prefix has "parrot"
    assert parser.can_parse(broken_file) is True
    # parse returns empty list without raising exception
    events = parser.parse(broken_file)
    assert events == []

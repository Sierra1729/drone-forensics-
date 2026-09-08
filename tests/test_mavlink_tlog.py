"""
tests/test_mavlink_tlog.py

Comprehensive test suite for the MAVLink Telemetry (.tlog) radio log forensic parser.
Validates:
1. MAVLink packet framing detection and parser dispatch.
2. Extraction of GLOBAL_POSITION_INT, ATTITUDE, and SYS_STATUS packets.
3. Operational events (Arming, RTL failsafe, Disarming).
4. Chain of custody hash-chain integration.
"""

from pathlib import Path
import pytest

from custody.ledger import ChainOfCustodyLedger
from normalize.schema import EventType, NormalizedEventStore
from parsers.base import get_parser_for_file, list_registered_parsers
from parsers.mavlink_tlog import MAVLinkTLogParser
from tests.synthetic_tlog import generate_synthetic_tlog


@pytest.fixture
def sample_tlog(tmp_path) -> Path:
    tlog_path = tmp_path / "radio_flight.tlog"
    return generate_synthetic_tlog(tlog_path)


def test_tlog_parser_registration(sample_tlog):
    registered = list_registered_parsers()
    assert "mavlink_telemetry_tlog" in registered

    parser = get_parser_for_file(sample_tlog)
    assert parser is not None
    assert isinstance(parser, MAVLinkTLogParser)


def test_can_parse_tlog(tmp_path, sample_tlog):
    parser = MAVLinkTLogParser()
    assert parser.can_parse(sample_tlog) is True

    # Empty file
    empty = tmp_path / "empty.tlog"
    empty.write_bytes(b"")
    # Empty file has .tlog extension so can_parse is True (or False if non-file)
    assert parser.can_parse(tmp_path / "missing.tlog") is False

    # Irrelevant file without .tlog
    other = tmp_path / "other.bin"
    other.write_bytes(b"NON_MAVLINK_CONTENT")
    assert parser.can_parse(other) is False


def test_tlog_extraction_and_telemetry(sample_tlog):
    parser = MAVLinkTLogParser()
    events = parser.parse(sample_tlog)
    assert len(events) > 0

    store = NormalizedEventStore()
    for ev in events:
        store.add(ev)

    # 1. GPS Waypoints (GLOBAL_POSITION_INT)
    gps_fixes = store.by_type(EventType.GPS_FIX.value)
    assert len(gps_fixes) == 10
    first_gps = gps_fixes[0]
    assert pytest.approx(first_gps.latitude, 0.0001) == 19.0760
    assert pytest.approx(first_gps.longitude, 0.0001) == 72.8777
    assert first_gps.altitude_m == 10.0
    assert pytest.approx(first_gps.ground_speed_mps, 0.1) == 12.5
    assert first_gps.heading_deg == 45.0
    assert first_gps.satellites_visible == 15
    assert first_gps.hdop == 0.75

    # 2. IMU Attitude Samples
    att_samples = store.by_type(EventType.IMU_SAMPLE.value)
    assert len(att_samples) == 10
    assert pytest.approx(att_samples[0].roll_deg, 0.1) == 1.15
    assert pytest.approx(att_samples[0].pitch_deg, 0.1) == -2.29

    # 3. Battery Telemetry (SYS_STATUS)
    bats = store.by_type(EventType.BATTERY_STATE.value)
    assert len(bats) == 10
    assert pytest.approx(bats[0].battery_voltage_v, 0.1) == 12.6
    assert pytest.approx(bats[0].battery_current_a, 0.1) == 16.5

    # 4. Critical Safety Messages (STATUSTEXT)
    arms = store.by_type(EventType.ARM_DISARM.value)
    assert len(arms) >= 1

    rths = store.by_type(EventType.RTH_TRIGGER.value)
    assert len(rths) >= 1
    assert "Failsafe" in rths[0].payload.get("message", "")


def test_tlog_custody_ledger_integration(tmp_path, sample_tlog):
    ledger_path = tmp_path / "tlog_custody.jsonl"
    ledger = ChainOfCustodyLedger(ledger_path)

    parser = MAVLinkTLogParser()
    events = parser.parse(sample_tlog, custody_ledger=ledger, actor="inspector_sharma")

    assert len(ledger) == 1
    ok, broken_at = ledger.verify_chain()
    assert ok is True
    assert broken_at is None

    for ev in events:
        assert ev.source_file_sha256 == ledger._entries[0].target_sha256

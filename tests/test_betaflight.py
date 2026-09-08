"""
tests/test_betaflight.py

Unit tests for Betaflight / INAV Blackbox flight log parser.
"""

from pathlib import Path
import pytest

from custody.ledger import ChainOfCustodyLedger
from normalize.schema import EventType, NormalizedEventStore
from parsers.base import get_parser_for_file, list_registered_parsers
from parsers.betaflight_blackbox import BetaflightBlackboxParser


@pytest.fixture
def sample_blackbox_csv(tmp_path) -> Path:
    log_path = tmp_path / "blackbox_flight.csv"
    content = """H Product:Blackbox flight data recorder by Nicholas Sherlock
H Data version:2
H Firmware type:Betaflight
H Firmware revision:4.4.2
H Craft name:Tactical-Kamikaze-FPV
H Log start datetime:2026-08-20T14:30:00.000Z
loopIteration,time,axisRate[0],axisRate[1],axisRate[2],vbatLatest,amperageLatest,GPS_fixType,GPS_numSat,GPS_coord[0],GPS_coord[1],GPS_altitude,GPS_speed,GPS_ground_course
0,0,12.5,-4.2,0.5,1680,2500,3,14,312345678,748765432,15000,1850,900
100,100000,15.1,-3.8,1.2,1660,3200,3,15,312348000,748768000,15200,1920,910
200,200000,14.8,-4.0,0.8,1640,3100,3,15,312351000,748771000,15400,2010,920
"""
    log_path.write_text(content, encoding="utf-8")
    return log_path


def test_betaflight_registration(sample_blackbox_csv):
    registered = list_registered_parsers()
    assert "betaflight_blackbox" in registered

    parser = get_parser_for_file(sample_blackbox_csv)
    assert parser is not None
    assert isinstance(parser, BetaflightBlackboxParser)


def test_can_parse_betaflight(tmp_path, sample_blackbox_csv):
    parser = BetaflightBlackboxParser()
    assert parser.can_parse(sample_blackbox_csv) is True

    empty = tmp_path / "empty.csv"
    empty.write_text("")
    assert parser.can_parse(empty) is False


def test_betaflight_extraction_and_telemetry(sample_blackbox_csv):
    parser = BetaflightBlackboxParser()
    events = parser.parse(sample_blackbox_csv)
    assert len(events) >= 4

    store = NormalizedEventStore()
    for ev in events:
        store.add(ev)

    # 1. Metadata
    params = store.by_type(EventType.CONFIG_PARAM.value)
    assert len(params) == 1
    meta = params[0].payload
    assert meta["craft_name"] == "Tactical-Kamikaze-FPV"
    assert meta["firmware_type"] == "Betaflight"
    assert meta["firmware_version"] == "4.4.2"

    # 2. GPS Fixes
    gps_fixes = store.by_type(EventType.GPS_FIX.value)
    assert len(gps_fixes) == 3
    first = gps_fixes[0]
    assert pytest.approx(first.latitude, 0.0001) == 31.2345678
    assert pytest.approx(first.longitude, 0.0001) == 74.8765432
    assert first.altitude_m == 150.0
    assert first.ground_speed_mps == 18.5
    assert first.heading_deg == 90.0
    assert first.satellites_visible == 14
    assert pytest.approx(first.battery_voltage_v, 0.01) == 16.8
    assert pytest.approx(first.battery_current_a, 0.01) == 25.0
    assert first.source_platform == "betaflight"


def test_betaflight_custody_integration(tmp_path, sample_blackbox_csv):
    ledger_path = tmp_path / "custody.jsonl"
    ledger = ChainOfCustodyLedger(ledger_path)

    parser = BetaflightBlackboxParser()
    events = parser.parse(sample_blackbox_csv, custody_ledger=ledger, actor="forensic_officer")

    assert len(ledger) == 1
    ok, broken_at = ledger.verify_chain()
    assert ok is True
    assert broken_at is None
    assert ledger._entries[0].action == "PARSE"

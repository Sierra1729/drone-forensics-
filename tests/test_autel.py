"""
tests/test_autel.py

Unit tests for Autel Robotics CSV flight log parser.
"""

from pathlib import Path
import pytest

from custody.ledger import ChainOfCustodyLedger
from normalize.schema import EventType, NormalizedEventStore
from parsers.base import get_parser_for_file, list_registered_parsers
from parsers.autel import AutelFlightLogParser


@pytest.fixture
def sample_autel_csv(tmp_path) -> Path:
    log_path = tmp_path / "Autel_FlightRecord_001.csv"
    content = """FlyModel,FlyTime,OSD.latitude,OSD.longitude,OSD.height,OSD.speed,OSD.pitch,OSD.roll,OSD.yaw,BATTERY.battery,BATTERY.voltage,GPS.satelliteCount,OSD.flyMode
Autel EVO II Pro 6K,0.0,28.6139,77.2090,12.5,4.2,-1.5,0.8,145.0,98.0,12400,18,GPS
Autel EVO II Pro 6K,1.0,28.6142,77.2094,15.0,6.5,-2.0,1.1,146.0,97.0,12350,18,GPS
Autel EVO II Pro 6K,2.0,28.6145,77.2098,18.2,8.1,-2.5,1.4,148.0,96.0,12300,19,Waypoint
"""
    log_path.write_text(content, encoding="utf-8")
    return log_path


def test_autel_registration(sample_autel_csv):
    registered = list_registered_parsers()
    assert "autel_robotics_csv" in registered

    parser = get_parser_for_file(sample_autel_csv)
    assert parser is not None
    assert isinstance(parser, AutelFlightLogParser)


def test_can_parse_autel(tmp_path, sample_autel_csv):
    parser = AutelFlightLogParser()
    assert parser.can_parse(sample_autel_csv) is True

    empty = tmp_path / "empty.csv"
    empty.write_text("")
    assert parser.can_parse(empty) is False


def test_autel_extraction_and_telemetry(sample_autel_csv):
    parser = AutelFlightLogParser()
    events = parser.parse(sample_autel_csv)
    assert len(events) >= 4

    store = NormalizedEventStore()
    for ev in events:
        store.add(ev)

    # 1. Metadata
    params = store.by_type(EventType.CONFIG_PARAM.value)
    assert len(params) >= 1
    assert params[0].payload.get("aircraft_model") == "Autel EVO II Pro 6K"

    # 2. GPS Fixes
    gps_fixes = store.by_type(EventType.GPS_FIX.value)
    assert len(gps_fixes) == 3
    first = gps_fixes[0]
    assert pytest.approx(first.latitude, 0.0001) == 28.6139
    assert pytest.approx(first.longitude, 0.0001) == 77.2090
    assert first.altitude_m == 12.5
    assert first.ground_speed_mps == 4.2
    assert first.satellites_visible == 18
    assert first.battery_remaining_pct == 98.0
    assert pytest.approx(first.battery_voltage_v, 0.01) == 12.4
    assert first.source_platform == "autel"

    # 3. Mode changes
    modes = store.by_type(EventType.MODE_CHANGE.value)
    assert len(modes) >= 1


def test_autel_custody_integration(tmp_path, sample_autel_csv):
    ledger_path = tmp_path / "autel_custody.jsonl"
    ledger = ChainOfCustodyLedger(ledger_path)

    parser = AutelFlightLogParser()
    events = parser.parse(sample_autel_csv, custody_ledger=ledger, actor="forensic_analyst")

    assert len(ledger) == 1
    ok, broken_at = ledger.verify_chain()
    assert ok is True
    assert broken_at is None


def test_autel_pdf_generation_without_serial(tmp_path, sample_autel_csv):
    from reports.generator import generate_pdf_report, ForensicCaseMetadata
    parser = AutelFlightLogParser()
    events = parser.parse(sample_autel_csv)

    pdf_out = tmp_path / "autel_report.pdf"
    meta = ForensicCaseMetadata(case_id="CASE-AUTEL-CSV-001")
    generated = generate_pdf_report(
        evidence_path=sample_autel_csv,
        events=events,
        metadata=meta,
        output_pdf_path=pdf_out,
    )
    assert generated.exists()
    assert generated.stat().st_size > 5000

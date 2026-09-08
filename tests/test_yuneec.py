"""
tests/test_yuneec.py

Unit tests for Yuneec ST16 telemetry CSV parser.
"""

from pathlib import Path
import pytest

from custody.ledger import ChainOfCustodyLedger
from normalize.schema import EventType, NormalizedEventStore
from parsers.base import get_parser_for_file, list_registered_parsers
from parsers.yuneec import YuneecFlightLogParser


@pytest.fixture
def sample_yuneec_csv(tmp_path) -> Path:
    log_path = tmp_path / "Telemetry_0001.csv"
    content = """GPS_time,f_voltage,f_current,Latitude,Longitude,Altitude,Roll,Pitch,Yaw,f_speed,satellites,gps_status,vehicle_mode
1787200000000,15.2,12.4,12.9716,77.5946,25.0,1.2,-0.8,85.0,7.2,16,3,Angle
1787200001000,15.1,13.1,12.9720,77.5950,28.0,1.5,-1.1,86.0,8.0,16,3,Angle
1787200002000,15.0,14.0,12.9725,77.5955,31.0,1.8,-1.4,87.0,8.5,17,3,ReturnHome
"""
    log_path.write_text(content, encoding="utf-8")
    return log_path


def test_yuneec_registration(sample_yuneec_csv):
    registered = list_registered_parsers()
    assert "yuneec_telemetry_csv" in registered

    parser = get_parser_for_file(sample_yuneec_csv)
    assert parser is not None
    assert isinstance(parser, YuneecFlightLogParser)


def test_can_parse_yuneec(tmp_path, sample_yuneec_csv):
    parser = YuneecFlightLogParser()
    assert parser.can_parse(sample_yuneec_csv) is True

    empty = tmp_path / "empty.csv"
    empty.write_text("")
    assert parser.can_parse(empty) is False


def test_yuneec_extraction_and_telemetry(sample_yuneec_csv):
    parser = YuneecFlightLogParser()
    events = parser.parse(sample_yuneec_csv)
    assert len(events) >= 4

    store = NormalizedEventStore()
    for ev in events:
        store.add(ev)

    # 1. Metadata
    params = store.by_type(EventType.CONFIG_PARAM.value)
    assert len(params) >= 1
    assert params[0].payload.get("aircraft_model") == "Yuneec Typhoon H"

    # 2. GPS Fixes
    gps_fixes = store.by_type(EventType.GPS_FIX.value)
    assert len(gps_fixes) == 3
    first = gps_fixes[0]
    assert pytest.approx(first.latitude, 0.0001) == 12.9716
    assert pytest.approx(first.longitude, 0.0001) == 77.5946
    assert first.altitude_m == 25.0
    assert first.ground_speed_mps == 7.2
    assert first.satellites_visible == 16
    assert pytest.approx(first.battery_voltage_v, 0.01) == 15.2
    assert pytest.approx(first.battery_current_a, 0.01) == 12.4
    assert first.source_platform == "yuneec"

    # 3. Mode changes
    modes = store.by_type(EventType.MODE_CHANGE.value)
    assert len(modes) >= 1


def test_yuneec_custody_integration(tmp_path, sample_yuneec_csv):
    ledger_path = tmp_path / "yuneec_custody.jsonl"
    ledger = ChainOfCustodyLedger(ledger_path)

    parser = YuneecFlightLogParser()
    events = parser.parse(sample_yuneec_csv, custody_ledger=ledger, actor="forensic_analyst")

    assert len(ledger) == 1
    ok, broken_at = ledger.verify_chain()
    assert ok is True
    assert broken_at is None

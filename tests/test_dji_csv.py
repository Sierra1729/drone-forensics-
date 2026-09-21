"""
tests/test_dji_csv.py

Unit test for DJI CSV (CsvView/DatCon/Airdata) flight log parser.
Validates extraction of timestamp, coordinates, altitude, kinematics, and report generation.
"""

from pathlib import Path
import pytest

from custody.ledger import ChainOfCustodyLedger
from normalize.schema import EventType, NormalizedEventStore
from parsers.base import get_parser_for_file, list_registered_parsers
from parsers.dji_csv import DJICSVFlightLogParser
from reports.generator import generate_pdf_report, ForensicCaseMetadata


@pytest.fixture
def sample_dji_csvview(tmp_path) -> Path:
    csv_file = tmp_path / "DJI_CsvView_Export.csv"
    content = """CUSTOM.date [local],CUSTOM.updateTime [local],OSD.flyTime [formatted],OSD.flyTime [s],OSD.latitude,OSD.longitude,OSD.height [ft],OSD.height [m],OSD.vpsHeight [ft],OSD.altitude [ft],OSD.hSpeed [MPH],OSD.hSpeed [m/s],OSD.xSpeed [m/s],OSD.pitch,OSD.roll,OSD.yaw,OSD.flycState [text],BATTERY.chargeLevel [%],BATTERY.voltage [V],GPS.numSats
8/29/2017,10:30:28.9,0m 2.8s,2.8,39.9612,-106.216,0,0,0.7,8128,0,0,0,0,-0.2,-110.2,Manual Takeoff,98,15.2,16
8/29/2017,10:30:29.3,0m 3.2s,3.2,39.9613,-106.216,3.3,1.0,1.2,8131,2.2,1.0,0.5,1.2,-0.1,-110.1,P-GPS,97,15.1,16
8/29/2017,10:30:30.1,0m 4.0s,4.0,39.9615,-106.2158,16.4,5.0,0.0,8144,6.7,3.0,1.8,4.5,0.3,-108.5,P-GPS,96,15.0,17
"""
    csv_file.write_text(content, encoding="utf-8")
    return csv_file


def test_dji_csv_registration():
    registered = list_registered_parsers()
    assert "dji_csv_telemetry" in registered


def test_can_parse_dji_csv(sample_dji_csvview):
    parser = get_parser_for_file(sample_dji_csvview)
    assert parser is not None
    assert isinstance(parser, DJICSVFlightLogParser)


def test_dji_csv_telemetry_extraction(sample_dji_csvview):
    parser = DJICSVFlightLogParser()
    events = parser.parse(sample_dji_csvview)

    assert len(events) >= 4  # 1 config + at least 1 mode change + 3 GPS fixes
    store = NormalizedEventStore()
    for ev in events:
        store.add(ev)

    gps_fixes = store.by_type(EventType.GPS_FIX.value)
    assert len(gps_fixes) == 3

    p1 = gps_fixes[0]
    assert pytest.approx(p1.latitude, 0.0001) == 39.9612
    assert pytest.approx(p1.longitude, 0.0001) == -106.216
    assert p1.pitch_deg == 0.0
    assert p1.roll_deg == -0.2
    assert p1.flight_mode == "Manual Takeoff"
    assert p1.battery_remaining_pct == 98.0
    assert p1.satellites_visible == 16

    p2 = gps_fixes[1]
    assert p2.altitude_m == 1.0
    assert p2.ground_speed_mps == 1.0
    assert p2.flight_mode == "P-GPS"


def test_dji_csv_pdf_generation(tmp_path, sample_dji_csvview):
    parser = DJICSVFlightLogParser()
    events = parser.parse(sample_dji_csvview)

    pdf_out = tmp_path / "dji_csvview_report.pdf"
    meta = ForensicCaseMetadata(case_id="CASE-DJI-CSV-TEST")
    generated = generate_pdf_report(
        evidence_path=sample_dji_csvview,
        events=events,
        metadata=meta,
        output_pdf_path=pdf_out,
    )
    assert generated.exists()
    assert generated.stat().st_size > 5000


def test_dji_csv_user_format_mmss_time_and_extended_telemetry(tmp_path):
    """Test with the exact user CSV layout where time has no hour e.g. 30:28.9."""
    csv_file = tmp_path / "DJIFlightRecord_2017-08-29_[14-30-27] (1).csv"
    content = """CUSTOM.date [local],CUSTOM.updateTime [local],OSD.flyTime [formatted],OSD.flyTime [s],OSD.latitude,OSD.longitude,OSD.height [ft],OSD.height [m],OSD.vpsHeight [ft],OSD.altitude [ft],OSD.hSpeed [MPH],OSD.hSpeed [m/s],OSD.xSpeed [m/s],OSD.xSpeed [MPH],OSD.ySpeed [m/s],OSD.ySpeed [MPH],OSD.zSpeed [m/s],OSD.zSpeed [MPH],OSD.pitch,OSD.roll,OSD.yaw,OSD.yaw [360],OSD.flycState [text]
8/29/2017,30:28.9,0m 2.8s,2.8,39.9612,-106.216,0,0,0.7,8128,0,0,0,0,0,0,0,0,0,-0.2,-110.2,249.8,Manual Takeoff
8/29/2017,30:29.3,0m 3.2s,3.2,39.9612,-106.216,0,0,0.7,8128,0,0,0,0,0,0,0,0,0,-0.2,-110.2,249.8,Manual Takeoff
8/29/2017,30:29.4,0m 3.4s,3.4,39.9612,-106.216,0,0,0.7,8128,0,0,0,0,0,0,0,0,0,-0.2,-110.2,249.8,Manual Takeoff
8/29/2017,30:30.1,0m 4.0s,4.0,39.9612,-106.216,0,0,0.3,8128,1.1,1.1,0,0,0,0,0,0,0,-0.2,-110.2,249.8,P-GPS
"""
    csv_file.write_text(content, encoding="utf-8")

    parser = DJICSVFlightLogParser()
    assert parser.can_parse(csv_file) is True

    events = parser.parse(csv_file)
    # Should extract GPS points and config
    gps_events = [e for e in events if e.event_type == EventType.GPS_FIX.value]
    assert len(gps_events) == 4
    assert pytest.approx(gps_events[0].latitude, 0.0001) == 39.9612
    assert pytest.approx(gps_events[0].longitude, 0.0001) == -106.216

    # Test extract_extended_telemetry
    ext = parser.extract_extended_telemetry(csv_file)
    assert ext is not None
    assert "altitude_chart" in ext
    assert len(ext["altitude_chart"]["times"]) == 4
    assert "attitude_chart" in ext
    assert len(ext["attitude_chart"]["pitch"]) == 4
    assert "power_chart" in ext
    assert "sensor_health_chart" in ext
    assert "summary" in ext
    assert ext["summary"]["hardware"] == "DJI UAV Platform (Flight Record CSV)"


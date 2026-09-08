"""
tests/test_media_extractor.py

Unit tests for Drone Media and MicroSD Carving Parser.
Validates:
1. Extraction of drone serial, model, and GPS from JPEG/DNG imagery with XMP tags.
2. Frame-by-frame GNSS coordinate extraction from companion video subtitle (.srt) files.
3. Chain of custody hash integration.
"""

from pathlib import Path
import pytest

from custody.ledger import ChainOfCustodyLedger
from normalize.schema import EventType, NormalizedEventStore
from parsers.base import get_parser_for_file, list_registered_parsers
from parsers.media_extractor import DroneMediaExtractorParser


@pytest.fixture
def sample_drone_jpeg(tmp_path) -> Path:
    img_path = tmp_path / "DJI_0042.jpg"
    # Create valid synthetic JPEG header with XMP drone metadata payload
    header = b"\xff\xd8\xff\xe1\x01\x00Exif\x00\x00"
    xmp_payload = """<?xpacket begin="" id="W5M0MpCehiHzreSzNTczkc9d"?>
<x:xmpmeta xmlns:x="adobe:ns:meta/">
 <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
  <rdf:Description rdf:about=""
    xmlns:drone-dji="http://www.dji.com/drone/1.0/">
   <drone-dji:DroneModel>DJI Mavic 3 Enterprise</drone-dji:DroneModel>
   <drone-dji:DroneSerialNumber>1581F432A987654</drone-dji:DroneSerialNumber>
   <drone-dji:GpsLatitude>+19.076090</drone-dji:GpsLatitude>
   <drone-dji:GpsLongitude>+72.877720</drone-dji:GpsLongitude>
   <drone-dji:AbsoluteAltitude>+142.50</drone-dji:AbsoluteAltitude>
   <drone-dji:FlightPitchDegree>+1.20</drone-dji:FlightPitchDegree>
   <drone-dji:FlightRollDegree>-0.80</drone-dji:FlightRollDegree>
   <drone-dji:FlightYawDegree>+180.50</drone-dji:FlightYawDegree>
  </rdf:Description>
 </rdf:RDF>
</x:xmpmeta>
2026:08:25 11:30:15
"""
    tail = b"\xff\xd9"
    img_path.write_bytes(header + xmp_payload.encode("latin1") + tail)
    return img_path


@pytest.fixture
def sample_drone_srt(tmp_path) -> Path:
    srt_path = tmp_path / "DJI_0042.srt"
    content = """1
00:00:00,000 --> 00:00:01,000
HOME(72.8770,19.0750) 2026-08-25 11:30:00
GPS(72.8771, 19.0751, 18) BAROMETER: 50.2m
[latitude: 19.0751] [longitude: 72.8771] [altitude: 50.2] [pitch: 0.5] [roll: -0.2] [yaw: 90.0]

2
00:00:01,000 --> 00:00:02,000
HOME(72.8770,19.0750) 2026-08-25 11:30:01
GPS(72.8774, 19.0754, 18) BAROMETER: 55.4m
[latitude: 19.0754] [longitude: 72.8774] [altitude: 55.4] [pitch: 1.0] [roll: -0.1] [yaw: 92.0]

3
00:00:02,000 --> 00:00:03,000
HOME(72.8770,19.0750) 2026-08-25 11:30:02
GPS(72.8778, 19.0758, 19) BAROMETER: 60.1m
[latitude: 19.0758] [longitude: 72.8778] [altitude: 60.1] [pitch: 1.5] [roll: 0.0] [yaw: 95.0]
"""
    srt_path.write_text(content, encoding="utf-8")
    return srt_path


def test_media_parser_registration(sample_drone_jpeg, sample_drone_srt):
    registered = list_registered_parsers()
    assert "drone_media_carver" in registered

    p1 = get_parser_for_file(sample_drone_jpeg)
    assert p1 is not None
    assert isinstance(p1, DroneMediaExtractorParser)

    p2 = get_parser_for_file(sample_drone_srt)
    assert p2 is not None
    assert isinstance(p2, DroneMediaExtractorParser)


def test_jpeg_xmp_carving(sample_drone_jpeg):
    parser = DroneMediaExtractorParser()
    events = parser.parse(sample_drone_jpeg)
    assert len(events) >= 2

    store = NormalizedEventStore()
    for ev in events:
        store.add(ev)

    # 1. Hardware Metadata
    params = store.by_type(EventType.CONFIG_PARAM.value)
    assert len(params) == 1
    meta = params[0].payload
    assert meta["aircraft_model"] == "DJI Mavic 3 Enterprise"
    assert meta["serial_number"] == "1581F432A987654"

    # 2. Coordinates
    gps_fixes = store.by_type(EventType.GPS_FIX.value)
    assert len(gps_fixes) == 1
    fix = gps_fixes[0]
    assert pytest.approx(fix.latitude, 0.0001) == 19.076090
    assert pytest.approx(fix.longitude, 0.0001) == 72.877720
    assert fix.altitude_m == 142.5
    assert pytest.approx(fix.pitch_deg, 0.01) == 1.2
    assert pytest.approx(fix.roll_deg, 0.01) == -0.8
    assert pytest.approx(fix.yaw_deg, 0.01) == 180.5


def test_video_srt_telemetry_extraction(sample_drone_srt):
    parser = DroneMediaExtractorParser()
    events = parser.parse(sample_drone_srt)
    assert len(events) == 3

    store = NormalizedEventStore()
    for ev in events:
        store.add(ev)

    gps_fixes = store.by_type(EventType.GPS_FIX.value)
    assert len(gps_fixes) == 3
    first = gps_fixes[0]
    assert pytest.approx(first.latitude, 0.0001) == 19.0751
    assert pytest.approx(first.longitude, 0.0001) == 72.8771
    assert first.altitude_m == 50.2
    assert first.satellites_visible == 18

    last = gps_fixes[-1]
    assert pytest.approx(last.latitude, 0.0001) == 19.0758
    assert pytest.approx(last.longitude, 0.0001) == 72.8778
    assert last.altitude_m == 60.1


def test_media_custody_integration(tmp_path, sample_drone_jpeg):
    ledger_path = tmp_path / "media_custody.jsonl"
    ledger = ChainOfCustodyLedger(ledger_path)

    parser = DroneMediaExtractorParser()
    events = parser.parse(sample_drone_jpeg, custody_ledger=ledger, actor="forensic_officer")

    assert len(ledger) == 1
    ok, broken_at = ledger.verify_chain()
    assert ok is True
    assert broken_at is None
    assert ledger._entries[0].action == "PARSE"

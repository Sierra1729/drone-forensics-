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


def test_dji_onboard_fly182_dat_can_parse_and_telemetry(tmp_path):
    """Test official DJI Onboard FLY182.DAT detection and DatCon telemetry decoding."""
    import struct
    import math

    fly_file = tmp_path / "FLY182.DAT"
    chunks = []

    # 1. DJI Onboard BUILD banner header
    header = b"BUILD 2018-09-12 14:32:10 DJI Mavic 2 Pro Flight Recorder V01.00.0100\r\n\x00" * 2
    chunks.append(header.ljust(256, b"\x00"))

    # 2. Add DatCon Onboard GPS frames (0x55 sync, len, sub, crc, msg_type)
    # DatCon GPS: msg_type = 42
    base_lat = 28.6139  # New Delhi
    base_lon = 77.2090
    for i in range(8):
        # Pack payload: offset_ms (uint32), lat (double in radians), lon (double in radians), alt (float), spd (float)
        offset_ms = (i + 1) * 1000
        lat_rad = math.radians(base_lat + (i * 0.0003))
        lon_rad = math.radians(base_lon + (i * 0.0003))
        alt = 35.0 + (i * 2.5)
        spd = 11.4
        hdg = 45.0
        payload = struct.pack("<Iddfff", offset_ms, lat_rad, lon_rad, alt, spd, hdg)

        # DatCon frame: 0x55, frame_len, sub, crc, msg_type(uint16), payload
        frame_len = 6 + len(payload)
        sub = 0x00
        crc = 0x55 ^ frame_len ^ sub
        msg_type = 42
        frame_hdr = struct.pack("<BBBBH", 0x55, frame_len, sub, crc, msg_type)
        chunks.append(frame_hdr + payload)

    # 3. Add DatCon Battery frame (msg_type = 50)
    batt_payload = struct.pack("<IHhB", 2000, 15200, -8500, 88)
    frame_len = 6 + len(batt_payload)
    crc = 0x55 ^ frame_len ^ 0x00
    frame_hdr = struct.pack("<BBBBH", 0x55, frame_len, 0x00, crc, 50)
    chunks.append(frame_hdr + batt_payload)

    fly_file.write_bytes(b"".join(chunks))

    parser = DJIFlightLogParser()
    assert parser.can_parse(fly_file) is True

    events = parser.parse(fly_file)
    assert len(events) >= 9

    # Verify metadata
    config_events = [e for e in events if e.event_type == EventType.CONFIG_PARAM.value]
    assert len(config_events) >= 1
    assert "Mavic" in config_events[0].payload.get("aircraft_model", "")

    # Verify GPS coordinates converted correctly from radians to degrees
    gps_events = [e for e in events if e.event_type == EventType.GPS_FIX.value]
    assert len(gps_events) == 8
    first_gps = gps_events[0]
    assert pytest.approx(first_gps.latitude, 0.001) == 28.6139
    assert pytest.approx(first_gps.longitude, 0.001) == 77.2090
    assert first_gps.altitude_m > 30.0
    assert first_gps.ground_speed_mps == 11.4

    # Verify Battery
    bats = [e for e in events if e.event_type == EventType.BATTERY_STATE.value]
    assert len(bats) == 1
    assert bats[0].battery_voltage_v == 15.2
    assert bats[0].battery_remaining_pct == 88.0


def test_dji_onboard_fly_file_in_gui_api(tmp_path):
    """Verify FLYxxx.DAT end-to-end ingestion in DesktopForensicAPI."""
    import struct
    from gui.api import DesktopForensicAPI

    fly_file = tmp_path / "FLY182.DAT"
    chunks = []
    chunks.append(b"BUILD 2020-03-10 DJI Phantom 4 Pro V2.0\x00".ljust(128, b"\x00"))

    # Scaled integer coordinates (1e7)
    for i in range(5):
        offset_ms = (i + 1) * 1000
        lat_int = int((19.0760 + i * 0.0002) * 1e7)
        lon_int = int((72.8777 + i * 0.0002) * 1e7)
        alt_mm = int((40.0 + i * 1.5) * 1000)
        payload = struct.pack("<Iiii", offset_ms, lat_int, lon_int, alt_mm)

        frame_len = 6 + len(payload)
        crc = 0x55 ^ frame_len ^ 0x00
        frame_hdr = struct.pack("<BBBBH", 0x55, frame_len, 0x00, crc, 42)
        chunks.append(frame_hdr + payload)

    fly_file.write_bytes(b"".join(chunks))

    api = DesktopForensicAPI()
    api.output_dir = tmp_path / "output"

    res = api.analyze_evidence(str(fly_file), case_id="CASE-FLY182-TEST", examiner="Inspector Cyber")
    assert res["status"] == "success"
    assert res["parser_name"] == "dji_flight_log"
    assert len(res["coords"]) == 5
    assert pytest.approx(res["coords"][0]["lat"], 0.001) == 19.0760
    assert pytest.approx(res["coords"][0]["lon"], 0.001) == 72.8777
    assert Path(res["pdf_path"]).exists()
    assert "extended_telemetry" in res
    assert "summary" in res["extended_telemetry"]


def test_dji_extract_extended_telemetry(tmp_path):
    """Test extract_extended_telemetry contract for DJI parser."""
    import struct
    import math

    fly_file = tmp_path / "FLY_TEST.DAT"
    chunks = []
    chunks.append(b"BUILD 2020-04-15 DJI Mavic 2 Pro\x00".ljust(512, b"\x00"))

    # Add 2048 packets (DJI V3 telemetry)
    for i in range(20):
        tick = (i + 1) * 200000
        key = tick % 256
        lon_r = math.radians(6.567 + i * 0.0001)
        lat_r = math.radians(46.521 + i * 0.0001)
        alt = 330.0 + i * 1.5
        vx = 1.2
        vy = 0.8
        vz = -0.5
        p_r = math.radians(5.0)
        r_r = math.radians(2.0)
        y_r = math.radians(45.0)
        baro_a = alt + 0.2

        pl_raw = struct.pack("<ddffffffff", lon_r, lat_r, alt, vx, vy, vz, p_r, r_r, y_r, baro_a)
        # Pad payload to 48 bytes
        pl_raw = pl_raw.ljust(48, b"\x00")
        pl_scrambled = bytes([b ^ key for b in pl_raw])

        flen = 10 + len(pl_scrambled)
        hdr = struct.pack("<BBBBHI", 0x55, flen, 0, 0, 2048, tick)
        chunks.append(hdr + pl_scrambled)

    # Add message packet (32768)
    msg_raw = b"{root}INFO:motors armed for takeoff\x00"
    tick = 500000
    key = tick % 256
    msg_scrambled = bytes([b ^ key for b in msg_raw])
    flen = 10 + len(msg_scrambled)
    hdr = struct.pack("<BBBBHI", 0x55, flen, 0, 0, 32768, tick)
    chunks.append(hdr + msg_scrambled)

    fly_file.write_bytes(b"".join(chunks))

    parser = DJIFlightLogParser()
    ext = parser.extract_extended_telemetry(fly_file)

    assert ext is not None
    assert "summary" in ext
    assert ext["summary"]["hardware"] == "DJI Mavic 2 Pro"
    assert "altitude_chart" in ext
    assert len(ext["altitude_chart"]["times"]) >= 15
    assert "attitude_chart" in ext
    assert "velocity_chart" in ext
    assert "power_chart" in ext
    assert "sensor_health_chart" in ext
    assert len(ext["logged_messages"]) >= 1
    assert any("motors armed" in m["message"].lower() for m in ext["logged_messages"])
    assert len(ext["parameters_table"]) >= 10



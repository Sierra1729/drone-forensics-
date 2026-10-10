"""
tests/test_adb_parser.py

Tests for AndroidADBExtractorParser:
- Android Backup (.ab)
- Android Logcat telemetry (.log / .logcat)
- Android Dumpsys hardware extraction (.txt / .dump)
"""

import zlib
import tarfile
import io
from pathlib import Path
from normalize.schema import EventType
from parsers.adb_parser import AndroidADBExtractorParser, SIG_ANDROID_BACKUP
from parsers.base import get_parser_for_file


def test_adb_parser_registration():
    parser = AndroidADBExtractorParser()
    assert parser.parser_name == "AndroidADBExtractorParser"
    assert "android" in parser.supported_platforms
    assert parser.parser_version == "1.0.0"


def test_parse_android_backup(tmp_path: Path):
    ab_file = tmp_path / "drone_backup.ab"
    
    # Create an unencrypted, zlib-compressed tar stream
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w") as tar:
        ti = tarfile.TarInfo("apps/dji.go.v4/f/FlightRecord/DJIFlightRecord.txt")
        ti.size = 12
        tar.addfile(ti, io.BytesIO(b"LOG_PAYLOAD_"))
    tar_bytes = tar_buf.getvalue()
    compressed_tar = zlib.compress(tar_bytes)

    # Header: ANDROID BACKUP\n1\n1\nnone\n
    header = b"ANDROID BACKUP\n1\n1\nnone\n" + compressed_tar
    ab_file.write_bytes(header)

    parser = AndroidADBExtractorParser()
    assert parser.can_parse(ab_file)
    events = parser.parse(ab_file)
    assert len(events) >= 1
    acq_events = [e for e in events if e.event_type == EventType.MOBILE_APP_ARTIFACT.value]
    assert len(acq_events) >= 1
    assert acq_events[0].payload["format"] == "Android ADB Backup Archive"


def test_parse_android_logcat(tmp_path: Path):
    logcat_file = tmp_path / "adb_logcat.log"
    content = (
        "--------- beginning of main\n"
        "01-15 14:22:01.120 1845 2130 D DJIFlightController: LAT: 28.6139, LON: 77.2090, ALT: 35.4m, SATS: 18\n"
        "01-15 14:22:05.340 1845 2130 I DJIFlightController: Home point recorded at 28.6139, 77.2090\n"
        "01-15 14:22:12.890 1845 2130 W DJIBattery: Battery level at 84%, Voltage: 15.2V\n"
        "01-15 14:23:45.100 1845 2130 D DJIFlightController: LAT: 28.6155, LON: 77.2115, ALT: 58.2m, SATS: 19\n"
        "01-15 14:25:10.500 1845 2130 I DJIFlightController: Landing command executed by pilot.\n"
    )
    logcat_file.write_text(content, encoding="utf-8")

    parser = AndroidADBExtractorParser()
    assert parser.can_parse(logcat_file)
    events = parser.parse(logcat_file)
    assert len(events) >= 4

    gps_events = [e for e in events if e.event_type == EventType.GPS_FIX.value]
    assert len(gps_events) == 2
    assert abs(gps_events[0].latitude - 28.6139) < 1e-4
    assert abs(gps_events[0].longitude - 77.2090) < 1e-4

    home_events = [e for e in events if e.event_type == EventType.APP_COMMAND.value]
    assert len(home_events) == 1

    bat_events = [e for e in events if e.event_type == EventType.BATTERY_STATE.value]
    assert len(bat_events) == 1
    assert bat_events[0].battery_remaining_pct == 84.0


def test_parse_android_dumpsys(tmp_path: Path):
    dumpsys_file = tmp_path / "adb_dumpsys.txt"
    content = (
        "DUMP OF SERVICE package:\n"
        "ro.serialno=1581F4QXB23001\n"
        "ro.product.model=DJI Smart Controller RM500\n"
        "ro.build.display.id=DJI-SC-V01.00.0820\n"
        "Package [dji.go.v4] (123456):\n"
        "Package [com.dji.industry.pilot] (789012):\n"
    )
    dumpsys_file.write_text(content, encoding="utf-8")

    parser = AndroidADBExtractorParser()
    assert parser.can_parse(dumpsys_file)
    events = parser.parse(dumpsys_file)
    assert len(events) == 1
    assert events[0].event_type == EventType.SYSTEM_STATUS.value
    assert events[0].payload["hardware_serial"] == "1581F4QXB23001"
    assert "DJI Smart Controller" in events[0].payload["hardware_model"]

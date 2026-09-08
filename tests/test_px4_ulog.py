"""
tests/test_px4_ulog.py

Comprehensive test suite for the PX4 Autopilot ULog (.ulg) forensic parser.
Validates:
1. ULog file magic byte detection.
2. Parser registration and plugin dispatch.
3. Metadata, parameter, and telemetry extraction.
4. Chain of custody hash-chain integration.
"""

import struct
from pathlib import Path
import pytest
import pyulog

from custody.ledger import ChainOfCustodyLedger
from parsers.base import get_parser_for_file, list_registered_parsers
from parsers.px4_ulog import PX4ULogParser


@pytest.fixture
def sample_ulog(tmp_path) -> Path:
    ulog_file = tmp_path / "flight_log.ulg"
    # Write a valid ULog header
    # HEADER_BYTES (7 bytes) + version (1 byte) + timestamp (uint64 8 bytes) = 16 bytes
    header = pyulog.ULog.HEADER_BYTES + b"\x01" + struct.pack("<Q", 1_700_000_000_000_000)
    ulog_file.write_bytes(header)
    return ulog_file


def test_px4_parser_registration(sample_ulog):
    registered = list_registered_parsers()
    assert "px4_ulog" in registered

    parser = get_parser_for_file(sample_ulog)
    assert parser is not None
    assert isinstance(parser, PX4ULogParser)


def test_can_parse_ulog(tmp_path, sample_ulog):
    parser = PX4ULogParser()
    assert parser.can_parse(sample_ulog) is True

    # Empty file
    empty = tmp_path / "empty.ulg"
    empty.write_bytes(b"")
    assert parser.can_parse(empty) is False

    # Irrelevant file
    bogus = tmp_path / "not_ulog.bin"
    bogus.write_bytes(b"BOGUS_FILE_HEADER")
    assert parser.can_parse(bogus) is False


def test_px4_ulog_parsing_and_custody(tmp_path, sample_ulog):
    ledger_path = tmp_path / "px4_custody.jsonl"
    ledger = ChainOfCustodyLedger(ledger_path)

    parser = PX4ULogParser()
    events = parser.parse(sample_ulog, custody_ledger=ledger, actor="inspector_jadhav")

    # Should at least extract the configuration/metadata event from the header
    assert len(events) >= 1
    assert events[0].source_platform == "px4"

    # Ledger must record the PARSE action
    assert len(ledger) == 1
    ok, broken_at = ledger.verify_chain()
    assert events[0].source_file_sha256 == ledger._entries[0].target_sha256


def test_px4_null_island_filtering():
    parser = PX4ULogParser()
    download_file = Path(r"C:\Users\pawan\Downloads\4c0030a3-fcb9-4252-968a-11256166c543.ulg")
    if download_file.exists():
        events = parser.parse(download_file)
        gps_events = [e for e in events if e.event_type == "gps_fix" and e.latitude is not None]
        assert len(gps_events) > 0
        # Ensure zero Null Island (0,0) coordinates exist
        for ev in gps_events:
            assert not (abs(ev.latitude) < 0.0001 and abs(ev.longitude) < 0.0001)
        # Ensure first point is in the real flight area, not in the Atlantic Ocean
        assert abs(gps_events[0].latitude) > 10.0
        assert abs(gps_events[0].longitude) > 50.0


def test_px4_extended_telemetry_extraction():
    parser = PX4ULogParser()
    sample_file = Path("sample_evidence/real_px4_flight.ulg")
    if sample_file.exists():
        ext = parser.extract_extended_telemetry(sample_file)
        assert isinstance(ext, dict)
        assert "summary" in ext
        assert "altitude_chart" in ext
        assert "attitude_chart" in ext
        assert "velocity_chart" in ext
        assert "power_chart" in ext
        assert "actuator_chart" in ext
        assert "sensor_health_chart" in ext
        assert "logged_messages" in ext
        assert "parameters_table" in ext

        assert len(ext["altitude_chart"]["times"]) > 0
        assert len(ext["attitude_chart"]["times"]) > 0
        assert len(ext["velocity_chart"]["times"]) > 0
        assert len(ext["power_chart"]["times"]) > 0
        assert len(ext["sensor_health_chart"]["times"]) > 0
        assert len(ext["parameters_table"]) > 0



"""Unit tests for resilient binary carving and partial-read parsing of corrupted UAV flight logs.

Tests PX4 ULog parser's ability to salvage valid telemetry from abruptly truncated
or corrupt flight logs (e.g. mid-flight power disconnect or crash) and flag
DATA_TRUNCATION_OR_CORRUPTION anomalies.
"""
import os
import sys
import struct
import tempfile
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from parsers.px4_ulog import PX4ULogParser
from parsers.base import NormalizedEvent
from normalize.schema import EventType



def create_synthetic_truncated_ulog(num_data_records=20, truncate_mid_packet=True) -> bytes:
    """Build a synthetically valid binary ULog stream and truncate it before EOF."""
    # 1. 16-byte ULog Magic Header: Magic(7B) + Version(1B) + Timestamp(8B)
    magic_header = b"\x55\x4C\x6F\x67\x01\x12\x35" + b"\x01" + struct.pack("<Q", 1700000000000000)

    # 2. Format Definition ('F'): vehicle_gps_position
    # Format definition string: "vehicle_gps_position:uint64_t timestamp;int32_t lat;int32_t lon;int32_t alt;float vel_m_s;"
    format_str = b"vehicle_gps_position:uint64_t timestamp;int32_t lat;int32_t lon;int32_t alt;float vel_m_s;"
    fmt_msg = struct.pack("<HB", len(format_str), ord("F")) + format_str

    # 3. Format Definition ('F'): battery_status
    bat_format_str = b"battery_status:uint64_t timestamp;float voltage_v;float current_a;float remaining;"
    bat_fmt_msg = struct.pack("<HB", len(bat_format_str), ord("B")) + bat_format_str  # Note: msg_type 'F' is standard

    # 4. Subscription Definition ('A'): message_id 0 -> vehicle_gps_position, multi_id 0
    # Add subscription struct: <HB (size, type) + B (multi_id) + H (msg_id) + string (format_name)
    sub_payload = struct.pack("<BH", 0, 0) + b"vehicle_gps_position"
    sub_msg = struct.pack("<HB", len(sub_payload), ord("A")) + sub_payload

    stream = magic_header + fmt_msg + sub_msg

    # 5. Add N Data ('D') packets
    base_time = 1700000000000000
    base_lat = int(28.6139 * 1e7)
    base_lon = int(77.2090 * 1e7)
    base_alt = 150000  # mm

    for i in range(num_data_records):
        t_us = base_time + (i * 100000)  # 10 Hz
        lat = base_lat + (i * 100)
        lon = base_lon + (i * 100)
        alt = base_alt + (i * 500)
        vel = 12.5 + (i * 0.1)

        data_payload = struct.pack("<H", 0) + struct.pack("<Qiiif", t_us, lat, lon, alt, vel)
        d_msg = struct.pack("<HB", len(data_payload), ord("D")) + data_payload
        stream += d_msg

    # 6. Apply Truncation
    if truncate_mid_packet:
        # Cut off the last packet in the middle of its payload
        stream = stream[:-12]
    else:
        # Cut off the last 5 packets cleanly
        stream = stream[:-100]

    return stream


def test_corrupted_ulog_binary_carving():
    """Verify that PX4ULogParser salvages intact telemetry from a truncated ULog and flags corruption."""
    raw_data = create_synthetic_truncated_ulog(num_data_records=25, truncate_mid_packet=True)

    with tempfile.NamedTemporaryFile(suffix=".ulg", delete=False) as f:
        f.write(raw_data)
        temp_path = f.name

    try:
        parser = PX4ULogParser()
        assert parser.can_parse(temp_path) is True

        events = parser.parse(temp_path)

        # Verify corruption flags
        assert parser.is_corrupted is True
        assert parser.corruption_offset is not None
        assert parser.corruption_offset > 0
        assert parser.salvaged_records_count > 0

        # Verify salvaged events
        gps_events = [e for e in events if e.latitude is not None and e.longitude is not None]
        assert len(gps_events) >= 20  # At least 20 intact packets salvaged
        assert gps_events[0].latitude is not None
        assert pytest.approx(gps_events[0].latitude, abs=1e-4) == 28.6139
        assert pytest.approx(gps_events[0].longitude, abs=1e-4) == 77.2090

        # Verify anomaly event is injected into timeline
        anomaly_events = [e for e in events if e.event_type in ("forensic_anomaly", "ANOMALY", "anomaly", EventType.FORENSIC_ANOMALY.value)]
        assert len(anomaly_events) >= 1
        corruption_anomaly = next((e for e in anomaly_events if e.payload.get("anomaly_type") == "DATA_TRUNCATION_OR_CORRUPTION" or e.payload.get("anomaly_indicator") == "DATA_TRUNCATION_OR_CORRUPTION"), None)
        assert corruption_anomaly is not None
        assert "corruption_offset" in corruption_anomaly.payload
        assert corruption_anomaly.payload["salvaged_records"] == parser.salvaged_records_count

    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_severely_truncated_ulog_header_only():
    """Verify that a ULog file cut off right after the header doesn't crash and reports 0 salvaged."""
    header_only = b"\x55\x4C\x6F\x67\x01\x12\x35" + b"\x01" + struct.pack("<Q", 1700000000000000)

    with tempfile.NamedTemporaryFile(suffix=".ulg", delete=False) as f:
        f.write(header_only)
        temp_path = f.name

    try:
        parser = PX4ULogParser()
        events = parser.parse(temp_path)

        assert parser.is_corrupted is True
        gps_events = [e for e in events if e.latitude is not None]
        assert len(gps_events) == 0
        anomaly_events = [e for e in events if e.event_type in ("forensic_anomaly", "ANOMALY", "anomaly", EventType.FORENSIC_ANOMALY.value)]
        assert len(anomaly_events) >= 1
        assert (anomaly_events[0].payload.get("anomaly_type") == "DATA_TRUNCATION_OR_CORRUPTION" or
                anomaly_events[0].payload.get("anomaly_indicator") == "DATA_TRUNCATION_OR_CORRUPTION")
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)



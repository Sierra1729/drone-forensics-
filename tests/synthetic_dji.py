"""
tests/synthetic_dji.py

Synthetic DJI Flight Record generator for deterministic forensic test suites.
Produces byte-accurate binary flight records adhering to the DJI mobile
flight record structure.
"""

from __future__ import annotations

import struct
from pathlib import Path

from parsers.dji import (
    DJI_HEADER_MAGIC,
    DJI_FRAME_SYNC,
    DJI_FRAME_END,
    REC_OSD,
    REC_HOME,
    REC_BATTERY,
    REC_EVENT,
)


def pack_frame(rec_type: int, payload: bytes) -> bytes:
    """Pack a single DJI record frame."""
    header = bytes([DJI_FRAME_SYNC, rec_type, len(payload)])
    return header + payload + bytes([DJI_FRAME_END])


def generate_synthetic_dji_log(output_path: Path) -> Path:
    """Generate a realistic DJI flight record log.

    Flight scenario:
    - Header: DJI Mavic 3 Enterprise, S/N: 1581F4GBD210001
    - Home Point Set: 19.0760° N, 72.8777° E, RTH Alt: 30m
    - Armed message
    - 10 OSD telemetry frames (P-GPS mode, ascending to 45m, speed 14.2 m/s, 18 sats)
    - 10 Battery frames (voltage 15.4V down to 13.8V, current 14.5A)
    - Low Battery warning & Auto RTH trigger event
    - RTH flight mode transition
    - Disarm event
    """
    chunks: list[bytes] = []

    # 1. 100-byte File Header
    magic = DJI_HEADER_MAGIC + b"6.0\x00"  # 16 bytes
    aircraft_model = b"DJI Mavic 3 Enterprise\x00"  # 32 bytes
    serial_no = b"1581F4GBD210001\x00"  # 16 bytes
    start_time_epoch_ms = 1756641600000  # Epoch ms (~Aug 2025)
    total_dist = 1450.5
    total_time = 360.0

    header_body = struct.pack(
        "<16s32s16sQff",
        magic,
        aircraft_model,
        serial_no,
        start_time_epoch_ms,
        total_dist,
        total_time,
    )
    # Pad to exactly 100 bytes
    header = header_body.ljust(100, b"\x00")
    chunks.append(header)

    # 2. Home Point Frame (Offset 0 ms)
    # "<ddfI"
    home_payload = struct.pack("<ddfI", 19.0760, 72.8777, 30.0, 0)
    chunks.append(pack_frame(REC_HOME, home_payload))

    # 3. Armed Event Frame (Offset 500 ms)
    # "<B64sI"
    arm_payload = struct.pack("<B64sI", 1, b"Motors Armed: Ready for flight\x00", 500)
    chunks.append(pack_frame(REC_EVENT, arm_payload))

    # 4. Telemetry Trajectory (10 Waypoints)
    base_lat = 19.0760
    base_lng = 72.8777

    for i in range(10):
        offset_ms = (i + 1) * 1000  # 1000ms intervals
        lat = base_lat + (i * 0.0004)
        lng = base_lng + (i * 0.0004)
        alt = 5.0 + (i * 4.0)
        spd = 14.2
        heading = 90.0
        pitch = -2.5
        roll = 1.0
        yaw = 89.8
        mode_str = b"P-GPS\x00" if i < 7 else b"RTH\x00"
        batt_pct = max(15, 95 - (i * 8))
        sat_count = 18
        hdop = 0.6

        # Pack OSD: "<ddffffff16sBBfI"
        osd_payload = struct.pack(
            "<ddffffff16sBBfI",
            lat,
            lng,
            alt,
            spd,
            heading,
            pitch,
            roll,
            yaw,
            mode_str,
            batt_pct,
            sat_count,
            hdop,
            offset_ms,
        )
        chunks.append(pack_frame(REC_OSD, osd_payload))

        # Pack Battery: "<ffffI"
        volt = 15.4 - (i * 0.16)
        curr = 14.5
        rem_pct = float(batt_pct)
        temp_c = 34.0 + (i * 0.3)
        bat_payload = struct.pack("<ffffI", volt, curr, rem_pct, temp_c, offset_ms)
        chunks.append(pack_frame(REC_BATTERY, bat_payload))

    # 5. Low Battery Warning & Auto RTH Event (Offset 7500 ms)
    rth_payload = struct.pack("<B64sI", 2, b"Low Battery Warning: Auto Return-To-Home Initiated\x00", 7500)
    chunks.append(pack_frame(REC_EVENT, rth_payload))

    # 6. Disarm Event (Offset 12000 ms)
    disarm_payload = struct.pack("<B64sI", 3, b"Motors Disarmed\x00", 12000)
    chunks.append(pack_frame(REC_EVENT, disarm_payload))

    data = b"".join(chunks)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(data)
    return output_path

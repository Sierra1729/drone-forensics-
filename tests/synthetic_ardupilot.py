"""
tests/synthetic_ardupilot.py

Synthetic ArduPilot DataFlash (.BIN) flight log generator for deterministic
forensic test suites and CI/CD pipelines.

Generates byte-accurate binary logs conforming to the ArduPilot DataFlash
specification (FMT declarations + binary telemetry records).
"""

from __future__ import annotations

import struct
from pathlib import Path

HEAD1 = 0xA3
HEAD2 = 0x95
FMT_TYPE = 0x80

# Message type IDs
TYPE_PARM = 0x81
TYPE_GPS = 0x02
TYPE_ATT = 0x03
TYPE_BAT = 0x04
TYPE_MODE = 0x05
TYPE_MSG = 0x06


def pack_fmt(msg_type: int, msg_len: int, name: str, fmt_str: str, labels: str) -> bytes:
    """Pack an 89-byte FMT declaration packet."""
    header = bytes([HEAD1, HEAD2, FMT_TYPE])
    payload = struct.pack(
        "<BB4s16s64s",
        msg_type,
        msg_len,
        name.encode("ascii"),
        fmt_str.encode("ascii"),
        labels.encode("ascii"),
    )
    return header + payload


def generate_synthetic_ardupilot_bin(output_path: Path) -> Path:
    """Create a realistic ArduPilot mission flight log.

    Simulated flight profile:
    - Boot & parameter initialization
    - Mode change to AUTO
    - Arming text message
    - GPS travel trail (starting at Mumbai / IIT Bombay: 19.0760° N, 72.8777° E)
    - Attitude pitch/roll adjustments
    - Battery discharge from 12.6V down to 10.4V
    - Low Battery Failsafe trigger -> Mode change to RTL (Return To Home)
    - Disarm text message
    """
    chunks: list[bytes] = []

    # 1. FMT Declarations
    # PARM: TimeUS(Q), Name(N=16s), Value(f) -> 3 + 28 = 31 bytes
    chunks.append(pack_fmt(TYPE_PARM, 31, "PARM", "QNf", "TimeUS,Name,Value"))

    # GPS: TimeUS(Q), Status(B), GMS(I), GWk(H), NSats(B), HDop(C), Lat(L), Lng(L), Alt(f), Spd(f), GCrs(f)
    # Payload size: 8 + 1 + 4 + 2 + 1 + 2 + 4 + 4 + 4 + 4 + 4 = 38 bytes -> 3 + 38 = 41 bytes
    chunks.append(pack_fmt(TYPE_GPS, 41, "GPS", "QBIHBCLLfff", "TimeUS,Status,GMS,GWk,NSats,HDop,Lat,Lng,Alt,Spd,GCrs"))

    # ATT: TimeUS(Q), Roll(f), Pitch(f), Yaw(f) -> 3 + 20 = 23 bytes
    chunks.append(pack_fmt(TYPE_ATT, 23, "ATT", "Qfff", "TimeUS,Roll,Pitch,Yaw"))

    # BAT: TimeUS(Q), Volt(f), Curr(f), RemPct(B) -> 3 + 17 = 20 bytes
    chunks.append(pack_fmt(TYPE_BAT, 20, "BAT", "QffB", "TimeUS,Volt,Curr,RemPct"))

    # MODE: TimeUS(Q), Mode(N=16s) -> 3 + 24 = 27 bytes
    chunks.append(pack_fmt(TYPE_MODE, 27, "MODE", "QN", "TimeUS,Mode"))

    # MSG: TimeUS(Q), Message(Z=64s) -> 3 + 72 = 75 bytes
    chunks.append(pack_fmt(TYPE_MSG, 75, "MSG", "QZ", "TimeUS,Message"))

    # 2. Flight Parameters (at boot, TimeUS = 100_000)
    p1_payload = struct.pack("<Q16sf", 100_000, b"PILOT_SPEED_UP", 250.0)
    chunks.append(bytes([HEAD1, HEAD2, TYPE_PARM]) + p1_payload)

    p2_payload = struct.pack("<Q16sf", 120_000, b"RTL_ALT", 1500.0)
    chunks.append(bytes([HEAD1, HEAD2, TYPE_PARM]) + p2_payload)

    # 3. Mode Change -> AUTO (TimeUS = 500_000)
    mode_payload = struct.pack("<Q16s", 500_000, b"AUTO\x00")
    chunks.append(bytes([HEAD1, HEAD2, TYPE_MODE]) + mode_payload)

    # 4. MSG -> Arming motors (TimeUS = 600_000)
    msg_arm = struct.pack("<Q64s", 600_000, b"Arming motors: Pre-arm checks PASSED\x00")
    chunks.append(bytes([HEAD1, HEAD2, TYPE_MSG]) + msg_arm)

    # 5. GPS, ATT, BAT Flight Trajectory (10 consecutive waypoints)
    # GPS Week = 2350, GMS starting at 100_000_000 (100,000 seconds)
    gwk = 2350
    base_gms = 100_000_000
    base_time_us = 1_000_000  # 1.0s after boot

    base_lat = 19.0760
    base_lng = 72.8777
    base_alt = 10.0
    base_volt = 12.6

    for i in range(10):
        t_us = base_time_us + (i * 1_000_000)  # 1 second increments
        gms = base_gms + (i * 1000)
        lat_scaled = int((base_lat + (i * 0.0005)) * 1e7)
        lng_scaled = int((base_lng + (i * 0.0005)) * 1e7)
        alt = base_alt + (i * 10.0)
        speed = 12.5
        gcrs = 45.0
        nsats = 14
        hdop_scaled = 80  # 80 * 0.01 = 0.8 HDOP
        status = 3  # 3D Fix

        # Pack GPS
        # ArduPilot format: Q(Q), B(B), I(I), H(H), B(B), H(H), i(i), i(i), f(f), f(f), f(f)
        gps_payload = struct.pack(
            "<QBIHBHiifff",
            t_us,
            status,
            gms,
            gwk,
            nsats,
            hdop_scaled,
            lat_scaled,
            lng_scaled,
            alt,
            speed,
            gcrs,
        )
        chunks.append(bytes([HEAD1, HEAD2, TYPE_GPS]) + gps_payload)

        # Pack ATT (Roll, Pitch, Yaw)
        att_payload = struct.pack("<Qfff", t_us, 1.2, -0.8, 45.0 + i)
        chunks.append(bytes([HEAD1, HEAD2, TYPE_ATT]) + att_payload)

        # Pack BAT
        volt = base_volt - (i * 0.22)
        curr = 18.5
        rem_pct = max(10, 100 - (i * 9))
        bat_payload = struct.pack("<QffB", t_us, volt, curr, rem_pct)
        chunks.append(bytes([HEAD1, HEAD2, TYPE_BAT]) + bat_payload)

    # 6. Failsafe Battery Trigger -> Mode change to RTL (TimeUS = 11_500_000)
    msg_fs = struct.pack("<Q64s", 11_500_000, b"Failsafe: Low Battery (10.4V) triggered RTL\x00")
    chunks.append(bytes([HEAD1, HEAD2, TYPE_MSG]) + msg_fs)

    mode_rtl = struct.pack("<Q16s", 11_600_000, b"RTL\x00")
    chunks.append(bytes([HEAD1, HEAD2, TYPE_MODE]) + mode_rtl)

    # 7. Disarm message (TimeUS = 15_000_000)
    msg_disarm = struct.pack("<Q64s", 15_000_000, b"Disarming motors after landing\x00")
    chunks.append(bytes([HEAD1, HEAD2, TYPE_MSG]) + msg_disarm)

    data = b"".join(chunks)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(data)
    return output_path

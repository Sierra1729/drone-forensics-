"""
tests/synthetic_tlog.py

Synthetic MAVLink Telemetry (.tlog) generator for forensic test suites.
"""

from __future__ import annotations

import struct
import time
from pathlib import Path
from pymavlink.dialects.v20 import common as mavlink2


def generate_synthetic_tlog(output_path: Path) -> Path:
    """Generate a valid MAVLink .tlog file containing telemetry frames."""
    mav = mavlink2.MAVLink(None)
    chunks: list[bytes] = []
    base_t_us = int(time.time() * 1e6)

    # Helper to pack a message with a 64-bit big-endian timestamp prefix (standard .tlog format)
    def add_msg(msg, offset_us: int):
        buf = msg.pack(mav)
        chunks.append(struct.pack(">Q", base_t_us + offset_us) + buf)

    # 1. HEARTBEAT
    hb = mav.heartbeat_encode(
        type=mavlink2.MAV_TYPE_QUADROTOR,
        autopilot=mavlink2.MAV_AUTOPILOT_ARDUPILOTMEGA,
        base_mode=mavlink2.MAV_MODE_FLAG_SAFETY_ARMED,
        custom_mode=4,  # AUTO
        system_status=mavlink2.MAV_STATE_ACTIVE,
    )
    add_msg(hb, 0)

    # 2. STATUSTEXT - Arming
    st_arm = mav.statustext_encode(
        severity=mavlink2.MAV_SEVERITY_INFO,
        text=b"Motors Armed: Pre-arm checks PASSED\x00",
    )
    add_msg(st_arm, 500_000)

    # 3. GPS & Flight Dynamics (10 waypoints)
    base_lat = 19.0760
    base_lon = 72.8777

    for i in range(10):
        t_offset = (i + 1) * 1_000_000  # 1s intervals

        # GPS_RAW_INT
        gps_raw = mav.gps_raw_int_encode(
            time_usec=base_t_us + t_offset,
            fix_type=3,
            lat=int((base_lat + (i * 0.0003)) * 1e7),
            lon=int((base_lon + (i * 0.0003)) * 1e7),
            alt=int((10.0 + (i * 5.0)) * 1000),
            eph=75,  # 0.75 HDOP
            epv=100,
            vel=1250,  # 12.5 m/s
            cog=4500,  # 45 deg
            satellites_visible=15,
        )
        add_msg(gps_raw, t_offset)

        # GLOBAL_POSITION_INT
        gpos = mav.global_position_int_encode(
            time_boot_ms=t_offset // 1000,
            lat=int((base_lat + (i * 0.0003)) * 1e7),
            lon=int((base_lon + (i * 0.0003)) * 1e7),
            alt=int((10.0 + (i * 5.0)) * 1000),
            relative_alt=int((10.0 + (i * 5.0)) * 1000),
            vx=884,   # ~8.84 m/s
            vy=884,   # ~8.84 m/s -> sqrt(8.84^2 + 8.84^2) = 12.5 m/s
            vz=0,
            hdg=4500, # 45.0 deg
        )
        add_msg(gpos, t_offset + 10_000)

        # ATTITUDE
        att = mav.attitude_encode(
            time_boot_ms=t_offset // 1000,
            roll=0.02,   # ~1.15 deg
            pitch=-0.04, # ~-2.29 deg
            yaw=0.785,   # ~45 deg
            rollspeed=0.0,
            pitchspeed=0.0,
            yawspeed=0.0,
        )
        add_msg(att, t_offset + 20_000)

        # SYS_STATUS (Battery)
        volt = max(10400, 12600 - (i * 220))  # mV
        curr = 1650                           # cA (16.5A)
        rem = max(15, 95 - (i * 8))           # %
        sys_st = mav.sys_status_encode(
            onboard_control_sensors_present=0,
            onboard_control_sensors_enabled=0,
            onboard_control_sensors_health=0,
            load=500,
            voltage_battery=volt,
            current_battery=curr,
            battery_remaining=rem,
            drop_rate_comm=0,
            errors_comm=0,
            errors_count1=0,
            errors_count2=0,
            errors_count3=0,
            errors_count4=0,
        )
        add_msg(sys_st, t_offset + 30_000)

    # 4. STATUSTEXT - Failsafe RTL
    st_rtl = mav.statustext_encode(
        severity=mavlink2.MAV_SEVERITY_WARNING,
        text=b"Failsafe: Low Battery triggered Auto-RTL\x00",
    )
    add_msg(st_rtl, 11_500_000)

    # 5. STATUSTEXT - Disarm
    st_disarm = mav.statustext_encode(
        severity=mavlink2.MAV_SEVERITY_INFO,
        text=b"Motors Disarmed after landing\x00",
    )
    add_msg(st_disarm, 15_000_000)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(b"".join(chunks))
    return output_path

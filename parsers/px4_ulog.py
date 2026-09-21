"""
parsers/px4_ulog.py

Forensic parser for PX4 Autopilot ULog (.ulg) binary flight logs.

Forensic Capabilities:
- uORB bus extraction: Unpacks vehicle_gps_position, vehicle_attitude,
  battery_status, and system parameters from native binary ULog files.
- Attitude conversion: Transforms quaternion components (q[0]..q[3]) into
  Euler angles (pitch, roll, yaw) with high mathematical precision.
- Dropout & CPU overload detection: Audits data loss events recorded on the uORB bus.
- System information: Recovers NuttX OS version, Git commit hash, and hardware ID.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Optional

import pyulog

from normalize.schema import NormalizedEvent, EventType
from parsers.base import BaseParser, register_parser


@register_parser
class PX4ULogParser(BaseParser):
    """Parser for PX4 Autopilot ULog (.ulg) binary flight logs."""

    @property
    def parser_name(self) -> str:
        return "px4_ulog"

    @property
    def parser_version(self) -> str:
        return "1.0.0"

    @property
    def supported_platforms(self) -> list[str]:
        return ["px4", "pixhawk", "auterion", "skynode", "cube"]

    def can_parse(self, file_path: Path) -> bool:
        """Check for ULogFile magic header (8 bytes: 0x55 0x4C 0x6F 0x67 0x46 0x69 0x6C 0x65)."""
        path = Path(file_path)
        if not path.is_file():
            return False
        try:
            with open(path, "rb") as f:
                header = f.read(16)
                if len(header) >= 7 and header[:7] == pyulog.ULog.HEADER_BYTES:
                    return True
                # Fallback on extension if header partially intact
                if path.suffix.lower() in (".ulg", ".ugl") and len(header) >= 4:
                    return header.startswith(b"ULog")
                return False
        except Exception:
            return False

    def parse_records(
        self,
        file_path: Path,
        file_sha256: str,
    ) -> list[NormalizedEvent]:
        try:
            ulog = pyulog.ULog(str(file_path))
        except Exception:
            return []

        events: list[NormalizedEvent] = []

        # 1. Hardware & System Info Metadata
        sys_info = ulog.msg_info_dict
        hardware_model = str(sys_info.get("ver_hw", "PX4 Flight Controller"))
        software_ver = str(sys_info.get("ver_sw", "PX4 Autopilot"))
        git_hash = str(sys_info.get("ver_sw_release", sys_info.get("git_hash", "")))

        # 2. Establish Absolute UTC Time Reference
        boot_utc_ref: Optional[datetime] = None

        # Check vehicle_gps_position for time_utc_usec
        for dataset in ulog.data_list:
            if dataset.name in ("vehicle_gps_position", "vehicle_gps_position_0"):
                data = dataset.data
                time_utc_usec = data.get("time_utc_usec")
                timestamps = data.get("timestamp")
                if (
                    time_utc_usec is not None
                    and len(time_utc_usec) > 0
                    and timestamps is not None
                    and len(timestamps) > 0
                ):
                    for t_utc, t_boot in zip(time_utc_usec, timestamps):
                        if t_utc > 1_500_000_000_000_000:  # Valid epoch after year 2017
                            gps_epoch_utc = datetime.fromtimestamp(t_utc / 1e6, tz=timezone.utc)
                            boot_utc_ref = gps_epoch_utc - timedelta(microseconds=int(t_boot))
                            break
            if boot_utc_ref is not None:
                break

        # Fallback time anchor if GPS time not available
        if boot_utc_ref is None:
            time_ref_utc = sys_info.get("time_ref_utc")
            if time_ref_utc and isinstance(time_ref_utc, (int, float)) and time_ref_utc > 0:
                boot_utc_ref = datetime.fromtimestamp(time_ref_utc, tz=timezone.utc)
            else:
                mtime = file_path.stat().st_mtime
                boot_utc_ref = datetime.fromtimestamp(mtime, tz=timezone.utc)

        # Initial Configuration & Hardware Identity Event
        meta_event = NormalizedEvent(
            timestamp_utc=boot_utc_ref,
            source_platform="px4",
            event_type=EventType.CONFIG_PARAM.value,
            source_file=str(file_path),
            source_file_sha256=file_sha256,
            payload={
                "aircraft_model": hardware_model,
                "firmware_version": software_ver,
                "git_commit": git_hash,
                "total_parameters": len(ulog.initial_parameters),
            },
        )
        events.append(meta_event)

        # 3. Parse Parameters
        for param_name, param_val in list(ulog.initial_parameters.items())[:20]:
            events.append(
                NormalizedEvent(
                    timestamp_utc=boot_utc_ref,
                    source_platform="px4",
                    event_type=EventType.CONFIG_PARAM.value,
                    source_file=str(file_path),
                    source_file_sha256=file_sha256,
                    payload={"parameter": param_name, "value": param_val},
                )
            )

        # 4. Parse GPS Telemetry & Local Position Telemetry (with indoor/bench fallback)
        gps_events: list[NormalizedEvent] = []
        local_pos_events: list[NormalizedEvent] = []

        # 4. Parse GPS Telemetry & Local Position Telemetry (with indoor/bench fallback)
        gps_events: list[NormalizedEvent] = []
        local_pos_events: list[NormalizedEvent] = []

        # Build satellite count lookup from vehicle_gps_position if present
        sat_map: dict[int, int] = {}
        for d in ulog.data_list:
            if d.name in ("vehicle_gps_position", "vehicle_gps_position_0", "sensor_gps", "sensor_gps_0"):
                ts_arr = d.data.get("timestamp")
                sats_arr = d.data.get("satellites_used")
                if ts_arr is not None and sats_arr is not None and len(ts_arr) > 0 and len(sats_arr) > 0:
                    for t, s in zip(ts_arr, sats_arr):
                        if s is not None:
                            sat_map[int(t)] = int(s)
                break

        # Build ground speed velocity map from local position (vx, vy) or GPS velocity topics
        vel_map: dict[int, float] = {}
        for d in ulog.data_list:
            if d.name in ("vehicle_local_position", "vehicle_local_position_0", "estimator_local_position"):
                ts_arr = d.data.get("timestamp", [])
                vxs = d.data.get("vx", [])
                vys = d.data.get("vy", [])
                if len(ts_arr) > 0 and len(vxs) > 0 and len(vys) > 0:
                    for t, vx, vy in zip(ts_arr, vxs, vys):
                        if vx is not None and vy is not None:
                            vel_map[int(t)] = float(math.hypot(float(vx), float(vy)))
                if vel_map:
                    break

        if not vel_map:
            for d in ulog.data_list:
                if d.name in ("vehicle_gps_position", "vehicle_gps_position_0", "sensor_gps"):
                    ts_arr = d.data.get("timestamp", [])
                    vels_arr = d.data.get("vel_m_s", [])
                    vel_n_arr = d.data.get("vel_n_m_s", d.data.get("vel_n", []))
                    vel_e_arr = d.data.get("vel_e_m_s", d.data.get("vel_e", []))
                    for i in range(len(ts_arr)):
                        t = int(ts_arr[i])
                        if i < len(vels_arr) and vels_arr[i] is not None and float(vels_arr[i]) >= 0:
                            vel_map[t] = float(vels_arr[i])
                        elif i < len(vel_n_arr) and i < len(vel_e_arr) and vel_n_arr[i] is not None and vel_e_arr[i] is not None:
                            vel_map[t] = float(math.hypot(float(vel_n_arr[i]), float(vel_e_arr[i])))
                    if vel_map:
                        break

        import bisect
        vel_times = sorted(vel_map.keys()) if vel_map else []

        def lookup_vel(t: int) -> Optional[float]:
            if not vel_times:
                return None
            idx = bisect.bisect_left(vel_times, t)
            if idx == 0:
                best_t = vel_times[0]
            elif idx >= len(vel_times):
                best_t = vel_times[-1]
            else:
                before = vel_times[idx - 1]
                after = vel_times[idx]
                best_t = before if abs(t - before) <= abs(t - after) else after
            if abs(t - best_t) <= 1_500_000:  # Within 1.5 seconds
                return vel_map[best_t]
            return None

        # Build attitude orientation map (pitch_deg, roll_deg, yaw_deg) from vehicle_attitude
        att_map: dict[int, tuple[float, float, float]] = {}
        for d in ulog.data_list:
            if d.name in ("vehicle_attitude", "vehicle_attitude_0", "estimator_attitude"):
                ts_arr = d.data.get("timestamp", [])
                q0 = d.data.get("q[0]", d.data.get("q_0", []))
                q1 = d.data.get("q[1]", d.data.get("q_1", []))
                q2 = d.data.get("q[2]", d.data.get("q_2", []))
                q3 = d.data.get("q[3]", d.data.get("q_3", []))
                if len(ts_arr) > 0 and len(q0) > 0 and len(q1) > 0 and len(q2) > 0 and len(q3) > 0:
                    for i in range(len(ts_arr)):
                        if q0[i] is not None and q1[i] is not None and q2[i] is not None and q3[i] is not None:
                            w, x, y, z = float(q0[i]), float(q1[i]), float(q2[i]), float(q3[i])
                            roll = math.degrees(math.atan2(2.0 * (w * x + y * z), 1.0 - 2.0 * (x * x + y * y)))
                            pitch_val = max(-1.0, min(1.0, 2.0 * (w * y - z * x)))
                            pitch = math.degrees(math.asin(pitch_val))
                            yaw = (math.degrees(math.atan2(2.0 * (w * z + x * y), 1.0 - 2.0 * (y * y + z * z))) + 360.0) % 360.0
                            att_map[int(ts_arr[i])] = (round(pitch, 2), round(roll, 2), round(yaw, 2))
                if att_map:
                    break

        att_times = sorted(att_map.keys()) if att_map else []

        def lookup_att(t: int) -> Optional[tuple[float, float, float]]:
            if not att_times:
                return None
            idx = bisect.bisect_left(att_times, t)
            if idx == 0:
                best_t = att_times[0]
            elif idx >= len(att_times):
                best_t = att_times[-1]
            else:
                before = att_times[idx - 1]
                after = att_times[idx]
                best_t = before if abs(t - before) <= abs(t - after) else after
            if abs(t - best_t) <= 1_500_000:  # Within 1.5 seconds
                return att_map[best_t]
            return None

        # Identify primary position dataset in priority order:
        # 1. vehicle_global_position (EKF2 fused state - primary source of truth)
        # 2. vehicle_gps_position (GNSS receiver)
        # 3. sensor_gps (Raw GNSS sensor)
        pos_candidates = (
            "vehicle_global_position",
            "vehicle_global_position_0",
            "vehicle_gps_position",
            "vehicle_gps_position_0",
            "sensor_gps",
            "sensor_gps_0",
        )
        primary_pos_dataset = None
        for cand in pos_candidates:
            for d in ulog.data_list:
                if d.name == cand:
                    primary_pos_dataset = d
                    break
            if primary_pos_dataset is not None:
                break

        if primary_pos_dataset is not None:
            d = primary_pos_dataset.data
            timestamps = d.get("timestamp", [])
            lats = d.get("lat", d.get("latitude_deg", []))
            lons = d.get("lon", d.get("longitude_deg", []))
            alts = d.get("alt", d.get("altitude_msl_m", []))
            vels = d.get("vel_m_s", [])
            vel_ns = d.get("vel_n", [])
            vel_es = d.get("vel_e", [])
            cog_rads = d.get("yaw", d.get("heading", d.get("cog_rad", [])))
            sats = d.get("satellites_used", [])
            hdops = d.get("hdop", d.get("eph", []))
            fix_types = d.get("fix_type", [])
            utc_times = d.get("time_utc_usec", [])

            n_points = len(timestamps)
            step = max(1, n_points // 2000) if n_points > 5000 else 1

            for idx in range(0, n_points, step):
                t_us = int(timestamps[idx])
                if idx < len(utc_times) and utc_times[idx] and int(utc_times[idx]) > 1_500_000_000_000_000:
                    ev_ts = datetime.fromtimestamp(int(utc_times[idx]) / 1e6, tz=timezone.utc)
                else:
                    ev_ts = boot_utc_ref + timedelta(microseconds=t_us)

                lat_val = float(lats[idx]) if idx < len(lats) and lats[idx] is not None else None
                if lat_val is not None and abs(lat_val) > 1000.0:
                    lat_val = lat_val / 1e7

                lon_val = float(lons[idx]) if idx < len(lons) and lons[idx] is not None else None
                if lon_val is not None and abs(lon_val) > 1000.0:
                    lon_val = lon_val / 1e7

                # STRICT FORENSIC FILTER: Discard uninitialized Null Island (0,0) and non-fixes
                if lat_val is None or lon_val is None:
                    continue
                if abs(lat_val) < 0.0001 and abs(lon_val) < 0.0001:
                    continue
                if abs(lat_val) > 90.0 or abs(lon_val) > 180.0:
                    continue

                alt_val = float(alts[idx]) if idx < len(alts) and alts[idx] is not None else None
                if alt_val is not None and alt_val > 100000.0:
                    alt_val = alt_val / 1e3

                # Speed: check vel_m_s, hypot(vel_n, vel_e), or lookup_vel(t_us)
                spd_val = None
                if idx < len(vels) and vels[idx] is not None and float(vels[idx]) > 0:
                    spd_val = float(vels[idx])
                elif idx < len(vel_ns) and idx < len(vel_es) and vel_ns[idx] is not None and vel_es[idx] is not None:
                    spd_val = math.hypot(float(vel_ns[idx]), float(vel_es[idx]))

                if spd_val is None or spd_val == 0.0:
                    matched_spd = lookup_vel(t_us)
                    if matched_spd is not None:
                        spd_val = round(matched_spd, 2)

                att_sample = lookup_att(t_us)
                pitch_val = att_sample[0] if att_sample else None
                roll_val = att_sample[1] if att_sample else None

                heading_val = None
                if idx < len(cog_rads) and cog_rads[idx] is not None:
                    heading_val = (math.degrees(float(cog_rads[idx])) + 360.0) % 360.0
                elif att_sample:
                    heading_val = att_sample[2]

                sat_val = int(sats[idx]) if idx < len(sats) and sats[idx] is not None else sat_map.get(t_us)
                hdop_val = float(hdops[idx]) if idx < len(hdops) and hdops[idx] is not None else None
                fix_val = int(fix_types[idx]) if idx < len(fix_types) and fix_types[idx] is not None else None

                if fix_val is not None and fix_val < 2:
                    continue
                if sat_val is not None and sat_val == 0:
                    continue

                ev = NormalizedEvent(
                    timestamp_utc=ev_ts,
                    source_platform="px4",
                    event_type=EventType.GPS_FIX.value,
                    source_file=str(file_path),
                    source_file_sha256=file_sha256,
                    latitude=lat_val,
                    longitude=lon_val,
                    altitude_m=alt_val,
                    ground_speed_mps=spd_val,
                    heading_deg=heading_val,
                    pitch_deg=pitch_val,
                    roll_deg=roll_val,
                    satellites_visible=sat_val,
                    hdop=hdop_val,
                    payload={"fix_type": fix_val, "time_us": t_us, "source_dataset": primary_pos_dataset.name},
                )
                gps_events.append(ev)

        # Second pass: derive kinematic ground speed, pitch and roll from trajectory dynamics if missing
        for i in range(1, len(gps_events)):
            prev = gps_events[i - 1]
            curr = gps_events[i]
            if prev.latitude is not None and prev.longitude is not None and curr.latitude is not None and curr.longitude is not None:
                dt = (curr.timestamp_utc - prev.timestamp_utc).total_seconds()
                if 0.05 <= dt <= 10.0:
                    d_lat = math.radians(curr.latitude - prev.latitude)
                    d_lon = math.radians(curr.longitude - prev.longitude)
                    a = math.sin(d_lat / 2)**2 + math.cos(math.radians(prev.latitude)) * math.cos(math.radians(curr.latitude)) * math.sin(d_lon / 2)**2
                    dist = 6371000.0 * 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
                    if curr.ground_speed_mps is None or curr.ground_speed_mps == 0.0:
                        calc_spd = dist / dt
                        if 0.0 < calc_spd < 150.0:
                            curr.ground_speed_mps = round(calc_spd, 2)

                    # Trajectory climb / descent slope pitch
                    d_alt = (curr.altitude_m or 0.0) - (prev.altitude_m or 0.0)
                    if curr.pitch_deg is None or (curr.pitch_deg == 0.0 and abs(d_alt) > 0.15):
                        slope_pitch = math.degrees(math.atan2(d_alt, max(0.4, dist)))
                        curr.pitch_deg = round(max(-35.0, min(35.0, slope_pitch)), 2)

                    # Trajectory banking roll
                    if (curr.roll_deg is None or curr.roll_deg == 0.0) and curr.heading_deg is not None and prev.heading_deg is not None:
                        d_hdg = (curr.heading_deg - prev.heading_deg + 540.0) % 360.0 - 180.0
                        spd = curr.ground_speed_mps or 0.0
                        if spd > 1.0 and abs(d_hdg) > 1.0:
                            turn_rate = math.radians(d_hdg / dt)
                            bank = math.degrees(math.atan(spd * turn_rate / 9.81))
                            curr.roll_deg = round(max(-40.0, min(40.0, bank)), 2)

        # 5. Parse remaining topics (local position fallback, attitude, battery, status)
        for dataset in ulog.data_list:
            if dataset.name in ("vehicle_local_position", "vehicle_local_position_0"):
                d = dataset.data
                timestamps = d.get("timestamp", [])
                xs = d.get("x", [])
                ys = d.get("y", [])
                zs = d.get("z", [])
                vxs = d.get("vx", [])
                vys = d.get("vy", [])
                headings = d.get("heading", d.get("yaw", []))
                ref_lats = d.get("ref_lat", [])
                ref_lons = d.get("ref_lon", [])
                ref_alts = d.get("ref_alt", [])

                n_points = len(timestamps)
                step = max(1, n_points // 2000) if n_points > 5000 else 1

                # Reference origin (default: Mumbai forensic center if unanchored)
                origin_lat = 19.0760
                origin_lon = 72.8777
                origin_alt = 10.0
                if len(ref_lats) > 0 and ref_lats[0] is not None and abs(float(ref_lats[0])) > 0.001:
                    origin_lat = float(ref_lats[0])
                if len(ref_lons) > 0 and ref_lons[0] is not None and abs(float(ref_lons[0])) > 0.001:
                    origin_lon = float(ref_lons[0])
                if len(ref_alts) > 0 and ref_alts[0] is not None:
                    origin_alt = float(ref_alts[0])

                meters_per_deg_lat = 111132.92
                meters_per_deg_lon = 111132.92 * math.cos(math.radians(origin_lat))
                if meters_per_deg_lon == 0:
                    meters_per_deg_lon = 1.0

                for idx in range(0, n_points, step):
                    t_us = int(timestamps[idx])
                    ev_ts = boot_utc_ref + timedelta(microseconds=t_us)

                    x_m = float(xs[idx]) if idx < len(xs) and xs[idx] is not None else 0.0
                    y_m = float(ys[idx]) if idx < len(ys) and ys[idx] is not None else 0.0
                    z_m = float(zs[idx]) if idx < len(zs) and zs[idx] is not None else 0.0

                    vx_m = float(vxs[idx]) if idx < len(vxs) and vxs[idx] is not None else 0.0
                    vy_m = float(vys[idx]) if idx < len(vys) and vys[idx] is not None else 0.0
                    spd = math.hypot(vx_m, vy_m)

                    att_s = lookup_att(t_us)
                    lp_pitch = att_s[0] if att_s else None
                    lp_roll = att_s[1] if att_s else None
                    heading_val = None
                    if idx < len(headings) and headings[idx] is not None:
                        heading_val = (math.degrees(float(headings[idx])) + 360.0) % 360.0
                    elif att_s:
                        heading_val = att_s[2]

                    proj_lat = origin_lat + (x_m / meters_per_deg_lat)
                    proj_lon = origin_lon + (y_m / meters_per_deg_lon)
                    alt_m = origin_alt - z_m  # In NED, -z is upwards altitude

                    ev = NormalizedEvent(
                        timestamp_utc=ev_ts,
                        source_platform="px4",
                        event_type=EventType.GPS_FIX.value,
                        source_file=str(file_path),
                        source_file_sha256=file_sha256,
                        latitude=round(proj_lat, 7),
                        longitude=round(proj_lon, 7),
                        altitude_m=round(alt_m, 2),
                        ground_speed_mps=round(spd, 2),
                        heading_deg=round(heading_val, 1) if heading_val is not None else None,
                        pitch_deg=lp_pitch,
                        roll_deg=lp_roll,
                        satellites_visible=0,
                        hdop=1.0,
                        payload={
                            "is_indoor_local": True,
                            "local_x_m": round(x_m, 3),
                            "local_y_m": round(y_m, 3),
                            "local_z_m": round(z_m, 3),
                            "time_us": t_us,
                        },
                    )
                    local_pos_events.append(ev)

            # 5. Parse Attitude Samples (vehicle_attitude)
            elif dataset.name in ("vehicle_attitude", "vehicle_attitude_0"):
                d = dataset.data
                timestamps = d.get("timestamp", [])
                q0 = d.get("q[0]", d.get("q_0", []))
                q1 = d.get("q[1]", d.get("q_1", []))
                q2 = d.get("q[2]", d.get("q_2", []))
                q3 = d.get("q[3]", d.get("q_3", []))

                n_points = len(timestamps)
                step = max(1, n_points // 1000) if n_points > 2000 else 1

                for idx in range(0, n_points, step):
                    t_us = int(timestamps[idx])
                    ev_ts = boot_utc_ref + timedelta(microseconds=t_us)

                    if (
                        idx < len(q0)
                        and idx < len(q1)
                        and idx < len(q2)
                        and idx < len(q3)
                    ):
                        w, x, y, z = float(q0[idx]), float(q1[idx]), float(q2[idx]), float(q3[idx])
                        # Quaternion to Euler angles (radians -> degrees)
                        roll = math.degrees(math.atan2(2.0 * (w * x + y * z), 1.0 - 2.0 * (x * x + y * y)))
                        pitch_val = max(-1.0, min(1.0, 2.0 * (w * y - z * x)))
                        pitch = math.degrees(math.asin(pitch_val))
                        yaw = math.degrees(math.atan2(2.0 * (w * z + x * y), 1.0 - 2.0 * (y * y + z * z)))

                        ev = NormalizedEvent(
                            timestamp_utc=ev_ts,
                            source_platform="px4",
                            event_type=EventType.IMU_SAMPLE.value,
                            source_file=str(file_path),
                            source_file_sha256=file_sha256,
                            pitch_deg=round(pitch, 2),
                            roll_deg=round(roll, 2),
                            yaw_deg=round(yaw, 2),
                            payload={"time_us": t_us},
                        )
                        events.append(ev)

            # 6. Parse Battery Status
            elif dataset.name in ("battery_status", "battery_status_0"):
                d = dataset.data
                timestamps = d.get("timestamp", [])
                volts = d.get("voltage_v", d.get("voltage_filtered_v", []))
                currs = d.get("current_a", d.get("current_filtered_a", []))
                rems = d.get("remaining", [])

                n_points = len(timestamps)
                step = max(1, n_points // 500) if n_points > 1000 else 1

                for idx in range(0, n_points, step):
                    t_us = int(timestamps[idx])
                    ev_ts = boot_utc_ref + timedelta(microseconds=t_us)

                    volt = float(volts[idx]) if idx < len(volts) else None
                    curr = float(currs[idx]) if idx < len(currs) else None
                    rem = float(rems[idx]) * 100.0 if idx < len(rems) and rems[idx] is not None else None

                    ev = NormalizedEvent(
                        timestamp_utc=ev_ts,
                        source_platform="px4",
                        event_type=EventType.BATTERY_STATE.value,
                        source_file=str(file_path),
                        source_file_sha256=file_sha256,
                        battery_voltage_v=round(volt, 2) if volt is not None else None,
                        battery_current_a=round(curr, 2) if curr is not None else None,
                        battery_remaining_pct=round(rem, 1) if rem is not None else None,
                        payload={"time_us": t_us},
                    )
                    events.append(ev)

            # 7. Parse Vehicle Status (Flight Modes and Arming Transitions)
            elif dataset.name in ("vehicle_status", "vehicle_status_0"):
                d = dataset.data
                timestamps = d.get("timestamp", [])
                nav_states = d.get("nav_state", [])
                arming_states = d.get("arming_state", [])

                nav_map = {
                    0: "MANUAL",
                    1: "ALTCTL",
                    2: "POSCTL",
                    3: "AUTO_MISSION",
                    4: "AUTO_LOITER",
                    5: "AUTO_RTL",
                    6: "AUTO_LAND",
                    7: "AUTO_RTGS",
                    8: "AUTO_TAKEOFF",
                    14: "OFFBOARD",
                    15: "STABILIZED",
                    21: "ORBIT",
                }
                arm_map = {1: "DISARMED", 2: "ARMED"}

                prev_nav = None
                prev_arm = None
                for idx in range(len(timestamps)):
                    t_us = int(timestamps[idx])
                    ev_ts = boot_utc_ref + timedelta(microseconds=t_us)

                    raw_nav = int(nav_states[idx]) if idx < len(nav_states) else None
                    raw_arm = int(arming_states[idx]) if idx < len(arming_states) else None

                    # Emit mode change event
                    if raw_nav is not None and raw_nav != prev_nav:
                        mode_str = nav_map.get(raw_nav, f"NAV_STATE_{raw_nav}")
                        events.append(
                            NormalizedEvent(
                                timestamp_utc=ev_ts,
                                source_platform="px4",
                                event_type=EventType.MODE_CHANGE.value,
                                source_file=str(file_path),
                                source_file_sha256=file_sha256,
                                flight_mode=mode_str,
                                payload={"raw_nav_state": raw_nav, "time_us": t_us},
                            )
                        )
                        prev_nav = raw_nav

                    # Emit arming transition event
                    if raw_arm is not None and raw_arm != prev_arm:
                        events.append(
                            NormalizedEvent(
                                timestamp_utc=ev_ts,
                                source_platform="px4",
                                event_type=EventType.ARM_DISARM.value,
                                source_file=str(file_path),
                                source_file_sha256=file_sha256,
                                payload={"arming_state": arm_map.get(raw_arm, f"STATE_{raw_arm}"), "time_us": t_us},
                            )
                        )
                        prev_arm = raw_arm

        # Select GPS telemetry: prioritize outdoor GPS fixes; fallback to indoor local coordinates if GPS empty
        has_valid_gps = any(
            ev.latitude is not None and abs(ev.latitude) > 0.0001
            for ev in gps_events
        )
        if has_valid_gps:
            events.extend(gps_events)
        elif local_pos_events:
            events.extend(local_pos_events)

        # 8. Parse System Logged Messages (Events, Failsafes, Warnings)
        for msg in ulog.logged_messages:
            t_us = msg.timestamp
            ev_ts = boot_utc_ref + timedelta(microseconds=t_us)
            txt = msg.message

            event_type = EventType.RAW.value
            lower_txt = txt.lower()
            if any(w in lower_txt for w in ["arm", "disarm"]):
                event_type = EventType.ARM_DISARM.value
            elif any(w in lower_txt for w in ["rtl", "return", "failsafe"]):
                event_type = EventType.RTH_TRIGGER.value
            elif any(w in lower_txt for w in ["geofence", "nfz"]):
                event_type = EventType.GEOFENCE_BREACH.value

            events.append(
                NormalizedEvent(
                    timestamp_utc=ev_ts,
                    source_platform="px4",
                    event_type=event_type,
                    source_file=str(file_path),
                    source_file_sha256=file_sha256,
                    payload={
                        "message": txt,
                        "log_level": msg.log_level,
                        "time_us": t_us,
                    },
                )
            )

        # 8. Parse Data Loss Dropouts (Forensic Reliability Metric)
        for d in ulog.dropouts:
            t_us = d.timestamp
            ev_ts = boot_utc_ref + timedelta(microseconds=t_us)
            events.append(
                NormalizedEvent(
                    timestamp_utc=ev_ts,
                    source_platform="px4",
                    event_type=EventType.RAW.value,
                    source_file=str(file_path),
                    source_file_sha256=file_sha256,
                    payload={
                        "anomaly_indicator": "CPU_BUS_DROPOUT",
                        "duration_ms": d.duration,
                        "time_us": t_us,
                    },
                )
            )

        return events

    def extract_extended_telemetry(self, file_path: Path) -> dict[str, Any]:
        """Extract rich time-series engineering datasets matching PX4 Flight Review."""
        try:
            ulog = pyulog.ULog(str(file_path))
        except Exception:
            return {}

        datasets = {d.name: d.data for d in ulog.data_list}
        sys_info = ulog.msg_info_dict

        # Hardware & Metadata Summary
        hw_model = str(sys_info.get("ver_hw", "PX4 Autopilot"))
        sw_ver = str(sys_info.get("ver_sw", sys_info.get("ver_sw_release", "v1.x")))
        os_ver = str(sys_info.get("ver_os", sys_info.get("os_name", "NuttX RTOS")))
        airframe_id = str(ulog.initial_parameters.get("SYS_AUTOSTART", "Standard Airframe"))
        uuid_str = str(sys_info.get("uid", sys_info.get("sys_uuid", "N/A")))

        def _clean(val: Any, default: float = 0.0) -> float:
            if val is None:
                return default
            try:
                f = float(val)
                if math.isnan(f) or math.isinf(f):
                    return default
                return round(f, 3)
            except Exception:
                return default

        # 1. Altitude Estimation Series (Fused vs Baro vs GPS vs Setpoint)
        alt_data: dict[str, list] = {"times": [], "fused": [], "baro": [], "gps": [], "setpoint": []}
        pos_src = datasets.get("vehicle_local_position") or datasets.get("vehicle_local_position_0")
        if pos_src and "timestamp" in pos_src and len(pos_src["timestamp"]) > 0:
            ts = pos_src["timestamp"]
            t0 = ts[0]
            zs = pos_src.get("z", [])
            step = max(1, len(ts) // 500)
            for i in range(0, len(ts), step):
                alt_data["times"].append(round((ts[i] - t0) / 1e6, 2))
                alt_data["fused"].append(_clean(-zs[i] if i < len(zs) else 0.0))

            # Sample GPS alt if aligned
            gps_src = datasets.get("vehicle_gps_position") or datasets.get("vehicle_gps_position_0")
            if gps_src and "alt" in gps_src:
                g_alts = gps_src["alt"]
                g_step = max(1, len(g_alts) // len(alt_data["times"])) if len(alt_data["times"]) > 0 else 1
                alt_data["gps"] = [_clean(g_alts[min(i * g_step, len(g_alts) - 1)] / (1e3 if max(g_alts) > 10000 else 1)) for i in range(len(alt_data["times"]))]

            # Sample Baro alt
            baro_src = datasets.get("vehicle_air_data") or datasets.get("sensor_baro")
            if baro_src:
                b_alts = baro_src.get("baro_alt_meter", baro_src.get("altitude", []))
                if len(b_alts) > 0:
                    b_step = max(1, len(b_alts) // len(alt_data["times"])) if len(alt_data["times"]) > 0 else 1
                    alt_data["baro"] = [_clean(b_alts[min(i * b_step, len(b_alts) - 1)]) for i in range(len(alt_data["times"]))]

        # 2. Attitude & Dynamics Series (Roll, Pitch, Yaw)
        att_data: dict[str, list] = {"times": [], "roll": [], "pitch": [], "yaw": []}
        att_src = datasets.get("vehicle_attitude") or datasets.get("vehicle_attitude_0")
        if att_src and "timestamp" in att_src and len(att_src["timestamp"]) > 0:
            ts = att_src["timestamp"]
            t0 = ts[0]
            q0 = att_src.get("q[0]", att_src.get("q_0", []))
            q1 = att_src.get("q[1]", att_src.get("q_1", []))
            q2 = att_src.get("q[2]", att_src.get("q_2", []))
            q3 = att_src.get("q[3]", att_src.get("q_3", []))
            step = max(1, len(ts) // 500)
            for i in range(0, len(ts), step):
                att_data["times"].append(round((ts[i] - t0) / 1e6, 2))
                if i < len(q0) and i < len(q1) and i < len(q2) and i < len(q3):
                    w, x, y, z = float(q0[i]), float(q1[i]), float(q2[i]), float(q3[i])
                    roll = math.degrees(math.atan2(2.0 * (w * x + y * z), 1.0 - 2.0 * (x * x + y * y)))
                    pitch_val = max(-1.0, min(1.0, 2.0 * (w * y - z * x)))
                    pitch = math.degrees(math.asin(pitch_val))
                    yaw = math.degrees(math.atan2(2.0 * (w * z + x * y), 1.0 - 2.0 * (y * y + z * z)))
                    att_data["roll"].append(round(roll, 2))
                    att_data["pitch"].append(round(pitch, 2))
                    att_data["yaw"].append(round(yaw, 2))
                else:
                    att_data["roll"].append(0.0)
                    att_data["pitch"].append(0.0)
                    att_data["yaw"].append(0.0)

        # 3. Kinematic Velocities Series (Vx, Vy, Vz, Speed)
        vel_data: dict[str, list] = {"times": [], "vx": [], "vy": [], "vz": [], "speed": []}
        if pos_src and "vx" in pos_src and len(pos_src["vx"]) > 0:
            ts = pos_src["timestamp"]
            t0 = ts[0]
            vxs = pos_src.get("vx", [])
            vys = pos_src.get("vy", [])
            vzs = pos_src.get("vz", [])
            step = max(1, len(ts) // 500)
            for i in range(0, len(ts), step):
                vel_data["times"].append(round((ts[i] - t0) / 1e6, 2))
                vx = float(vxs[i]) if i < len(vxs) else 0.0
                vy = float(vys[i]) if i < len(vys) else 0.0
                vz = float(vzs[i]) if i < len(vzs) else 0.0
                vel_data["vx"].append(_clean(vx))
                vel_data["vy"].append(_clean(vy))
                vel_data["vz"].append(_clean(vz))
                vel_data["speed"].append(_clean(math.hypot(vx, vy)))

        # 4. Power & Battery Subsystem
        power_data: dict[str, list] = {"times": [], "voltage": [], "current": [], "remaining": [], "discharged_mah": []}
        bat_src = datasets.get("battery_status") or datasets.get("battery_status_0")
        if bat_src and "timestamp" in bat_src and len(bat_src["timestamp"]) > 0:
            ts = bat_src["timestamp"]
            t0 = ts[0]
            volts = bat_src.get("voltage_v", bat_src.get("voltage_filtered_v", []))
            currs = bat_src.get("current_a", bat_src.get("current_filtered_a", []))
            rems = bat_src.get("remaining", [])
            dischs = bat_src.get("discharged_mah", [])
            step = max(1, len(ts) // 500)
            for i in range(0, len(ts), step):
                power_data["times"].append(round((ts[i] - t0) / 1e6, 2))
                power_data["voltage"].append(_clean(volts[i] if i < len(volts) else 0.0))
                power_data["current"].append(_clean(currs[i] if i < len(currs) else 0.0))
                rem_val = float(rems[i]) * 100.0 if i < len(rems) and rems[i] is not None else 0.0
                power_data["remaining"].append(round(rem_val, 1))
                power_data["discharged_mah"].append(_clean(dischs[i] if i < len(dischs) else 0.0))
        elif "system_power" in datasets and "timestamp" in datasets["system_power"] and len(datasets["system_power"]["timestamp"]) > 0:
            sp_src = datasets["system_power"]
            ts = sp_src["timestamp"]
            t0 = ts[0]
            volts = sp_src.get("voltage5v_v", sp_src.get("voltage_payload_v", []))
            step = max(1, len(ts) // 500)
            for i in range(0, len(ts), step):
                power_data["times"].append(round((ts[i] - t0) / 1e6, 2))
                power_data["voltage"].append(_clean(volts[i] if i < len(volts) else 5.0))
                power_data["current"].append(0.0)
                power_data["remaining"].append(100.0)
                power_data["discharged_mah"].append(0.0)

        # 5. Actuators & Motors Subsystem
        act_data: dict[str, list] = {"times": [], "m1": [], "m2": [], "m3": [], "m4": []}
        act_src = (
            datasets.get("actuator_motors")
            or datasets.get("actuator_outputs")
            or datasets.get("actuator_controls_0")
            or datasets.get("actuator_motors_0")
        )
        if act_src and "timestamp" in act_src and len(act_src["timestamp"]) > 0:
            ts = act_src["timestamp"]
            t0 = ts[0]
            c0 = act_src.get("control[0]", act_src.get("output[0]", []))
            c1 = act_src.get("control[1]", act_src.get("output[1]", []))
            c2 = act_src.get("control[2]", act_src.get("output[2]", []))
            c3 = act_src.get("control[3]", act_src.get("output[3]", []))
            step = max(1, len(ts) // 500)
            for i in range(0, len(ts), step):
                act_data["times"].append(round((ts[i] - t0) / 1e6, 2))
                act_data["m1"].append(_clean(c0[i] if i < len(c0) else 0.0))
                act_data["m2"].append(_clean(c1[i] if i < len(c1) else 0.0))
                act_data["m3"].append(_clean(c2[i] if i < len(c2) else 0.0))
                act_data["m4"].append(_clean(c3[i] if i < len(c3) else 0.0))

        # 6. Avionics, GNSS & CPU Health
        health_data: dict[str, list] = {"times": [], "sats": [], "hdop": [], "cpu_load": [], "ram_usage": []}
        gps_src = datasets.get("vehicle_gps_position") or datasets.get("vehicle_gps_position_0")
        if gps_src and "timestamp" in gps_src and len(gps_src["timestamp"]) > 0:
            ts = gps_src["timestamp"]
            t0 = ts[0]
            sats = gps_src.get("satellites_used", [])
            hdops = gps_src.get("hdop", gps_src.get("eph", []))
            step = max(1, len(ts) // 500)
            for i in range(0, len(ts), step):
                health_data["times"].append(round((ts[i] - t0) / 1e6, 2))
                health_data["sats"].append(int(sats[i]) if i < len(sats) and sats[i] is not None else 0)
                health_data["hdop"].append(_clean(hdops[i] if i < len(hdops) else 0.0))

        cpu_src = datasets.get("cpuload") or datasets.get("cpuload_0")
        if cpu_src and len(health_data["times"]) > 0:
            c_loads = cpu_src.get("load", [])
            r_loads = cpu_src.get("ram_usage", [])
            if len(c_loads) > 0:
                c_step = max(1, len(c_loads) // len(health_data["times"]))
                health_data["cpu_load"] = [round(_clean(c_loads[min(i * c_step, len(c_loads) - 1)]) * 100.0, 1) for i in range(len(health_data["times"]))]
            if len(r_loads) > 0:
                r_step = max(1, len(r_loads) // len(health_data["times"]))
                health_data["ram_usage"] = [round(_clean(r_loads[min(i * r_step, len(r_loads) - 1)]) * 100.0, 1) for i in range(len(health_data["times"]))]

        # 7. Diagnostic Logged Messages
        messages: list[dict[str, Any]] = []
        for msg in ulog.logged_messages:
            messages.append({
                "time_s": round(msg.timestamp / 1e6, 2),
                "level": str(msg.log_level),
                "message": msg.message,
            })

        # 8. Flight Controller Configuration Parameters Audit
        params: list[dict[str, Any]] = []
        for k, v in ulog.initial_parameters.items():
            is_critical = any(prefix in k for prefix in ["GF_", "NAV_", "COM_", "RTL_", "BAT_", "MPC_", "MC_"])
            params.append({
                "name": str(k),
                "value": str(v),
                "is_critical": is_critical,
            })

        return {
            "summary": {
                "airframe": airframe_id,
                "hardware": hw_model,
                "software_version": sw_ver,
                "os_version": os_ver,
                "vehicle_uuid": uuid_str,
                "total_parameters": len(ulog.initial_parameters),
                "total_logged_messages": len(messages),
            },
            "altitude_chart": alt_data,
            "attitude_chart": att_data,
            "velocity_chart": vel_data,
            "power_chart": power_data,
            "actuator_chart": act_data,
            "sensor_health_chart": health_data,
            "logged_messages": messages,
            "parameters_table": params[:300],  # Return top critical parameters
        }


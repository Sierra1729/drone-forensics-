"""
parsers/yuneec.py

Forensic flight log parser for Yuneec commercial UAVs (Typhoon H, H520, Mantis Q, Tornado).
Yuneec drones record ST16/ST16S telemetry CSV files widely utilized in industrial inspection,
search & rescue, and law enforcement operations.
"""

from __future__ import annotations

import csv
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Any

from normalize.schema import NormalizedEvent, EventType
from parsers.base import BaseParser, register_parser


@register_parser
class YuneecFlightLogParser(BaseParser):
    """Forensic parser for Yuneec ST16 / ST16S ground station telemetry logs."""

    @property
    def parser_name(self) -> str:
        return "yuneec_telemetry_csv"

    @property
    def supported_platforms(self) -> list[str]:
        return ["yuneec", "typhoon_h", "h520", "mantis_q"]

    def can_parse(self, file_path: Path) -> bool:
        """Sniff header for Yuneec ST16 telemetry column signatures."""
        try:
            path = Path(file_path)
            if not path.is_file() or path.stat().st_size == 0:
                return False

            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                first_line = f.readline()

            if "GPS_time" in first_line and ("f_voltage" in first_line or "f_current" in first_line):
                return True
            if "Latitude" in first_line and "Longitude" in first_line and "f_speed" in first_line:
                return True

            return False
        except Exception:
            return False

    def parse_records(
        self,
        file_path: Path,
        file_sha256: str,
    ) -> list[NormalizedEvent]:
        """Extract Yuneec multirotor kinematics, attitude, battery, and flight modes."""
        events: list[NormalizedEvent] = []
        path = Path(file_path)

        base_time = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        aircraft_model = "Yuneec Typhoon H"
        prev_mode = None

        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for row in reader:
                clean_row = {k.strip(): v.strip() for k, v in row.items() if k is not None and v is not None}

                # Timestamp
                ev_ts = base_time
                time_str = clean_row.get("GPS_time") or clean_row.get("time") or clean_row.get("Time")
                if time_str:
                    try:
                        # Epoch milliseconds or ISO format
                        if time_str.isdigit() and len(time_str) >= 12:
                            ev_ts = datetime.fromtimestamp(int(time_str) / 1000.0, tz=timezone.utc)
                        else:
                            dt = datetime.fromisoformat(time_str.replace("Z", "+00:00"))
                            if dt.tzinfo is None:
                                dt = dt.replace(tzinfo=timezone.utc)
                            ev_ts = dt
                    except Exception:
                        pass

                # Coordinates
                lat_str = clean_row.get("Latitude") or clean_row.get("latitude")
                lon_str = clean_row.get("Longitude") or clean_row.get("longitude")
                alt_str = clean_row.get("Altitude") or clean_row.get("altitude")
                spd_str = clean_row.get("f_speed") or clean_row.get("speed")
                sat_str = clean_row.get("satellites") or clean_row.get("num_sats")

                lat, lon = None, None
                if lat_str and lon_str:
                    try:
                        lat = float(lat_str)
                        lon = float(lon_str)
                        if abs(lat) > 1000.0:
                            lat = lat / 1e7
                        if abs(lon) > 1000.0:
                            lon = lon / 1e7
                    except ValueError:
                        lat, lon = None, None

                alt_m = None
                if alt_str:
                    try:
                        alt_m = float(alt_str)
                    except ValueError:
                        pass

                spd_mps = None
                if spd_str:
                    try:
                        spd_mps = float(spd_str)
                    except ValueError:
                        pass

                sats = None
                if sat_str:
                    try:
                        sats = int(float(sat_str))
                    except ValueError:
                        pass

                # Attitude
                roll = None
                pitch = None
                yaw = None
                try:
                    if "Roll" in clean_row:
                        roll = float(clean_row["Roll"])
                    if "Pitch" in clean_row:
                        pitch = float(clean_row["Pitch"])
                    if "Yaw" in clean_row:
                        yaw = float(clean_row["Yaw"])
                except ValueError:
                    pass

                # Battery
                volt = None
                curr = None
                try:
                    if "f_voltage" in clean_row:
                        volt = float(clean_row["f_voltage"])
                    if "f_current" in clean_row:
                        curr = float(clean_row["f_current"])
                except ValueError:
                    pass

                # Flight Mode
                mode_str = clean_row.get("vehicle_mode") or clean_row.get("f_mode") or clean_row.get("Mode")
                if mode_str and mode_str != prev_mode:
                    events.append(
                        NormalizedEvent(
                            timestamp_utc=ev_ts,
                            source_platform="yuneec",
                            event_type=EventType.MODE_CHANGE.value,
                            source_file=str(file_path),
                            source_file_sha256=file_sha256,
                            flight_mode=mode_str,
                            payload={"aircraft_model": aircraft_model},
                        )
                    )
                    prev_mode = mode_str

                if lat is not None and lon is not None:
                    events.append(
                        NormalizedEvent(
                            timestamp_utc=ev_ts,
                            source_platform="yuneec",
                            event_type=EventType.GPS_FIX.value,
                            source_file=str(file_path),
                            source_file_sha256=file_sha256,
                            latitude=lat,
                            longitude=lon,
                            altitude_m=alt_m,
                            ground_speed_mps=spd_mps,
                            heading_deg=yaw,
                            pitch_deg=round(pitch, 2) if pitch is not None else None,
                            roll_deg=round(roll, 2) if roll is not None else None,
                            yaw_deg=round(yaw, 2) if yaw is not None else None,
                            satellites_visible=sats,
                            battery_voltage_v=round(volt, 2) if volt is not None else None,
                            battery_current_a=round(curr, 2) if curr is not None else None,
                            flight_mode=mode_str,
                            payload={"aircraft_model": aircraft_model},
                        )
                    )

        events.insert(
            0,
            NormalizedEvent(
                timestamp_utc=base_time,
                source_platform="yuneec",
                event_type=EventType.CONFIG_PARAM.value,
                source_file=str(file_path),
                source_file_sha256=file_sha256,
                payload={"aircraft_model": aircraft_model},
            ),
        )

        return events

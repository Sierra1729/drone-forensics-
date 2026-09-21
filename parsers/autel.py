"""
parsers/autel.py

Forensic flight log parser for Autel Robotics UAVs (Autel EVO, EVO II, EVO Max 4T, Dragonfish).
Autel drones are widely deployed across enterprise surveillance and tactical operations as a primary
alternative to DJI platforms.
"""

from __future__ import annotations

import csv
from datetime import datetime, timezone, timedelta
import io
from pathlib import Path
from typing import Optional, List, Dict, Any

from normalize.schema import NormalizedEvent, EventType
from parsers.base import BaseParser, register_parser


@register_parser
class AutelFlightLogParser(BaseParser):
    """Forensic parser for Autel Robotics flight telemetry logs."""

    @property
    def parser_name(self) -> str:
        return "autel_robotics_csv"

    @property
    def parser_version(self) -> str:
        return "1.0.0"

    @property
    def supported_platforms(self) -> list[str]:
        return ["autel", "autel_evo", "autel_robotics", "dragonfish"]

    def can_parse(self, file_path: Path) -> bool:
        """Sniff header for Autel proprietary column names and signatures."""
        try:
            path = Path(file_path)
            if not path.is_file() or path.stat().st_size == 0:
                return False

            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                first_lines = [f.readline() for _ in range(5)]

            combined = " ".join(first_lines)
            # Exclude DJI CsvView / DatCon files
            if "CUSTOM.date" in combined or "OSD.flycState" in combined:
                return False

            if "Autel" in combined or "FlyModel" in combined:
                return True
            if "OSD.latitude" in combined and "OSD.longitude" in combined:
                return True
            if "OSD.flyTime" in combined or "BATTERY.battery" in combined:
                return True

            return False
        except Exception:
            return False

    def parse_records(
        self,
        file_path: Path,
        file_sha256: str,
    ) -> list[NormalizedEvent]:
        """Extract Autel aircraft model, GNSS path, Euler angles, and power telemetry."""
        events: list[NormalizedEvent] = []
        path = Path(file_path)

        base_time = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        aircraft_model = "Autel EVO II"
        serial_number = None

        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            fieldnames = [c.strip() for c in (reader.fieldnames or [])]

            # Re-initialize DictReader with stripped fieldnames
            f.seek(0)
            reader = csv.DictReader(f)

            prev_mode = None

            for row in reader:
                # Clean keys and values
                clean_row = {k.strip(): v.strip() for k, v in row.items() if k is not None and v is not None}

                # Extract model / serial if present in row
                if "FlyModel" in clean_row and clean_row["FlyModel"]:
                    aircraft_model = clean_row["FlyModel"]
                if "DroneID" in clean_row and clean_row["DroneID"]:
                    serial_number = clean_row["DroneID"]

                # Timestamp
                ev_ts = base_time
                for time_key in ["DateTime", "UTCTime", "Time", "OSD.flyTime", "FlyTime"]:
                    if time_key in clean_row and clean_row[time_key]:
                        raw_t = clean_row[time_key]
                        try:
                            # Try parsing ISO or standard formats
                            dt = datetime.fromisoformat(raw_t.replace("Z", "+00:00"))
                            if dt.tzinfo is None:
                                dt = dt.replace(tzinfo=timezone.utc)
                            ev_ts = dt
                            break
                        except Exception:
                            try:
                                # Try float seconds offset
                                sec_offset = float(raw_t)
                                ev_ts = base_time + timedelta(seconds=sec_offset)
                                break
                            except Exception:
                                pass

                # GPS Coordinates
                lat_str = clean_row.get("OSD.latitude") or clean_row.get("Latitude") or clean_row.get("latitude")
                lon_str = clean_row.get("OSD.longitude") or clean_row.get("Longitude") or clean_row.get("longitude")
                alt_str = clean_row.get("OSD.height") or clean_row.get("OSD.altitude") or clean_row.get("Altitude")
                spd_str = clean_row.get("OSD.speed") or clean_row.get("Speed") or clean_row.get("speed")
                sat_str = clean_row.get("GPS.satelliteCount") or clean_row.get("Satellites")

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

                # Attitude (Pitch, Roll, Yaw)
                pitch = None
                roll = None
                yaw = None
                pitch_str = clean_row.get("OSD.pitch") or clean_row.get("Pitch")
                roll_str = clean_row.get("OSD.roll") or clean_row.get("Roll")
                yaw_str = clean_row.get("OSD.yaw") or clean_row.get("Yaw")
                if pitch_str:
                    try:
                        pitch = float(pitch_str)
                    except ValueError:
                        pass
                if roll_str:
                    try:
                        roll = float(roll_str)
                    except ValueError:
                        pass
                if yaw_str:
                    try:
                        yaw = float(yaw_str)
                    except ValueError:
                        pass

                # Battery
                bat_pct = None
                bat_volt = None
                bat_pct_str = clean_row.get("BATTERY.battery") or clean_row.get("BatteryPercentage")
                bat_volt_str = clean_row.get("BATTERY.voltage") or clean_row.get("BatteryVoltage")
                if bat_pct_str:
                    try:
                        bat_pct = float(bat_pct_str)
                    except ValueError:
                        pass
                if bat_volt_str:
                    try:
                        bat_volt = float(bat_volt_str)
                        if bat_volt > 100.0:
                            bat_volt = bat_volt / 1000.0  # mV to V
                    except ValueError:
                        pass

                # Flight Mode
                mode_str = clean_row.get("OSD.flyMode") or clean_row.get("FlyMode") or clean_row.get("Mode")
                if mode_str and mode_str != prev_mode:
                    events.append(
                        NormalizedEvent(
                            timestamp_utc=ev_ts,
                            source_platform="autel",
                            event_type=EventType.MODE_CHANGE.value,
                            source_file=str(file_path),
                            source_file_sha256=file_sha256,
                            flight_mode=mode_str,
                            payload={"aircraft_model": aircraft_model},
                        )
                    )
                    prev_mode = mode_str

                # GPS Fix or Battery Event
                if lat is not None and lon is not None:
                    events.append(
                        NormalizedEvent(
                            timestamp_utc=ev_ts,
                            source_platform="autel",
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
                            battery_remaining_pct=round(bat_pct, 1) if bat_pct is not None else None,
                            battery_voltage_v=round(bat_volt, 2) if bat_volt is not None else None,
                            flight_mode=mode_str,
                            payload={
                                "aircraft_model": aircraft_model,
                                "serial_number": serial_number,
                            },
                        )
                    )

        # Initial config metadata event
        events.insert(
            0,
            NormalizedEvent(
                timestamp_utc=base_time,
                source_platform="autel",
                event_type=EventType.CONFIG_PARAM.value,
                source_file=str(file_path),
                source_file_sha256=file_sha256,
                payload={
                    "aircraft_model": aircraft_model,
                    "serial_number": serial_number,
                },
            ),
        )

        return events

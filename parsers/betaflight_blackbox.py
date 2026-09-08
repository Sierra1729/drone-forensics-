"""
parsers/betaflight_blackbox.py

Forensic flight log parser for Betaflight, INAV, and Cleanflight Blackbox logs (.bbl, .csv).
Critical for defense and law enforcement investigations involving improvised FPV kamikaze drones,
border surveillance quads, and custom multirotors running STM32 flight controllers.
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
class BetaflightBlackboxParser(BaseParser):
    """Forensic parser for Betaflight / INAV Blackbox telemetry and crash dumps."""

    @property
    def parser_name(self) -> str:
        return "betaflight_blackbox"

    @property
    def supported_platforms(self) -> list[str]:
        return ["betaflight", "inav", "cleanflight", "fpv_blackbox"]

    def can_parse(self, file_path: Path) -> bool:
        """Inspect file header for Betaflight/INAV Blackbox tokens."""
        try:
            path = Path(file_path)
            if not path.is_file() or path.stat().st_size == 0:
                return False

            with open(path, "rb") as f:
                header_bytes = f.read(4096)

            # Check for Blackbox signature headers
            if b"H Product:Blackbox" in header_bytes or b"H Data version:" in header_bytes:
                return True
            if b"H Firmware type:Betaflight" in header_bytes or b"H Firmware type:INAV" in header_bytes:
                return True

            # Check for CSV export headers with Blackbox column signatures
            try:
                text_head = header_bytes.decode("utf-8", errors="ignore")
                first_lines = text_head.splitlines()[:5]
                for line in first_lines:
                    if ("loopIteration" in line and "time" in line) or ("GPS_coord[0]" in line and "GPS_coord[1]" in line):
                        return True
                    if "vbatLatest" in line and ("axisRate[0]" in line or "gyroADC[0]" in line):
                        return True
            except Exception:
                pass

            return False
        except Exception:
            return False

    def parse_records(
        self,
        file_path: Path,
        file_sha256: str,
    ) -> list[NormalizedEvent]:
        """Extract craft metadata, GPS coordinates, attitude, and battery metrics."""
        events: list[NormalizedEvent] = []
        path = Path(file_path)

        metadata: Dict[str, Any] = {
            "craft_name": "Unknown FPV/DIY Quad",
            "firmware_type": "Betaflight/INAV",
            "firmware_version": "Unknown",
            "log_date": None,
        }

        # Base reference time defaults to file mtime or UTC now
        base_time = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)

        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)
            header_row: Optional[List[str]] = None

            for line in f:
                line_str = line.strip()
                if not line_str:
                    continue

                # 1. Parse 'H ' Header metadata fields
                if line_str.startswith("H "):
                    tokens = line_str[2:].split(":", 1)
                    if len(tokens) == 2:
                        k, v = tokens[0].strip(), tokens[1].strip()
                        if k == "Craft name":
                            metadata["craft_name"] = v
                        elif k == "Firmware type":
                            metadata["firmware_type"] = v
                        elif k == "Firmware revision":
                            metadata["firmware_version"] = v
                        elif k == "Log start datetime":
                            try:
                                # Example: 2026-08-15T10:30:00.000+00:00
                                parsed_dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
                                if parsed_dt.tzinfo is None:
                                    parsed_dt = parsed_dt.replace(tzinfo=timezone.utc)
                                base_time = parsed_dt
                                metadata["log_date"] = v
                            except Exception:
                                pass
                    continue

                # 2. Check for CSV Column Header
                if header_row is None and ("loopIteration" in line_str or "time" in line_str or "GPS_coord[0]" in line_str):
                    header_io = io.StringIO(line_str)
                    header_row = [c.strip() for c in next(csv.reader(header_io))]
                    continue

                # 3. Parse Telemetry Row if header is active
                if header_row is not None:
                    row_io = io.StringIO(line_str)
                    row_vals = next(csv.reader(row_io), [])
                    if len(row_vals) != len(header_row):
                        continue

                    row_dict = dict(zip(header_row, row_vals))
                    try:
                        time_us_val = float(row_dict.get("time", 0.0) or 0.0)
                    except ValueError:
                        continue

                    ev_ts = base_time + timedelta(microseconds=time_us_val)

                    # Extract GPS if present
                    lat_str = row_dict.get("GPS_coord[0]") or row_dict.get("GPS_latitude")
                    lon_str = row_dict.get("GPS_coord[1]") or row_dict.get("GPS_longitude")
                    alt_str = row_dict.get("GPS_altitude") or row_dict.get("altitude")
                    spd_str = row_dict.get("GPS_speed") or row_dict.get("speed")
                    course_str = row_dict.get("GPS_ground_course") or row_dict.get("heading")
                    sats_str = row_dict.get("GPS_numSat") or row_dict.get("satellites")

                    lat = None
                    lon = None
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
                            if alt_m > 10000.0:
                                alt_m = alt_m / 100.0  # cm to meters
                        except ValueError:
                            pass

                    spd_mps = None
                    if spd_str:
                        try:
                            spd_mps = float(spd_str)
                            if spd_mps > 500.0:
                                spd_mps = spd_mps / 100.0  # cm/s to m/s
                        except ValueError:
                            pass

                    hdg = None
                    if course_str:
                        try:
                            hdg = float(course_str)
                            if hdg > 360.0:
                                hdg = hdg / 10.0  # deci-degrees
                        except ValueError:
                            pass

                    sats = None
                    if sats_str:
                        try:
                            sats = int(float(sats_str))
                        except ValueError:
                            pass

                    # Extract Battery
                    vbat_str = row_dict.get("vbatLatest") or row_dict.get("vbat")
                    vbat = None
                    if vbat_str:
                        try:
                            vbat = float(vbat_str)
                            if vbat > 100.0:
                                vbat = vbat / 100.0  # centivolts
                            elif vbat > 50.0:
                                vbat = vbat / 10.0
                        except ValueError:
                            pass

                    amp_str = row_dict.get("amperageLatest") or row_dict.get("amperage")
                    amp = None
                    if amp_str:
                        try:
                            amp = float(amp_str)
                            if amp > 1000.0:
                                amp = amp / 100.0  # centi-amps
                        except ValueError:
                            pass

                    # Extract Attitude / Rates
                    roll = None
                    pitch = None
                    yaw = None
                    for r_key in ["axisRate[0]", "gyroADC[0]", "roll"]:
                        if r_key in row_dict:
                            try:
                                roll = float(row_dict[r_key])
                                break
                            except ValueError:
                                pass
                    for p_key in ["axisRate[1]", "gyroADC[1]", "pitch"]:
                        if p_key in row_dict:
                            try:
                                pitch = float(row_dict[p_key])
                                break
                            except ValueError:
                                pass
                    for y_key in ["axisRate[2]", "gyroADC[2]", "yaw"]:
                        if y_key in row_dict:
                            try:
                                yaw = float(row_dict[y_key])
                                break
                            except ValueError:
                                pass

                    # Determine Event Type
                    if lat is not None and lon is not None:
                        events.append(
                            NormalizedEvent(
                                timestamp_utc=ev_ts,
                                source_platform="betaflight",
                                event_type=EventType.GPS_FIX.value,
                                source_file=str(file_path),
                                source_file_sha256=file_sha256,
                                latitude=lat,
                                longitude=lon,
                                altitude_m=alt_m,
                                ground_speed_mps=spd_mps,
                                heading_deg=hdg,
                                satellites_visible=sats,
                                battery_voltage_v=round(vbat, 2) if vbat is not None else None,
                                battery_current_a=round(amp, 2) if amp is not None else None,
                                pitch_deg=round(pitch, 2) if pitch is not None else None,
                                roll_deg=round(roll, 2) if roll is not None else None,
                                yaw_deg=round(yaw, 2) if yaw is not None else None,
                                payload={
                                    "craft_name": metadata["craft_name"],
                                    "firmware": metadata["firmware_type"],
                                },
                            )
                        )
                    elif vbat is not None:
                        events.append(
                            NormalizedEvent(
                                timestamp_utc=ev_ts,
                                source_platform="betaflight",
                                event_type=EventType.BATTERY_STATE.value,
                                source_file=str(file_path),
                                source_file_sha256=file_sha256,
                                battery_voltage_v=round(vbat, 2),
                                battery_current_a=round(amp, 2) if amp is not None else None,
                                payload={
                                    "craft_name": metadata["craft_name"],
                                },
                            )
                        )

        # Emit initial config/metadata event
        events.insert(
            0,
            NormalizedEvent(
                timestamp_utc=base_time,
                source_platform="betaflight",
                event_type=EventType.CONFIG_PARAM.value,
                source_file=str(file_path),
                source_file_sha256=file_sha256,
                payload=metadata,
            ),
        )

        return events

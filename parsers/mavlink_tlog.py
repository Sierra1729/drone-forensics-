"""
parsers/mavlink_tlog.py

Forensic parser for MAVLink Telemetry (.tlog) radio logs.

Forensic Capabilities:
- GCS downlink extraction: Parses radio telemetry captured by Mission Planner,
  QGroundControl, and ground station tablets.
- Decodes MAVLink v1 (0xFE) and MAVLink v2 (0xFD) packets.
- Extracts GLOBAL_POSITION_INT, ATTITUDE, SYS_STATUS, and STATUSTEXT events.
- Recovers flight modes from HEARTBEAT packets.
"""

from __future__ import annotations

import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from pymavlink import mavutil

from normalize.schema import NormalizedEvent, EventType
from parsers.base import BaseParser, register_parser

MAVLINK_V1_STX = 0xFE
MAVLINK_V2_STX = 0xFD


@register_parser
class MAVLinkTLogParser(BaseParser):
    """Parser for MAVLink Telemetry logs (.tlog)."""

    @property
    def parser_name(self) -> str:
        return "mavlink_telemetry_tlog"

    @property
    def supported_platforms(self) -> list[str]:
        return ["mavlink", "ardupilot", "px4", "qgroundcontrol", "mission_planner"]

    def can_parse(self, file_path: Path) -> bool:
        """Check for .tlog extension or MAVLink framing sync bytes (0xFE / 0xFD)."""
        path = Path(file_path)
        if not path.is_file():
            return False
        if path.suffix.lower() == ".tlog":
            return True
        try:
            with open(path, "rb") as f:
                header = f.read(16)
                # In .tlog files, each packet is prefixed by an 8-byte big-endian timestamp
                # followed by the MAVLink packet starting with 0xFE or 0xFD.
                if len(header) >= 9:
                    if header[8] in (MAVLINK_V1_STX, MAVLINK_V2_STX):
                        return True
                    if header[0] in (MAVLINK_V1_STX, MAVLINK_V2_STX):
                        return True
                return False
        except Exception:
            return False

    def parse_records(
        self,
        file_path: Path,
        file_sha256: str,
    ) -> list[NormalizedEvent]:
        try:
            mlog = mavutil.mavlink_connection(str(file_path))
        except Exception:
            return []

        events: list[NormalizedEvent] = []
        current_mode: Optional[str] = None

        # Track latest GPS quality metrics to enrich positions
        last_sats: Optional[int] = None
        last_hdop: Optional[float] = None

        while True:
            try:
                msg = mlog.recv_match(blocking=False)
            except Exception:
                continue

            if msg is None:
                break

            msg_type = msg.get_type()
            if msg_type == "BAD_DATA":
                continue

            # In pymavlink, msg._timestamp contains the packet reception epoch seconds
            raw_ts = getattr(msg, "_timestamp", None)
            if raw_ts and raw_ts > 1_000_000_000:
                event_ts = datetime.fromtimestamp(raw_ts, tz=timezone.utc)
            else:
                event_ts = datetime.now(timezone.utc)

            base_kwargs: dict[str, Any] = {
                "timestamp_utc": event_ts,
                "source_platform": "mavlink",
                "source_file": str(file_path),
                "source_file_sha256": file_sha256,
                "flight_mode": current_mode,
            }

            if msg_type == "HEARTBEAT":
                custom_mode = getattr(msg, "custom_mode", 0)
                type_id = getattr(msg, "type", 0)
                current_mode = f"MODE_{custom_mode}"

            elif msg_type == "GPS_RAW_INT":
                last_sats = getattr(msg, "satellites_visible", None)
                eph = getattr(msg, "eph", None)
                last_hdop = round(eph / 100.0, 2) if eph is not None else None

            elif msg_type == "GLOBAL_POSITION_INT":
                lat = getattr(msg, "lat", None)
                lon = getattr(msg, "lon", None)
                alt = getattr(msg, "relative_alt", getattr(msg, "alt", None))
                vx = getattr(msg, "vx", 0)
                vy = getattr(msg, "vy", 0)
                hdg = getattr(msg, "hdg", None)

                lat_val = lat / 1e7 if lat is not None else None
                lon_val = lon / 1e7 if lon is not None else None
                alt_val = alt / 1000.0 if alt is not None else None
                spd_val = round(math.sqrt(vx * vx + vy * vy) / 100.0, 2)
                hdg_val = hdg / 100.0 if hdg is not None and hdg <= 36000 else None

                ev = NormalizedEvent(
                    event_type=EventType.GPS_FIX.value,
                    latitude=lat_val,
                    longitude=lon_val,
                    altitude_m=alt_val,
                    ground_speed_mps=spd_val,
                    heading_deg=hdg_val,
                    satellites_visible=last_sats,
                    hdop=last_hdop,
                    payload={"msg_type": "GLOBAL_POSITION_INT"},
                    **base_kwargs,
                )
                events.append(ev)

            elif msg_type == "ATTITUDE":
                roll = getattr(msg, "roll", None)
                pitch = getattr(msg, "pitch", None)
                yaw = getattr(msg, "yaw", None)

                ev = NormalizedEvent(
                    event_type=EventType.IMU_SAMPLE.value,
                    roll_deg=round(math.degrees(roll), 2) if roll is not None else None,
                    pitch_deg=round(math.degrees(pitch), 2) if pitch is not None else None,
                    yaw_deg=round(math.degrees(yaw), 2) if yaw is not None else None,
                    payload={"msg_type": "ATTITUDE"},
                    **base_kwargs,
                )
                events.append(ev)

            elif msg_type in ("SYS_STATUS", "BATTERY_STATUS"):
                volt_raw = getattr(msg, "voltage_battery", None)
                curr_raw = getattr(msg, "current_battery", None)
                rem_raw = getattr(msg, "battery_remaining", None)

                volt = round(volt_raw / 1000.0, 2) if volt_raw and volt_raw > 0 else None
                curr = round(curr_raw / 100.0, 2) if curr_raw and curr_raw >= 0 else None
                rem = float(rem_raw) if rem_raw and rem_raw >= 0 else None

                ev = NormalizedEvent(
                    event_type=EventType.BATTERY_STATE.value,
                    battery_voltage_v=volt,
                    battery_current_a=curr,
                    battery_remaining_pct=rem,
                    payload={"msg_type": msg_type},
                    **base_kwargs,
                )
                events.append(ev)

            elif msg_type == "STATUSTEXT":
                text = str(getattr(msg, "text", "")).strip()
                severity = getattr(msg, "severity", 0)

                event_type = EventType.RAW.value
                lower_txt = text.lower()
                if any(w in lower_txt for w in ["arm", "disarm"]):
                    event_type = EventType.ARM_DISARM.value
                elif any(w in lower_txt for w in ["rtl", "return", "failsafe"]):
                    event_type = EventType.RTH_TRIGGER.value
                elif any(w in lower_txt for w in ["geofence", "nfz"]):
                    event_type = EventType.GEOFENCE_BREACH.value

                ev = NormalizedEvent(
                    event_type=event_type,
                    payload={"message": text, "severity": severity},
                    **base_kwargs,
                )
                events.append(ev)

        return events

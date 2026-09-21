"""
parsers/parrot.py

Forensic parser for Parrot UAV flight logs (Parrot ANAFI, ANAFI Thermal, ANAFI USA, Bebop).

Forensic Capabilities:
- Structure detection: Identifies Parrot FreeFlight JSON and telemetry export logs.
- Dual-entity identification: Recovers both Aircraft and Skycontroller serial numbers,
  hardware models, firmware versions, and run IDs.
- Kinematic & sensor normalization: Extracts GPS fixes, barometric altitude, velocity,
  attitude (pitch, roll, yaw), battery voltage/percentage, and satellite visibility.
- Operational event mapping: Normalizes takeoff, landing, return-to-home, and app alerts.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Optional

from normalize.schema import NormalizedEvent, EventType
from parsers.base import BaseParser, register_parser


@register_parser
class ParrotFlightLogParser(BaseParser):
    """Parser for Parrot ANAFI and Bebop series JSON flight logs."""

    @property
    def parser_name(self) -> str:
        return "parrot_anafi_json"

    @property
    def parser_version(self) -> str:
        return "1.0.0"

    @property
    def supported_platforms(self) -> list[str]:
        return ["parrot", "parrot_anafi", "parrot_bebop"]

    def can_parse(self, file_path: Path) -> bool:
        """Inspect file content to identify Parrot JSON flight logs."""
        path = Path(file_path)
        if not path.is_file():
            return False
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                prefix = f.read(1024)
                if not prefix.strip().startswith("{"):
                    return False
                # Check for characteristic Parrot keys
                lower_prefix = prefix.lower()
                if "parrot" in lower_prefix or "anafi" in lower_prefix or "skycontroller" in lower_prefix:
                    return True
                if "run_id" in lower_prefix and "telemetry" in lower_prefix:
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
            data = json.loads(file_path.read_text(encoding="utf-8", errors="replace"))
        except json.JSONDecodeError:
            return []

        if not isinstance(data, dict):
            return []

        # 1. Parse Equipment Metadata
        drone_model = data.get("drone_model", "Parrot ANAFI Series")
        serial_number = data.get("serial_number", "UNKNOWN")
        firmware_ver = data.get("firmware_version", "UNKNOWN")
        run_id = data.get("run_id", "")
        flight_date_raw = data.get("flight_date")

        start_time_utc: datetime
        if flight_date_raw:
            try:
                start_time_utc = datetime.fromisoformat(flight_date_raw.replace("Z", "+00:00"))
                if start_time_utc.tzinfo is None:
                    start_time_utc = start_time_utc.replace(tzinfo=timezone.utc)
                else:
                    start_time_utc = start_time_utc.astimezone(timezone.utc)
            except Exception:
                start_time_utc = datetime.now(timezone.utc)
        else:
            start_time_utc = datetime.now(timezone.utc)

        controller_info = data.get("controller", {})

        events: list[NormalizedEvent] = []

        # Initial Configuration & Identity Event
        meta_event = NormalizedEvent(
            timestamp_utc=start_time_utc,
            source_platform="parrot",
            event_type=EventType.CONFIG_PARAM.value,
            source_file=str(file_path),
            source_file_sha256=file_sha256,
            payload={
                "aircraft_model": drone_model,
                "serial_number": serial_number,
                "firmware_version": firmware_ver,
                "run_id": run_id,
                "controller_model": controller_info.get("model", "N/A"),
                "controller_serial": controller_info.get("serial_number", "N/A"),
            },
        )
        events.append(meta_event)

        # 2. Parse High-Frequency Telemetry Stream
        telemetry_records = data.get("telemetry", [])
        current_mode: Optional[str] = None

        for item in telemetry_records:
            if not isinstance(item, dict):
                continue

            offset_ms = item.get("timestamp_ms", 0)
            event_ts = start_time_utc + timedelta(milliseconds=offset_ms)

            lat = item.get("latitude")
            lng = item.get("longitude")
            alt = item.get("altitude_m")
            spd = item.get("speed_mps")
            heading = item.get("heading_deg")
            pitch = item.get("pitch_deg")
            roll = item.get("roll_deg")
            yaw = item.get("yaw_deg")
            batt_pct = item.get("battery_pct")
            batt_volt = item.get("battery_voltage_v")
            sats = item.get("satellites")
            hdop = item.get("hdop")
            mode = item.get("flight_mode")

            if mode:
                current_mode = str(mode)

            ev = NormalizedEvent(
                timestamp_utc=event_ts,
                source_platform="parrot",
                event_type=EventType.GPS_FIX.value,
                source_file=str(file_path),
                source_file_sha256=file_sha256,
                latitude=float(lat) if lat is not None else None,
                longitude=float(lng) if lng is not None else None,
                altitude_m=float(alt) if alt is not None else None,
                ground_speed_mps=float(spd) if spd is not None else None,
                heading_deg=float(heading) if heading is not None else None,
                pitch_deg=float(pitch) if pitch is not None else None,
                roll_deg=float(roll) if roll is not None else None,
                yaw_deg=float(yaw) if yaw is not None else None,
                satellites_visible=int(sats) if sats is not None else None,
                hdop=float(hdop) if hdop is not None else None,
                battery_remaining_pct=float(batt_pct) if batt_pct is not None else None,
                battery_voltage_v=float(batt_volt) if batt_volt is not None else None,
                flight_mode=current_mode,
                payload={
                    "offset_ms": offset_ms,
                    "is_flying": item.get("is_flying", False),
                },
            )
            events.append(ev)

        # 3. Parse Operational Safety & Navigation Events
        event_records = data.get("events", [])
        for ev_item in event_records:
            if not isinstance(ev_item, dict):
                continue

            offset_ms = ev_item.get("timestamp_ms", 0)
            event_ts = start_time_utc + timedelta(milliseconds=offset_ms)
            ev_type_raw = str(ev_item.get("event_type", "")).lower()
            msg = ev_item.get("message", "")

            event_type = EventType.RAW.value
            if any(w in ev_type_raw for w in ["takeoff", "landing", "arm", "disarm"]):
                event_type = EventType.ARM_DISARM.value
            elif any(w in ev_type_raw for w in ["rth", "return", "failsafe"]):
                event_type = EventType.RTH_TRIGGER.value
            elif any(w in ev_type_raw for w in ["geofence", "nfz"]):
                event_type = EventType.GEOFENCE_BREACH.value

            ev = NormalizedEvent(
                timestamp_utc=event_ts,
                source_platform="parrot",
                event_type=event_type,
                source_file=str(file_path),
                source_file_sha256=file_sha256,
                flight_mode=current_mode,
                payload={
                    "parrot_event": ev_type_raw,
                    "message": msg,
                    "offset_ms": offset_ms,
                },
            )
            events.append(ev)

        return events

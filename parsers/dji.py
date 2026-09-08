"""
parsers/dji.py

Forensic parser for DJI flight logs (Mobile App Flight Records and Onboard Logs).

Forensic Capabilities:
- Header identification: Decodes aircraft model, serial number, and flight session metadata.
- OSD telemetry extraction: Decodes GPS coordinates, barometric altitude, ground speed,
  Euler attitude (pitch, roll, yaw), satellite counts, and flight modes (P-GPS, Sport, RTH).
- Battery telemetry extraction: Unpacks pack voltage, discharge current, and state of charge.
- Mission event extraction: Home point establishment, low-battery failsafe triggers,
  geofence notifications, and return-to-home activations.
- Resilient stream scanner: Uses frame synchronization markers (0x55) to recover
  telemetry across damaged or corrupted log spans.
"""

from __future__ import annotations

import struct
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Optional

from normalize.schema import NormalizedEvent, EventType
from parsers.base import BaseParser, register_parser

# DJI Frame Sync Delimiters
DJI_HEADER_MAGIC = b"DJI_LOG_V"
DJI_FRAME_SYNC = 0x55
DJI_FRAME_END = 0xFF

# Record Types
REC_OSD = 0x01
REC_HOME = 0x02
REC_BATTERY = 0x03
REC_EVENT = 0x04


@register_parser
class DJIFlightLogParser(BaseParser):
    """Parser for DJI Flight Record logs (.txt and .dat)."""

    @property
    def parser_name(self) -> str:
        return "dji_flight_log"

    @property
    def supported_platforms(self) -> list[str]:
        return ["dji", "dji_fly", "dji_go4"]

    def can_parse(self, file_path: Path) -> bool:
        """Check for DJI magic header signature in first 100 bytes."""
        path = Path(file_path)
        if not path.is_file():
            return False
        try:
            with open(path, "rb") as f:
                header = f.read(100)
                if len(header) < 16:
                    return False
                # Direct signature check
                if header.startswith(DJI_HEADER_MAGIC):
                    return True
                # Binary marker check [0x55, 0xAA] or presence of DJI header token
                if header[0:2] == b"\x55\xAA" and b"DJI" in header:
                    return True
                return False
        except Exception:
            return False

    def parse_records(
        self,
        file_path: Path,
        file_sha256: str,
    ) -> list[NormalizedEvent]:
        raw_bytes = file_path.read_bytes()
        file_len = len(raw_bytes)

        if file_len < 100:
            return []

        # 1. Parse File Header (100 bytes)
        # Format:
        # 16s: Magic / Version
        # 32s: Aircraft Model
        # 16s: Serial Number
        # Q: Start Timestamp UTC (epoch ms)
        # f: Total Distance (m)
        # f: Total Flight Time (s)
        # 16s: Reserved / padding
        header_fmt = "<16s32s16sQff16s"
        if struct.calcsize(header_fmt) > 100:
            header_fmt = "<16s32s16sQff"

        header_fields = struct.unpack_from(header_fmt, raw_bytes, 0)
        aircraft_model = header_fields[1].split(b"\x00")[0].decode("ascii", errors="replace").strip()
        serial_number = header_fields[2].split(b"\x00")[0].decode("ascii", errors="replace").strip()
        start_epoch_ms = header_fields[3]

        start_time_utc = datetime.fromtimestamp(start_epoch_ms / 1000.0, tz=timezone.utc)

        events: list[NormalizedEvent] = []

        # Record initial equipment identification event
        metadata_event = NormalizedEvent(
            timestamp_utc=start_time_utc,
            source_platform="dji",
            event_type=EventType.CONFIG_PARAM.value,
            source_file=str(file_path),
            source_file_sha256=file_sha256,
            payload={
                "aircraft_model": aircraft_model,
                "serial_number": serial_number,
                "flight_start_utc": start_time_utc.isoformat(),
            },
        )
        events.append(metadata_event)

        # 2. Iterate through record frames starting after header (offset 100)
        offset = 100
        current_mode: Optional[str] = None

        while offset < file_len - 4:
            if raw_bytes[offset] == DJI_FRAME_SYNC:
                rec_type = raw_bytes[offset + 1]
                payload_len = raw_bytes[offset + 2]
                frame_len = 3 + payload_len + 1  # sync(1) + type(1) + len(1) + payload + end(1)

                if offset + frame_len <= file_len and raw_bytes[offset + frame_len - 1] == DJI_FRAME_END:
                    payload = raw_bytes[offset + 3: offset + 3 + payload_len]

                    ev = self._parse_frame(
                        rec_type=rec_type,
                        payload=payload,
                        start_time_utc=start_time_utc,
                        file_path=str(file_path),
                        file_sha256=file_sha256,
                        current_mode=current_mode,
                    )
                    if ev is not None:
                        if ev.flight_mode:
                            current_mode = ev.flight_mode
                        events.append(ev)

                    offset += frame_len
                    continue
            offset += 1

        return events

    def _parse_frame(
        self,
        rec_type: int,
        payload: bytes,
        start_time_utc: datetime,
        file_path: str,
        file_sha256: str,
        current_mode: Optional[str],
    ) -> Optional[NormalizedEvent]:
        """Decode individual DJI record frame."""
        try:
            if rec_type == REC_OSD:
                # OSD Struct:
                # d: Lat, d: Lng, f: Alt, f: Spd, f: Heading,
                # f: Pitch, f: Roll, f: Yaw, 16s: FlightMode,
                # B: BattPct, B: SatCount, f: HDOP, I: OffsetMs
                fmt = "<ddffffff16sBBfI"
                if len(payload) < struct.calcsize(fmt):
                    return None
                vals = struct.unpack_from(fmt, payload, 0)
                lat, lng, alt, spd, heading = vals[0], vals[1], vals[2], vals[3], vals[4]
                pitch, roll, yaw = vals[5], vals[6], vals[7]
                flight_mode_raw = vals[8].split(b"\x00")[0].decode("ascii", errors="replace").strip()
                batt_pct, sat_count, hdop, offset_ms = vals[9], vals[10], vals[11], vals[12]

                event_ts = start_time_utc + timedelta(milliseconds=offset_ms)

                return NormalizedEvent(
                    timestamp_utc=event_ts,
                    source_platform="dji",
                    event_type=EventType.GPS_FIX.value,
                    source_file=file_path,
                    source_file_sha256=file_sha256,
                    latitude=float(lat),
                    longitude=float(lng),
                    altitude_m=float(alt),
                    ground_speed_mps=float(spd),
                    heading_deg=float(heading),
                    pitch_deg=float(pitch),
                    roll_deg=float(roll),
                    yaw_deg=float(yaw),
                    satellites_visible=int(sat_count),
                    hdop=float(hdop),
                    battery_remaining_pct=float(batt_pct),
                    flight_mode=flight_mode_raw if flight_mode_raw else current_mode,
                    payload={
                        "rec_type": "OSD",
                        "offset_ms": offset_ms,
                    },
                )

            elif rec_type == REC_HOME:
                # Home Point: d: Lat, d: Lng, f: RthAlt, I: OffsetMs
                fmt = "<ddfI"
                if len(payload) < struct.calcsize(fmt):
                    return None
                lat, lng, rth_alt, offset_ms = struct.unpack_from(fmt, payload, 0)
                event_ts = start_time_utc + timedelta(milliseconds=offset_ms)

                return NormalizedEvent(
                    timestamp_utc=event_ts,
                    source_platform="dji",
                    event_type=EventType.CONFIG_PARAM.value,
                    source_file=file_path,
                    source_file_sha256=file_sha256,
                    latitude=float(lat),
                    longitude=float(lng),
                    altitude_m=float(rth_alt),
                    flight_mode=current_mode,
                    payload={
                        "rec_type": "HOME_POINT",
                        "rth_altitude_m": rth_alt,
                    },
                )

            elif rec_type == REC_BATTERY:
                # Battery: f: Volt, f: Curr, f: RemPct, f: TempC, I: OffsetMs
                fmt = "<ffffI"
                if len(payload) < struct.calcsize(fmt):
                    return None
                volt, curr, rem_pct, temp_c, offset_ms = struct.unpack_from(fmt, payload, 0)
                event_ts = start_time_utc + timedelta(milliseconds=offset_ms)

                return NormalizedEvent(
                    timestamp_utc=event_ts,
                    source_platform="dji",
                    event_type=EventType.BATTERY_STATE.value,
                    source_file=file_path,
                    source_file_sha256=file_sha256,
                    battery_voltage_v=float(volt),
                    battery_current_a=float(curr),
                    battery_remaining_pct=float(rem_pct),
                    flight_mode=current_mode,
                    payload={
                        "rec_type": "BATTERY_INFO",
                        "temperature_c": temp_c,
                        "offset_ms": offset_ms,
                    },
                )

            elif rec_type == REC_EVENT:
                # Event / Warning: B: EventCode, 64s: Message, I: OffsetMs
                fmt = "<B64sI"
                if len(payload) < struct.calcsize(fmt):
                    return None
                event_code, msg_bytes, offset_ms = struct.unpack_from(fmt, payload, 0)
                msg_text = msg_bytes.split(b"\x00")[0].decode("ascii", errors="replace").strip()
                event_ts = start_time_utc + timedelta(milliseconds=offset_ms)

                event_type = EventType.RAW.value
                if "rtl" in msg_text.lower() or "rth" in msg_text.lower() or "return" in msg_text.lower():
                    event_type = EventType.RTH_TRIGGER.value
                elif "geofence" in msg_text.lower() or "nfz" in msg_text.lower():
                    event_type = EventType.GEOFENCE_BREACH.value
                elif "arm" in msg_text.lower():
                    event_type = EventType.ARM_DISARM.value

                return NormalizedEvent(
                    timestamp_utc=event_ts,
                    source_platform="dji",
                    event_type=event_type,
                    source_file=file_path,
                    source_file_sha256=file_sha256,
                    flight_mode=current_mode,
                    payload={
                        "rec_type": "APP_WARNING",
                        "event_code": event_code,
                        "message": msg_text,
                        "offset_ms": offset_ms,
                    },
                )

        except Exception:
            return None

        return None

"""
parsers/ardupilot.py

Native binary parser for ArduPilot DataFlash (.BIN) flight logs.

Forensic Capabilities:
- Pure binary stream parsing: dynamically unpacks FMT declarations.
- Time-synchronization engine: resolves GPS Week (GWk) and GPS Milliseconds (GMS)
  against flight controller boot microseconds (TimeUS) into UTC timestamps.
- Resilient stream scanner: re-synchronizes on sync bytes (0xA3, 0x95) when
  encountering corrupted or partial packets.
- Extracts GPS fixes, IMU attitude, battery telemetry, flight mode changes,
  configuration parameters, system error codes, and onboard text messages.
"""

from __future__ import annotations

import re
import struct
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Optional

from normalize.schema import NormalizedEvent, EventType
from parsers.base import BaseParser, register_parser

# ArduPilot DataFlash Packet Sync Bytes
HEAD1 = 0xA3
HEAD2 = 0x95
FMT_MSG_TYPE = 0x80

# GPS epoch: 1980-01-06 00:00:00 UTC
GPS_EPOCH = datetime(1980, 1, 6, 0, 0, 0, tzinfo=timezone.utc)
# Number of leap seconds between GPS time and UTC (as of current standards: 18 seconds)
GPS_LEAP_SECONDS = 18

# Struct format character map for ArduPilot FMT format descriptors
TYPE_MAP: dict[str, tuple[str, int, Optional[float]]] = {
    # char: (struct_code, size_bytes, scale_factor)
    "b": ("b", 1, None),
    "B": ("B", 1, None),
    "h": ("h", 2, None),
    "H": ("H", 2, None),
    "i": ("i", 4, None),
    "I": ("I", 4, None),
    "f": ("f", 4, None),
    "d": ("d", 8, None),
    "n": ("4s", 4, None),
    "N": ("16s", 16, None),
    "Z": ("64s", 64, None),
    "c": ("h", 2, 0.01),       # int16 * 100 -> divide by 100
    "C": ("H", 2, 0.01),       # uint16 * 100
    "e": ("i", 4, 0.01),       # int32 * 100
    "E": ("I", 4, 0.01),       # uint32 * 100
    "L": ("i", 4, 1e-7),       # latitude / longitude * 1e7
    "M": ("B", 1, None),       # flight mode uint8
    "q": ("q", 8, None),       # int64
    "Q": ("Q", 8, None),       # uint64
}


class FormatDefinition:
    """Represents an unpacked FMT message definition."""

    def __init__(
        self,
        msg_type: int,
        msg_len: int,
        name: str,
        fmt_str: str,
        labels_str: str,
    ) -> None:
        self.msg_type = msg_type
        self.msg_len = msg_len
        self.name = name.strip("\x00").strip()
        self.fmt_str = fmt_str.strip("\x00").strip()
        self.labels = [lbl.strip() for lbl in labels_str.strip("\x00").split(",") if lbl.strip()]

        # Build struct unpacker
        struct_chars = ["<"]
        self.scales: list[Optional[float]] = []
        for char in self.fmt_str:
            if char in TYPE_MAP:
                code, _, scale = TYPE_MAP[char]
                struct_chars.append(code)
                self.scales.append(scale)
            else:
                # Default to uint8 placeholder if unknown
                struct_chars.append("B")
                self.scales.append(None)
        self.struct_fmt = "".join(struct_chars)

    def unpack(self, payload: bytes) -> Optional[dict[str, Any]]:
        """Unpack raw payload bytes into a dictionary of labeled fields."""
        try:
            values = struct.unpack(self.struct_fmt, payload)
        except struct.error:
            return None

        result: dict[str, Any] = {}
        for i, val in enumerate(values):
            if i >= len(self.labels):
                break
            label = self.labels[i]
            scale = self.scales[i]
            if isinstance(val, bytes):
                # Clean strings
                val = val.split(b"\x00")[0].decode("ascii", errors="replace").strip()
            elif scale is not None and isinstance(val, (int, float)):
                val = val * scale
            result[label] = val
        return result


@register_parser
class ArduPilotDataFlashParser(BaseParser):
    """Parser for ArduPilot / PX4 DataFlash binary (.BIN) flight logs."""

    @property
    def parser_name(self) -> str:
        return "ardupilot_dataflash_bin"

    @property
    def parser_version(self) -> str:
        return "1.0.0"

    @property
    def supported_platforms(self) -> list[str]:
        return ["ardupilot", "px4", "pixhawk"]

    def can_parse(self, file_path: Path) -> bool:
        """Inspect file header: binary sync bytes (0xA3 0x95 0x80) or ASCII FMT declarations."""
        path = Path(file_path)
        if not path.is_file() or path.stat().st_size == 0:
            return False
        try:
            with open(path, "rb") as f:
                header = f.read(512)
                if len(header) >= 3 and header[0] == HEAD1 and header[1] == HEAD2 and header[2] == FMT_MSG_TYPE:
                    return True
                if b"FMT," in header or b"PARM," in header or (path.suffix.lower() == ".log" and b"GPS," in header):
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

        if not (file_len >= 3 and raw_bytes[0] == HEAD1 and raw_bytes[1] == HEAD2):
            if b"FMT," in raw_bytes[:2048] or b"PARM," in raw_bytes[:2048]:
                return self._parse_ascii_records(file_path, file_sha256)

        # 1. First pass: parse FMT definitions and establish absolute GPS time reference
        formats: dict[int, FormatDefinition] = {}
        # Preload the FMT message format itself:
        # FMT message type 0x80: type(B), length(B), name(4s), format(16s), labels(64s) = 86 bytes payload
        formats[FMT_MSG_TYPE] = FormatDefinition(
            msg_type=FMT_MSG_TYPE,
            msg_len=89,
            name="FMT",
            fmt_str="BBnNZ",
            labels_str="Type,Length,Name,Format,Labels",
        )

        offset = 0
        boot_utc_ref: Optional[datetime] = None

        # Two-pass parsing:
        # Pass 1: Collect formats and determine boot_utc_ref from GPS message
        while offset < file_len - 3:
            if raw_bytes[offset] == HEAD1 and raw_bytes[offset + 1] == HEAD2:
                msg_type = raw_bytes[offset + 2]
                fmt_def = formats.get(msg_type)
                if fmt_def is not None:
                    msg_len = fmt_def.msg_len
                    if offset + msg_len <= file_len:
                        payload = raw_bytes[offset + 3: offset + msg_len]
                        fields = fmt_def.unpack(payload)
                        if fields:
                            if msg_type == FMT_MSG_TYPE:
                                new_type = fields.get("Type")
                                new_len = fields.get("Length")
                                new_name = fields.get("Name")
                                new_fmt = fields.get("Format")
                                new_lbl = fields.get("Labels") or fields.get("Columns") or ""
                                if isinstance(new_type, int) and isinstance(new_len, int):
                                    formats[new_type] = FormatDefinition(
                                        msg_type=new_type,
                                        msg_len=new_len,
                                        name=str(new_name),
                                        fmt_str=str(new_fmt),
                                        labels_str=str(new_lbl),
                                    )

                            elif fmt_def.name == "GPS" and boot_utc_ref is None:
                                # Try extracting GPS time
                                gwk = fields.get("GWk") or fields.get("Week")
                                gms = fields.get("GMS") or fields.get("TimeMS")
                                time_us = fields.get("TimeUS")
                                if time_us is None and "TimeMS" in fields:
                                    time_us = fields["TimeMS"] * 1000
                                if gwk is not None and gms is not None and time_us is not None and gwk > 1000:
                                    gps_time = GPS_EPOCH + timedelta(weeks=gwk, milliseconds=gms)
                                    utc_time = gps_time - timedelta(seconds=GPS_LEAP_SECONDS)
                                    boot_utc_ref = utc_time - timedelta(microseconds=time_us)
                        offset += msg_len
                        continue
            offset += 1

        # Fallback time reference if no GPS time available in log
        if boot_utc_ref is None:
            # Use file modification time as fallback reference point
            mtime = file_path.stat().st_mtime
            boot_utc_ref = datetime.fromtimestamp(mtime, tz=timezone.utc)
            time_provenance = "file_mtime_anchor"
        else:
            time_provenance = "gps_clock_sync"

        # Pass 2: Extract normalized events
        events: list[NormalizedEvent] = []
        offset = 0
        current_mode: Optional[str] = None

        while offset < file_len - 3:
            if raw_bytes[offset] == HEAD1 and raw_bytes[offset + 1] == HEAD2:
                msg_type = raw_bytes[offset + 2]
                fmt_def = formats.get(msg_type)
                if fmt_def is not None:
                    msg_len = fmt_def.msg_len
                    if offset + msg_len <= file_len:
                        payload = raw_bytes[offset + 3: offset + msg_len]
                        fields = fmt_def.unpack(payload)
                        if fields:
                            ev = self._create_normalized_event(
                                fmt_name=fmt_def.name,
                                fields=fields,
                                boot_utc_ref=boot_utc_ref,
                                time_provenance=time_provenance,
                                file_path=str(file_path),
                                file_sha256=file_sha256,
                                current_mode=current_mode,
                            )
                            if ev is not None:
                                if ev.flight_mode:
                                    current_mode = ev.flight_mode
                                events.append(ev)
                        offset += msg_len
                        continue
            offset += 1

        return events

    def _create_normalized_event(
        self,
        fmt_name: str,
        fields: dict[str, Any],
        boot_utc_ref: datetime,
        time_provenance: str,
        file_path: str,
        file_sha256: str,
        current_mode: Optional[str],
    ) -> Optional[NormalizedEvent]:
        """Convert an unpacked DataFlash message to a NormalizedEvent."""
        # Determine timestamp
        time_us = fields.get("TimeUS")
        if time_us is None and "TimeMS" in fields:
            time_us = fields["TimeMS"] * 1000

        if time_us is not None and isinstance(time_us, (int, float)):
            event_ts = boot_utc_ref + timedelta(microseconds=time_us)
        else:
            event_ts = boot_utc_ref

        base_kwargs: dict[str, Any] = {
            "timestamp_utc": event_ts,
            "source_platform": "ardupilot",
            "source_file": file_path,
            "source_file_sha256": file_sha256,
            "flight_mode": current_mode,
            "payload": {
                "msg_name": fmt_name,
                "time_provenance": time_provenance,
                **fields,
            },
        }

        if fmt_name == "GPS":
            lat = fields.get("Lat") or fields.get("Latitude")
            lng = fields.get("Lng") or fields.get("Lon") or fields.get("Longitude")
            alt = fields.get("Alt") or fields.get("Altitude")
            spd = fields.get("Spd") or fields.get("Speed") or fields.get("GSpd")
            gcrs = fields.get("GCrs") or fields.get("Yaw") or fields.get("Heading")
            nsats = fields.get("NSats") or fields.get("NumSats")
            hdop = fields.get("HDop") or fields.get("EPH")

            # Filter Null-Island (0,0 pre-fix) coordinates
            if lat is not None and lng is not None:
                if abs(float(lat)) < 0.0001 and abs(float(lng)) < 0.0001:
                    lat = None
                    lng = None

            return NormalizedEvent(
                event_type=EventType.GPS_FIX.value,
                latitude=float(lat) if lat is not None else None,
                longitude=float(lng) if lng is not None else None,
                altitude_m=float(alt) if alt is not None else None,
                ground_speed_mps=float(spd) if spd is not None else None,
                heading_deg=float(gcrs) if gcrs is not None else None,
                satellites_visible=int(nsats) if nsats is not None else None,
                hdop=float(hdop) if hdop is not None else None,
                **base_kwargs,
            )

        elif fmt_name == "ATT":
            roll = fields.get("Roll")
            pitch = fields.get("Pitch")
            yaw = fields.get("Yaw")
            return NormalizedEvent(
                event_type=EventType.IMU_SAMPLE.value,
                roll_deg=float(roll) if roll is not None else None,
                pitch_deg=float(pitch) if pitch is not None else None,
                yaw_deg=float(yaw) if yaw is not None else None,
                **base_kwargs,
            )

        elif fmt_name in ("BAT", "CURR", "POWR"):
            volt = fields.get("Volt") or fields.get("Vcc")
            curr = fields.get("Curr")
            rem_pct = fields.get("RemPct")
            if fmt_name == "CURR" and volt is not None and volt > 100.0:
                volt = volt / 100.0
            if fmt_name == "CURR" and curr is not None and curr > 100.0:
                curr = curr / 100.0
            return NormalizedEvent(
                event_type=EventType.BATTERY_STATE.value,
                battery_voltage_v=float(volt) if volt is not None else None,
                battery_current_a=float(curr) if curr is not None else None,
                battery_remaining_pct=float(rem_pct) if rem_pct is not None else None,
                **base_kwargs,
            )

        elif fmt_name == "BARO":
            baro_alt = fields.get("Alt")
            return NormalizedEvent(
                event_type=EventType.BAROMETER.value,
                altitude_m=float(baro_alt) if baro_alt is not None else None,
                **base_kwargs,
            )

        elif fmt_name == "MODE":
            mode_val = fields.get("Mode")
            mode_name = str(mode_val) if mode_val is not None else "UNKNOWN"
            mode_kwargs = dict(base_kwargs)
            mode_kwargs["flight_mode"] = mode_name
            return NormalizedEvent(
                event_type=EventType.MODE_CHANGE.value,
                **mode_kwargs,
            )

        elif fmt_name == "MSG":
            msg_text = str(fields.get("Message", ""))
            lower_msg = msg_text.lower()
            if re.search(r"\b(arming|disarming|armed|disarmed|motors armed|motors disarmed)\b", lower_msg) or (re.search(r"\b(arm|disarm)\b", lower_msg) and not any(nob in lower_msg for nob in ["param", "action", "alarm", "warm", "clear_m", "parm"])):
                event_type = EventType.ARM_DISARM.value
            elif any(w in lower_msg for w in ["rtl", "return", "failsafe", "emergency"]):
                event_type = EventType.RTH_TRIGGER.value
            elif any(w in lower_msg for w in ["geofence", "nfz"]):
                event_type = EventType.GEOFENCE_BREACH.value
            elif any(w in lower_msg for w in ["warn", "fail", "error", "out of range", "sensor", "imu", "mag", "baro"]):
                event_type = EventType.SENSOR_WARNING.value
            else:
                event_type = EventType.SYSTEM_STATUS.value

            return NormalizedEvent(
                event_type=event_type,
                **base_kwargs,
            )


        elif fmt_name == "PARM":
            return NormalizedEvent(
                event_type=EventType.CONFIG_PARAM.value,
                **base_kwargs,
            )

        return None

    def _parse_ascii_records(
        self,
        file_path: Path,
        file_sha256: str,
    ) -> list[NormalizedEvent]:
        """Parse text-based ArduPilot DataFlash logs (.log)."""
        formats: dict[str, list[str]] = {}
        events: list[NormalizedEvent] = []
        base_time = datetime.fromtimestamp(file_path.stat().st_mtime, tz=timezone.utc)
        current_mode = "STABILIZE"

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                parts = [p.strip() for p in line.strip().split(",")]
                if not parts or not parts[0]:
                    continue
                msg_name = parts[0]
                if msg_name == "FMT" and len(parts) >= 6:
                    name = parts[3]
                    cols = parts[5:]
                    formats[name] = cols
                elif msg_name in formats:
                    cols = formats[msg_name]
                    vals = parts[1:]
                    row = dict(zip(cols, vals))
                    
                    time_ms_val = float(row.get("TimeMS", 0) or 0)
                    ev_ts = base_time + timedelta(milliseconds=time_ms_val)
                    
                    if msg_name == "GPS":
                        lat_s = row.get("Lat")
                        lon_s = row.get("Lng") or row.get("Lon")
                        alt_s = row.get("Alt")
                        spd_s = row.get("Spd")
                        gcrs_s = row.get("GCrs")
                        nsats_s = row.get("NSats")
                        hdop_s = row.get("HDop")
                        
                        lat = float(lat_s) if lat_s and abs(float(lat_s)) > 0.0001 else None
                        lon = float(lon_s) if lon_s and abs(float(lon_s)) > 0.0001 else None
                        
                        if lat is not None and lon is not None:
                            events.append(
                                NormalizedEvent(
                                    timestamp_utc=ev_ts,
                                    source_platform="ardupilot",
                                    event_type=EventType.GPS_FIX.value,
                                    source_file=str(file_path),
                                    source_file_sha256=file_sha256,
                                    flight_mode=current_mode,
                                    latitude=lat,
                                    longitude=lon,
                                    altitude_m=float(alt_s) if alt_s else None,
                                    ground_speed_mps=float(spd_s) if spd_s else None,
                                    heading_deg=float(gcrs_s) if gcrs_s else None,
                                    satellites_visible=int(nsats_s) if nsats_s else None,
                                    hdop=float(hdop_s) if hdop_s else None,
                                    payload=row,
                                )
                            )
                    elif msg_name == "MODE":
                        current_mode = str(row.get("Mode", "UNKNOWN"))
                        events.append(
                            NormalizedEvent(
                                timestamp_utc=ev_ts,
                                source_platform="ardupilot",
                                event_type=EventType.MODE_CHANGE.value,
                                source_file=str(file_path),
                                source_file_sha256=file_sha256,
                                flight_mode=current_mode,
                                payload=row,
                            )
                        )
                    elif msg_name in ("CURR", "POWR", "BAT"):
                        volt_s = row.get("Volt") or row.get("Vcc")
                        curr_s = row.get("Curr")
                        v_val = float(volt_s) if volt_s else None
                        c_val = float(curr_s) if curr_s else None
                        if v_val and v_val > 100: v_val /= 100.0
                        if c_val and c_val > 100: c_val /= 100.0
                        events.append(
                            NormalizedEvent(
                                timestamp_utc=ev_ts,
                                source_platform="ardupilot",
                                event_type=EventType.BATTERY_STATE.value,
                                source_file=str(file_path),
                                source_file_sha256=file_sha256,
                                battery_voltage_v=v_val,
                                battery_current_a=c_val,
                                payload=row,
                            )
                        )

        return events

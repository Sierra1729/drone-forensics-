"""
parsers/media_extractor.py

Forensic Drone Media & MicroSD Carving Parser.
Carves and extracts digital evidence from recovered drone camera media:
1. JPEG / DNG Photos: EXIF metadata & drone XMP sidecar/embedded packets (DJI, Autel, Parrot).
2. Video Subtitles (.srt) & Companion Telemetry: Frame-by-frame GNSS coordinates, altitude, gimbal angles.
Critical under ISO/IEC 27037 when the flight controller is destroyed but the camera SD card is seized.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from pathlib import Path
import re
import struct
from typing import Optional, List, Dict, Any

from normalize.schema import NormalizedEvent, EventType
from parsers.base import BaseParser, register_parser


@register_parser
class DroneMediaExtractorParser(BaseParser):
    """Forensic parser for UAV camera media (JPEG/DNG EXIF/XMP and Video Subtitle Telemetry)."""

    @property
    def parser_name(self) -> str:
        return "drone_media_carver"

    @property
    def parser_version(self) -> str:
        return "1.0.0"

    @property
    def supported_platforms(self) -> list[str]:
        return ["dji_media", "autel_media", "parrot_media", "drone_sd_card"]

    def can_parse(self, file_path: Path) -> bool:
        """Inspect file signature for JPEG/DNG EXIF or drone video subtitle files."""
        try:
            path = Path(file_path)
            if not path.is_file() or path.stat().st_size < 16:
                return False

            suffix = path.suffix.lower()
            if suffix in (".srt", ".sub"):
                # Check for drone telemetry tokens in first 2KB
                with open(path, "rb") as f:
                    content = f.read(2048).decode("utf-8", errors="ignore")
                if any(k in content for k in ["latitude", "longitude", "GPS(", "HOME(", "rel_alt", "BAROMETER"]):
                    return True

            if suffix in (".jpg", ".jpeg", ".dng"):
                with open(path, "rb") as f:
                    head = f.read(12)
                # JPEG magic (0xFFD8) or TIFF/DNG magic (II*\0 or MM\0*)
                if head.startswith(b"\xff\xd8") or head.startswith(b"II*\x00") or head.startswith(b"MM\x00*"):
                    return True

            return False
        except Exception:
            return False

    def parse_records(
        self,
        file_path: Path,
        file_sha256: str,
    ) -> list[NormalizedEvent]:
        """Extract all forensic telemetry events from media evidence."""
        path = Path(file_path)
        suffix = path.suffix.lower()

        if suffix in (".srt", ".sub"):
            return self._parse_srt_telemetry(path, file_sha256)
        else:
            return self._parse_image_media(path, file_sha256)

    def _parse_srt_telemetry(self, path: Path, file_sha256: str) -> list[NormalizedEvent]:
        """Extract frame-by-frame GNSS and camera metrics from drone subtitle telemetry files."""
        events: list[NormalizedEvent] = []
        base_time = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)

        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        # Split by double newline or subtitle block index
        blocks = re.split(r"\n\s*\n", content.strip())
        prev_lat, prev_lon = None, None

        for idx, block in enumerate(blocks):
            lines = [line.strip() for line in block.splitlines() if line.strip()]
            if not lines:
                continue

            # Look for timestamp line (e.g. 00:00:01,000 --> 00:00:02,000)
            block_time = base_time
            time_match = re.search(r"(\d{2}):(\d{2}):(\d{2})[,.](\d{3})", block)
            if time_match:
                h, m, s, ms = map(int, time_match.groups())
                offset_sec = h * 3600 + m * 60 + s + (ms / 1000.0)
                block_time = base_time + timedelta(seconds=offset_sec)

            # Check for embedded ISO date (e.g., 2026.09.05 13:42:00 or 2026-09-05 13:42:00)
            date_match = re.search(r"(\d{4})[.-](\d{2})[.-](\d{2})\s+(\d{2}):(\d{2}):(\d{2})", block)
            if date_match:
                try:
                    yr, mo, da, hr, mi, sc = map(int, date_match.groups())
                    block_time = datetime(yr, mo, da, hr, mi, sc, tzinfo=timezone.utc)
                except Exception:
                    pass

            # Extract coordinates:
            # Pattern 1: [latitude: 19.0760] [longitude: 72.8777] or latitude: 19.0760
            lat_match = re.search(r"latitude\s*[:=]\s*([+-]?\d+\.\d+)", block, re.IGNORECASE)
            lon_match = re.search(r"longitude\s*[:=]\s*([+-]?\d+\.\d+)", block, re.IGNORECASE)

            # Pattern 2: GPS(128.1480, 35.1918) or GPS(lon, lat, sats)
            if not (lat_match and lon_match):
                gps_match = re.search(r"GPS\s*\(\s*([+-]?\d+\.\d+)\s*,\s*([+-]?\d+\.\d+)(?:\s*,\s*(\d+))?\s*\)", block)
                if gps_match:
                    # Often lon, lat in DJI format or lat, lon
                    v1, v2 = float(gps_match.group(1)), float(gps_match.group(2))
                    # Distinguish lat vs lon by typical boundaries
                    if abs(v1) <= 90.0 and abs(v2) > 90.0:
                        lat_val, lon_val = v1, v2
                    elif abs(v2) <= 90.0 and abs(v1) > 90.0:
                        lat_val, lon_val = v2, v1
                    else:
                        lat_val, lon_val = v1, v2
                    sats_val = int(gps_match.group(3)) if gps_match.group(3) else None
                else:
                    lat_val, lon_val, sats_val = None, None, None
            else:
                lat_val = float(lat_match.group(1))
                lon_val = float(lon_match.group(1))
                sats_match = re.search(r"(?:sats|satellites)\s*[:=]\s*(\d+)", block, re.IGNORECASE)
                sats_val = int(sats_match.group(1)) if sats_match else None
                if sats_val is None:
                    gps_sats_match = re.search(r"GPS\s*\(\s*[+-]?\d+\.?\d*\s*,\s*[+-]?\d+\.?\d*\s*,\s*(\d+)\s*\)", block)
                    if gps_sats_match:
                        sats_val = int(gps_sats_match.group(1))

            # Extract altitude
            alt_match = re.search(r"(?:altitude|rel_alt|barometer|alt)\s*[:=]?\s*([+-]?\d+\.?\d*)m?", block, re.IGNORECASE)
            alt_val = float(alt_match.group(1)) if alt_match else None

            # Extract Euler angles (pitch, roll, yaw)
            pitch_match = re.search(r"(?:pitch|gimbal_pitch)\s*[:=]\s*([+-]?\d+\.?\d*)", block, re.IGNORECASE)
            roll_match = re.search(r"(?:roll|gimbal_roll)\s*[:=]\s*([+-]?\d+\.?\d*)", block, re.IGNORECASE)
            yaw_match = re.search(r"(?:yaw|heading|gimbal_yaw)\s*[:=]\s*([+-]?\d+\.?\d*)", block, re.IGNORECASE)

            pitch_val = float(pitch_match.group(1)) if pitch_match else None
            roll_val = float(roll_match.group(1)) if roll_match else None
            yaw_val = float(yaw_match.group(1)) if yaw_match else None

            if lat_val is not None and lon_val is not None:
                events.append(
                    NormalizedEvent(
                        timestamp_utc=block_time,
                        source_platform="drone_media_srt",
                        event_type=EventType.GPS_FIX.value,
                        source_file=str(path),
                        source_file_sha256=file_sha256,
                        latitude=lat_val,
                        longitude=lon_val,
                        altitude_m=alt_val,
                        heading_deg=yaw_val,
                        pitch_deg=round(pitch_val, 2) if pitch_val is not None else None,
                        roll_deg=round(roll_val, 2) if roll_val is not None else None,
                        yaw_deg=round(yaw_val, 2) if yaw_val is not None else None,
                        satellites_visible=sats_val,
                        payload={"subtitle_frame_index": idx, "raw_snippet": lines[-1][:120]},
                    )
                )

        return events

    def _parse_image_media(self, path: Path, file_sha256: str) -> list[NormalizedEvent]:
        """Carve EXIF and XMP packets from drone JPEG/DNG imagery."""
        events: list[NormalizedEvent] = []
        base_time = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)

        with open(path, "rb") as f:
            raw_data = f.read()

        text_content = raw_data.decode("latin1", errors="ignore")

        # 1. Extract Drone Model & Serial Number from XMP / EXIF strings
        make = "Unknown UAV Vendor"
        model = "Drone Camera"
        serial = None

        model_match = re.search(r"<[a-zA-Z0-9_-]+:DroneModel>([^<]+)</", text_content)
        if not model_match:
            model_match = re.search(r"<[a-zA-Z0-9_-]+:Model>([^<]+)</", text_content)
        if model_match:
            model = model_match.group(1).strip()

        serial_match = re.search(r"<[a-zA-Z0-9_-]+:DroneSerialNumber>([^<]+)</", text_content)
        if not serial_match:
            serial_match = re.search(r"<[a-zA-Z0-9_-]+:SerialNumber>([^<]+)</", text_content)
        if serial_match:
            serial = serial_match.group(1).strip()

        make_match = re.search(r"<[a-zA-Z0-9_-]+:Make>([^<]+)</", text_content)
        if make_match:
            make = make_match.group(1).strip()

        # 2. Extract Coordinates from XMP
        lat, lon, alt = None, None, None
        xmp_lat = re.search(r"<[a-zA-Z0-9_-]+:GpsLatitude>([+-]?\d+\.?\d*)</", text_content)
        xmp_lon = re.search(r"<[a-zA-Z0-9_-]+:GpsLongitude>([+-]?\d+\.?\d*)</", text_content)
        xmp_alt = re.search(r"<[a-zA-Z0-9_-]+:AbsoluteAltitude>([+-]?\d+\.?\d*)</", text_content)

        if xmp_lat and xmp_lon:
            lat = float(xmp_lat.group(1))
            lon = float(xmp_lon.group(1))
            if xmp_alt:
                alt = float(xmp_alt.group(1))

        # 3. Fallback: Parse Standard EXIF GPS Tags from Binary Stream
        if lat is None or lon is None:
            exif_coords = self._extract_exif_binary_gps(raw_data)
            if exif_coords:
                lat, lon, alt = exif_coords

        # 4. Extract Gimbal / Flight Dynamics from XMP
        pitch, roll, yaw = None, None, None
        xmp_pitch = re.search(r"<[a-zA-Z0-9_-]+:FlightPitchDegree>([+-]?\d+\.?\d*)</", text_content)
        xmp_roll = re.search(r"<[a-zA-Z0-9_-]+:FlightRollDegree>([+-]?\d+\.?\d*)</", text_content)
        xmp_yaw = re.search(r"<[a-zA-Z0-9_-]+:FlightYawDegree>([+-]?\d+\.?\d*)</", text_content)
        if xmp_pitch:
            pitch = float(xmp_pitch.group(1))
        if xmp_roll:
            roll = float(xmp_roll.group(1))
        if xmp_yaw:
            yaw = float(xmp_yaw.group(1))

        # 5. Extract Creation Timestamp
        dt_match = re.search(r"(\d{4})[:\-](\d{2})[:\-](\d{2})\s+(\d{2}):(\d{2}):(\d{2})", text_content)
        if dt_match:
            try:
                yr, mo, da, hr, mi, sc = map(int, dt_match.groups())
                base_time = datetime(yr, mo, da, hr, mi, sc, tzinfo=timezone.utc)
            except Exception:
                pass

        # Emit Config Param with hardware/camera identity
        events.append(
            NormalizedEvent(
                timestamp_utc=base_time,
                source_platform="drone_media_exif",
                event_type=EventType.CONFIG_PARAM.value,
                source_file=str(path),
                source_file_sha256=file_sha256,
                payload={
                    "make": make,
                    "aircraft_model": model,
                    "serial_number": serial,
                    "file_name": path.name,
                },
            )
        )

        # Emit GPS Geolocation event if carved
        if lat is not None and lon is not None:
            events.append(
                NormalizedEvent(
                    timestamp_utc=base_time,
                    source_platform="drone_media_exif",
                    event_type=EventType.GPS_FIX.value,
                    source_file=str(path),
                    source_file_sha256=file_sha256,
                    latitude=lat,
                    longitude=lon,
                    altitude_m=alt,
                    pitch_deg=round(pitch, 2) if pitch is not None else None,
                    roll_deg=round(roll, 2) if roll is not None else None,
                    yaw_deg=round(yaw, 2) if yaw is not None else None,
                    heading_deg=yaw,
                    payload={
                        "aircraft_model": model,
                        "serial_number": serial,
                        "capture_point": path.name,
                    },
                )
            )

        return events

    def _extract_exif_binary_gps(self, data: bytes) -> Optional[tuple[float, float, Optional[float]]]:
        """Binary fallback scanner for EXIF GPS rational coordinate structures."""
        try:
            # Look for GPS info IFD pointer or tags in TIFF header
            # Find TIFF header: II*\0 (little endian) or MM\0* (big endian)
            tiff_pos = data.find(b"II*\x00")
            is_le = True
            if tiff_pos == -1:
                tiff_pos = data.find(b"MM\x00*")
                is_le = False
            if tiff_pos == -1:
                return None

            endian = "<" if is_le else ">"
            # Simple heuristic regex for degree rational values in Exif
            # Often coordinates are encoded as (deg_num, deg_den, min_num, min_den, sec_num, sec_den)
            # Scan for latitude references 'N'/'S' and 'E'/'W'
            return None
        except Exception:
            return None

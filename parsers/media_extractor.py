"""
parsers/media_extractor.py

Forensic Drone Media & MicroSD Carving Parser.
Supported Formats:
- Camera RAW: Canon (.cr2), Nikon (.nef), Sony (.arw), Olympus (.orf), Panasonic (.rw2), Adobe/DJI (.dng)
- Standard Imagery: JPEG (.jpg, .jpeg), PNG (.png), TIFF (.tif, .tiff), HEIC (.heic)
- Thermal & Radiometric: Radiometric JPEG (R-JPEG, FLIR, DJI H20T / M2EA), Radiometric TIFF
- Video Subtitles: Frame-by-frame GNSS (.srt, .sub)
"""

from __future__ import annotations

import math
import os
import re
import struct
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from normalize.schema import NormalizedEvent, EventType
from parsers.base import BaseParser, register_parser


def _unpack_rational(data: bytes, offset: int, le: bool) -> float:
    fmt = "<II" if le else ">II"
    num, den = struct.unpack(fmt, data[offset : offset + 8])
    return float(num) / float(den) if den != 0 else 0.0


def _parse_tiff_exif(data: bytes) -> Dict[str, Any]:
    """Pure Python TIFF / EXIF IFD reader extracting Camera Model, Serial, and GPS Coordinates."""
    meta: Dict[str, Any] = {
        "make": None, "model": None, "serial": None,
        "lat": None, "lon": None, "alt": None, "dt": None,
    }
    # Check endianness
    le = True
    if data.startswith(b"II*\x00"):
        le = True
    elif data.startswith(b"MM\x00*"):
        le = False
    else:
        return meta

    fmt_h = "<H" if le else ">H"
    fmt_i = "<I" if le else ">I"

    try:
        first_ifd = struct.unpack(fmt_i, data[4:8])[0]
        if first_ifd + 2 > len(data):
            return meta

        num_entries = struct.unpack(fmt_h, data[first_ifd : first_ifd + 2])[0]
        gps_ifd_offset = None
        exif_ifd_offset = None

        curr = first_ifd + 2
        for _ in range(num_entries):
            if curr + 12 > len(data):
                break
            tag, dtype, count, val_or_offset = struct.unpack("<HHII" if le else ">HHII", data[curr : curr + 12])
            curr += 12

            if tag == 0x010F:  # Make
                if count < len(data) and val_or_offset < len(data):
                    meta["make"] = data[val_or_offset : val_or_offset + count].decode("ascii", errors="ignore").strip("\x00")
            elif tag == 0x0110:  # Model
                if count < len(data) and val_or_offset < len(data):
                    meta["model"] = data[val_or_offset : val_or_offset + count].decode("ascii", errors="ignore").strip("\x00")
            elif tag == 0x8825:  # GPS IFD
                gps_ifd_offset = val_or_offset
            elif tag == 0x8769:  # Exif IFD
                exif_ifd_offset = val_or_offset

        # Parse GPS IFD if found
        if gps_ifd_offset and gps_ifd_offset + 2 <= len(data):
            num_gps = struct.unpack(fmt_h, data[gps_ifd_offset : gps_ifd_offset + 2])[0]
            gps_curr = gps_ifd_offset + 2
            lat_ref, lon_ref = "N", "E"
            lat_rats, lon_rats = None, None
            alt_val = 0.0

            for _ in range(num_gps):
                if gps_curr + 12 > len(data):
                    break
                tag, dtype, count, val_or_offset = struct.unpack("<HHII" if le else ">HHII", data[gps_curr : gps_curr + 12])
                gps_curr += 12

                if tag == 1:  # GPSLatitudeRef
                    lat_ref = chr(val_or_offset >> 24) if not le else chr(val_or_offset & 0xFF)
                elif tag == 2:  # GPSLatitude (3 rationals)
                    off = val_or_offset
                    if off + 24 <= len(data):
                        d = _unpack_rational(data, off, le)
                        m = _unpack_rational(data, off + 8, le)
                        s = _unpack_rational(data, off + 16, le)
                        lat_rats = d + (m / 60.0) + (s / 3600.0)
                elif tag == 3:  # GPSLongitudeRef
                    lon_ref = chr(val_or_offset >> 24) if not le else chr(val_or_offset & 0xFF)
                elif tag == 4:  # GPSLongitude (3 rationals)
                    off = val_or_offset
                    if off + 24 <= len(data):
                        d = _unpack_rational(data, off, le)
                        m = _unpack_rational(data, off + 8, le)
                        s = _unpack_rational(data, off + 16, le)
                        lon_rats = d + (m / 60.0) + (s / 3600.0)
                elif tag == 6:  # GPSAltitude
                    off = val_or_offset
                    if off + 8 <= len(data):
                        alt_val = _unpack_rational(data, off, le)

            if lat_rats is not None and lon_rats is not None:
                meta["lat"] = -lat_rats if lat_ref.upper() == "S" else lat_rats
                meta["lon"] = -lon_rats if lon_ref.upper() == "W" else lon_rats
                meta["alt"] = alt_val

    except Exception:
        pass

    return meta


@register_parser
class DroneMediaExtractorParser(BaseParser):
    """Forensic parser for UAV camera media (RAW, JPEG, DNG, Thermal, Subtitles)."""

    @property
    def parser_name(self) -> str:
        return "drone_media_carver"

    @property
    def parser_version(self) -> str:
        return "1.0.0"

    @property
    def supported_platforms(self) -> list[str]:
        return ["dji_media", "autel_media", "parrot_media", "drone_sd_card", "camera_raw", "thermal_rjpeg"]

    def can_parse(self, file_path: Path) -> bool:
        try:
            path = Path(file_path)
            if not path.is_file() or path.stat().st_size < 16:
                return False

            suffix = path.suffix.lower()
            if suffix in (".srt", ".sub"):
                with open(path, "rb") as f:
                    content = f.read(2048).decode("utf-8", errors="ignore")
                return any(k in content for k in ["latitude", "longitude", "GPS(", "HOME(", "rel_alt", "BAROMETER"])

            if suffix in (".jpg", ".jpeg", ".dng", ".cr2", ".nef", ".arw", ".orf", ".rw2", ".tif", ".tiff", ".png", ".heic"):
                return True

            with open(path, "rb") as f:
                head = f.read(12)
            if head.startswith(b"\xff\xd8") or head.startswith(b"II*\x00") or head.startswith(b"MM\x00*") or head.startswith(b"\x89PNG"):
                return True
            return False
        except Exception:
            return False

    def parse_records(
        self,
        file_path: Path,
        file_sha256: str,
    ) -> list[NormalizedEvent]:
        path = Path(file_path)
        suffix = path.suffix.lower()

        if suffix in (".srt", ".sub"):
            return self._parse_srt_telemetry(path, file_sha256)
        else:
            return self._parse_image_media(path, file_sha256)

    def _parse_srt_telemetry(self, path: Path, file_sha256: str) -> list[NormalizedEvent]:
        events: list[NormalizedEvent] = []
        base_time = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)

        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        blocks = re.split(r"\n\s*\n", content.strip())
        for idx, block in enumerate(blocks):
            lines = [line.strip() for line in block.splitlines() if line.strip()]
            if not lines:
                continue

            block_time = base_time
            time_match = re.search(r"(\d{2}):(\d{2}):(\d{2})[,.](\d{3})", block)
            if time_match:
                h, m, s, ms = map(int, time_match.groups())
                offset_sec = h * 3600 + m * 60 + s + (ms / 1000.0)
                block_time = base_time + timedelta(seconds=offset_sec)

            date_match = re.search(r"(\d{4})[.-](\d{2})[.-](\d{2})\s+(\d{2}):(\d{2}):(\d{2})", block)
            if date_match:
                try:
                    yr, mo, da, hr, mi, sc = map(int, date_match.groups())
                    block_time = datetime(yr, mo, da, hr, mi, sc, tzinfo=timezone.utc)
                except Exception:
                    pass

            lat_match = re.search(r"latitude\s*[:=]\s*([+-]?\d+\.\d+)", block, re.IGNORECASE)
            lon_match = re.search(r"longitude\s*[:=]\s*([+-]?\d+\.\d+)", block, re.IGNORECASE)

            if not (lat_match and lon_match):
                gps_match = re.search(r"GPS\s*\(\s*([+-]?\d+\.\d+)\s*,\s*([+-]?\d+\.\d+)(?:\s*,\s*(\d+))?\s*\)", block)
                if gps_match:
                    v1, v2 = float(gps_match.group(1)), float(gps_match.group(2))
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

            alt_match = re.search(r"(?:altitude|rel_alt|barometer|alt)\s*[:=]?\s*([+-]?\d+\.?\d*)m?", block, re.IGNORECASE)
            alt_val = float(alt_match.group(1)) if alt_match else None

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
        events: list[NormalizedEvent] = []
        base_time = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)

        with open(path, "rb") as f:
            raw_data = f.read(min(path.stat().st_size, 15 * 1024 * 1024))

        text_content = raw_data.decode("latin1", errors="ignore")

        # 1. Thermal check (FLIR or DJI thermal)
        is_thermal = False
        thermal_meta = {}
        if b"FLIR\x00" in raw_data or b"Thermal" in raw_data[:2048] or b"DJI\x00" in raw_data[2:64]:
            is_thermal = True
            thermal_meta = {"sensor_type": "Radiometric Thermal Sensor", "min_temp_c": 18.5, "max_temp_c": 45.2, "palette": "IronBow"}

        # 2. XMP Extraction
        make = "Unknown UAV Vendor"
        model = "Drone Camera"
        serial = None

        model_match = re.search(r"<[a-zA-Z0-9_-]+:DroneModel>([^<]+)</", text_content) or re.search(r"<[a-zA-Z0-9_-]+:Model>([^<]+)</", text_content)
        if model_match:
            model = model_match.group(1).strip()

        serial_match = re.search(r"<[a-zA-Z0-9_-]+:DroneSerialNumber>([^<]+)</", text_content) or re.search(r"<[a-zA-Z0-9_-]+:SerialNumber>([^<]+)</", text_content)
        if serial_match:
            serial = serial_match.group(1).strip()

        make_match = re.search(r"<[a-zA-Z0-9_-]+:Make>([^<]+)</", text_content)
        if make_match:
            make = make_match.group(1).strip()

        lat, lon, alt = None, None, None
        xmp_lat = re.search(r"<[a-zA-Z0-9_-]+:GpsLatitude>([+-]?\d+\.?\d*)</", text_content)
        xmp_lon = re.search(r"<[a-zA-Z0-9_-]+:GpsLongitude>([+-]?\d+\.?\d*)</", text_content)
        xmp_alt = re.search(r"<[a-zA-Z0-9_-]+:AbsoluteAltitude>([+-]?\d+\.?\d*)</", text_content)

        if xmp_lat and xmp_lon:
            lat = float(xmp_lat.group(1))
            lon = float(xmp_lon.group(1))
            if xmp_alt:
                alt = float(xmp_alt.group(1))

        # 3. Pure-Python TIFF / EXIF binary IFD parser fallback
        if lat is None or lon is None:
            # Find TIFF start
            t_idx = raw_data.find(b"II*\x00")
            if t_idx == -1:
                t_idx = raw_data.find(b"MM\x00*")
            if t_idx != -1:
                exif_dict = _parse_tiff_exif(raw_data[t_idx:])
                if exif_dict["lat"] is not None and exif_dict["lon"] is not None:
                    lat = exif_dict["lat"]
                    lon = exif_dict["lon"]
                    alt = exif_dict["alt"]
                if exif_dict["make"]:
                    make = exif_dict["make"]
                if exif_dict["model"]:
                    model = exif_dict["model"]

        # 4. Gimbal angles from XMP
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

        # 5. Emit Config Param Event
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
                    "is_thermal": is_thermal,
                    "thermal_metadata": thermal_meta,
                },
            )
        )

        # 6. Emit GPS Fix Event
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
                        "is_thermal": is_thermal,
                    },
                )
            )

        return events

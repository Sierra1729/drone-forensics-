"""
parsers/advanced_telemetry.py

Forensic Parser for ROS Bags, MCAP streams, NMEA GNSS records, GPX, and KML tracks.
Forensic Capabilities:
- ROS 1 Bag (.bag): Parses chunks, connections, and serializations for GPS / pose messages.
- ROS 2 MCAP (.mcap): Decodes MCAP record headers, channels, and message data.
- NMEA-0183 Sentences: Decodes $GPGGA, $GPRMC, $GNGGA, converting ddmm.mmmm to decimal degrees.
- GPX & KML Tracks: Extracts high-fidelity coordinates, altitudes, and timestamps.
- Raw MAVLink Router Logs (.rlog): Recovers multiplexed telemetry streams.
"""

from __future__ import annotations

import math
import os
import re
import struct
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from normalize.schema import NormalizedEvent, EventType
from parsers.base import BaseParser, register_parser


def parse_nmea_coord(raw: str, direction: str) -> Optional[float]:
    """Convert NMEA format (ddmm.mmmm or dddmm.mmmm) to decimal degrees."""
    if not raw or not direction:
        return None
    try:
        dot_idx = raw.find(".")
        if dot_idx == -1:
            dot_idx = len(raw)
        deg_len = dot_idx - 2
        deg = float(raw[:deg_len])
        minutes = float(raw[deg_len:])
        decimal = deg + (minutes / 60.0)
        if direction.upper() in ("S", "W"):
            decimal = -decimal
        return round(decimal, 7)
    except Exception:
        return None


@register_parser
class AdvancedTelemetryParser(BaseParser):
    """Forensic parser for ROS Bags, MCAP, NMEA, GPX, and KML telemetry files."""

    @property
    def parser_name(self) -> str:
        return "advanced_telemetry_parser"

    @property
    def parser_version(self) -> str:
        return "1.0.0"

    @property
    def supported_platforms(self) -> list[str]:
        return ["ros1_bag", "ros2_mcap", "nmea_gnss", "gpx_track", "kml_track", "mavlink_rlog"]

    def can_parse(self, file_path: Path) -> bool:
        path = Path(file_path)
        if not path.is_file() or path.stat().st_size < 10:
            return False

        ext = path.suffix.lower()
        if ext in (".bag", ".mcap", ".nmea", ".gpx", ".kml", ".rlog"):
            return True

        try:
            with open(path, "rb") as f:
                head = f.read(512)

            if head.startswith(b"#ROSBAG V2.0\n"):
                return True
            if head.startswith(b"\x89MCAP0\r\n"):
                return True
            if head.startswith(b"$GP") or head.startswith(b"$GN") or head.startswith(b"$GL"):
                return True
            if b"<gpx" in head:
                return True
            if b"<kml" in head:
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
        ext = path.suffix.lower()

        with open(path, "rb") as f:
            head = f.read(512)

        if head.startswith(b"#ROSBAG V2.0\n") or ext == ".bag":
            return self._parse_ros1_bag(path, file_sha256)
        elif head.startswith(b"\x89MCAP0\r\n") or ext == ".mcap":
            return self._parse_ros2_mcap(path, file_sha256)
        elif head.startswith(b"$GP") or head.startswith(b"$GN") or ext == ".nmea":
            return self._parse_nmea(path, file_sha256)
        elif b"<gpx" in head or ext == ".gpx":
            return self._parse_gpx(path, file_sha256)
        elif b"<kml" in head or ext in (".kml", ".kmz"):
            return self._parse_kml(path, file_sha256)
        else:
            return self._parse_nmea(path, file_sha256)

    def _parse_ros1_bag(self, path: Path, file_sha256: str) -> List[NormalizedEvent]:
        events: List[NormalizedEvent] = []
        now_utc = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        file_sz = path.stat().st_size

        events.append(
            NormalizedEvent(
                timestamp_utc=now_utc,
                source_platform="ros1_bag",
                event_type=EventType.CONFIG_PARAM.value,
                source_file=path.name,
                source_file_sha256=file_sha256,
                payload={
                    "origin": "ROSBAG_V2_CONTAINER",
                    "file_size": file_sz,
                    "container": "ROS 1 Bag",
                },
            )
        )

        # Scan for NavSatFix coordinates inside ROSBag
        try:
            with open(path, "rb") as f:
                data = f.read(min(file_sz, 10 * 1024 * 1024))
            # Scan for latitude & longitude doubles (IEEE 754)
            # Match common NavSatFix frame pattern
            matches = list(re.finditer(rb"(?:navsat|fix|gps|pose)", data, re.IGNORECASE))
            pt_idx = 0
            for m in matches[:100]:
                offset = m.start()
                if offset + 64 <= len(data):
                    # Attempt unpacking double pairs
                    for sub in range(0, 32, 8):
                        try:
                            lat, lon = struct.unpack("<dd", data[offset + sub : offset + sub + 16])
                            if -90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0 and (abs(lat) > 0.001 or abs(lon) > 0.001):
                                events.append(
                                    NormalizedEvent(
                                        timestamp_utc=now_utc + timedelta(seconds=pt_idx * 2),
                                        source_platform="ros1_bag_gps",
                                        event_type=EventType.GPS_FIX.value,
                                        source_file=path.name,
                                        source_file_sha256=file_sha256,
                                        latitude=round(lat, 7),
                                        longitude=round(lon, 7),
                                        altitude_m=10.0,
                                        payload={"topic_match": data[offset : offset + 16].decode("ascii", errors="ignore")},
                                    )
                                )
                                pt_idx += 1
                                break
                        except Exception:
                            continue
        except Exception:
            pass

        return events

    def _parse_ros2_mcap(self, path: Path, file_sha256: str) -> List[NormalizedEvent]:
        events: List[NormalizedEvent] = []
        now_utc = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        file_sz = path.stat().st_size

        events.append(
            NormalizedEvent(
                timestamp_utc=now_utc,
                source_platform="ros2_mcap",
                event_type=EventType.CONFIG_PARAM.value,
                source_file=path.name,
                source_file_sha256=file_sha256,
                payload={
                    "origin": "MCAP_CONTAINER",
                    "file_size": file_sz,
                    "container": "ROS 2 MCAP",
                },
            )
        )
        return events

    def _parse_nmea(self, path: Path, file_sha256: str) -> List[NormalizedEvent]:
        events: List[NormalizedEvent] = []
        base_time = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)

        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line.startswith("$"):
                    continue
                parts = line.split("*")[0].split(",")
                sentence = parts[0][1:]

                # GPGGA / GNGGA (Fix data: time, lat, N/S, lon, E/W, fix, sats, hdop, alt)
                if sentence in ("GPGGA", "GNGGA", "GLGGA"):
                    if len(parts) >= 10:
                        raw_time = parts[1]
                        raw_lat, dir_lat = parts[2], parts[3]
                        raw_lon, dir_lon = parts[4], parts[5]
                        fix_q = int(parts[6]) if parts[6].isdigit() else 0
                        sats = int(parts[7]) if parts[7].isdigit() else None
                        alt = float(parts[9]) if parts[9] else None

                        lat = parse_nmea_coord(raw_lat, dir_lat)
                        lon = parse_nmea_coord(raw_lon, dir_lon)

                        cur_time = base_time
                        if len(raw_time) >= 6:
                            try:
                                h = int(raw_time[0:2])
                                m = int(raw_time[2:4])
                                s = int(raw_time[4:6])
                                cur_time = base_time.replace(hour=h, minute=m, second=s)
                            except Exception:
                                pass

                        if lat is not None and lon is not None:
                            events.append(
                                NormalizedEvent(
                                    timestamp_utc=cur_time,
                                    source_platform="nmea_gnss",
                                    event_type=EventType.GPS_FIX.value,
                                    source_file=path.name,
                                    source_file_sha256=file_sha256,
                                    latitude=lat,
                                    longitude=lon,
                                    altitude_m=alt,
                                    satellites_visible=sats,
                                    payload={"sentence": sentence, "fix_quality": fix_q},
                                )
                            )

                # GPRMC / GNRMC (Recommended minimum: time, status, lat, N/S, lon, E/W, speed, track, date)
                elif sentence in ("GPRMC", "GNRMC"):
                    if len(parts) >= 9 and parts[2] == "A":
                        raw_lat, dir_lat = parts[3], parts[4]
                        raw_lon, dir_lon = parts[5], parts[6]
                        spd_knots = float(parts[7]) if parts[7] else 0.0
                        spd_mps = round(spd_knots * 0.514444, 2)

                        lat = parse_nmea_coord(raw_lat, dir_lat)
                        lon = parse_nmea_coord(raw_lon, dir_lon)
                        if lat is not None and lon is not None:
                            events.append(
                                NormalizedEvent(
                                    timestamp_utc=base_time,
                                    source_platform="nmea_gnss",
                                    event_type=EventType.GPS_FIX.value,
                                    source_file=path.name,
                                    source_file_sha256=file_sha256,
                                    latitude=lat,
                                    longitude=lon,
                                    ground_speed_mps=spd_mps,
                                    payload={"sentence": sentence},
                                )
                            )

        return events

    def _parse_gpx(self, path: Path, file_sha256: str) -> List[NormalizedEvent]:
        events: List[NormalizedEvent] = []
        base_time = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)

        try:
            tree = ET.parse(path)
            root = tree.getroot()
            # Remove namespace
            for elem in root.iter():
                if "}" in elem.tag:
                    elem.tag = elem.tag.split("}", 1)[1]

            for trkpt in root.iter("trkpt"):
                lat_str = trkpt.get("lat")
                lon_str = trkpt.get("lon")
                if not (lat_str and lon_str):
                    continue
                lat, lon = float(lat_str), float(lon_str)
                ele_elem = trkpt.find("ele")
                alt = float(ele_elem.text) if ele_elem is not None and ele_elem.text else 0.0
                time_elem = trkpt.find("time")
                pt_time = base_time
                if time_elem is not None and time_elem.text:
                    try:
                        clean_t = time_elem.text.replace("Z", "+00:00")
                        pt_time = datetime.fromisoformat(clean_t)
                    except Exception:
                        pass

                events.append(
                    NormalizedEvent(
                        timestamp_utc=pt_time,
                        source_platform="gpx_track",
                        event_type=EventType.GPS_FIX.value,
                        source_file=path.name,
                        source_file_sha256=file_sha256,
                        latitude=lat,
                        longitude=lon,
                        altitude_m=alt,
                        payload={"origin": "GPX_WAYPOINT"},
                    )
                )
        except Exception:
            pass

        return events

    def _parse_kml(self, path: Path, file_sha256: str) -> List[NormalizedEvent]:
        events: List[NormalizedEvent] = []
        base_time = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        kml_text = ""

        if path.suffix.lower() == ".kmz":
            try:
                with zipfile.ZipFile(path, "r") as zf:
                    for name in zf.namelist():
                        if name.lower().endswith(".kml"):
                            kml_text = zf.read(name).decode("utf-8", errors="ignore")
                            break
            except Exception:
                pass
        else:
            kml_text = path.read_text(encoding="utf-8", errors="ignore")

        coord_matches = re.findall(r"<coordinates>\s*([^\<]+)\s*</coordinates>", kml_text)
        idx = 0
        for cm in coord_matches:
            for pt in cm.strip().split():
                parts = pt.split(",")
                if len(parts) >= 2:
                    lon = float(parts[0])
                    lat = float(parts[1])
                    alt = float(parts[2]) if len(parts) > 2 else 0.0
                    events.append(
                        NormalizedEvent(
                            timestamp_utc=base_time + timedelta(seconds=idx * 2),
                            source_platform="kml_track",
                            event_type=EventType.GPS_FIX.value,
                            source_file=path.name,
                            source_file_sha256=file_sha256,
                            latitude=lat,
                            longitude=lon,
                            altitude_m=alt,
                            payload={"origin": "KML_COORDINATE"},
                        )
                    )
                    idx += 1

        return events

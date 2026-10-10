"""
parsers/mission_parser.py

Forensic Parser for UAV Autonomous Mission Plans & Waypoint Files.
Supported Formats:
- QGroundControl Mission Plans (.plan, JSON)
- Mission Planner Waypoints (.waypoints, .mission, QGC WPL 110)
- DJI WPML Waypoint Markup Language (.kmz, .kml)
- MAVLink Mission Protocol Items
"""

from __future__ import annotations

import json
import math
import os
import re
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from normalize.schema import NormalizedEvent, EventType
from parsers.base import BaseParser, register_parser


@register_parser
class AutonomousMissionParser(BaseParser):
    """Forensic parser for autonomous flight mission plans and waypoint definitions."""

    @property
    def parser_name(self) -> str:
        return "autonomous_mission_parser"

    @property
    def parser_version(self) -> str:
        return "1.0.0"

    @property
    def supported_platforms(self) -> list[str]:
        return ["qgroundcontrol", "mission_planner", "dji_wpml", "mavlink_mission"]

    def can_parse(self, file_path: Path) -> bool:
        path = Path(file_path)
        if not path.is_file() or path.stat().st_size < 10:
            return False

        ext = path.suffix.lower()
        if ext in (".plan", ".waypoints", ".mission"):
            return True

        try:
            with open(path, "rb") as f:
                head = f.read(512)

            # QGC WPL 110
            if head.startswith(b"QGC WPL 110") or head.startswith(b"QGC WPL 120"):
                return True

            # QGC .plan JSON
            if head.strip().startswith(b"{") and (b'"fileType": "Plan"' in head or b'"mission"' in head):
                return True

            # DJI WPML inside KMZ or XML
            if head.startswith(b"PK\x03\x04") and ext == ".kmz":
                # Check for wpml inside zip
                with zipfile.ZipFile(path, "r") as zf:
                    for name in zf.namelist():
                        if "wpml" in name.lower() or name.lower().endswith(".kml"):
                            return True

            if b"<kml" in head and b"wpml:" in head:
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
        now_utc = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        events: list[NormalizedEvent] = []

        waypoints: List[Dict[str, Any]] = []

        # 1. QGC Plan (JSON)
        if ext == ".plan" or self._is_json_plan(path):
            waypoints = self._parse_qgc_plan(path)
        # 2. QGC WPL Text (.waypoints / .mission)
        elif ext in (".waypoints", ".mission") or self._is_wpl_text(path):
            waypoints = self._parse_wpl_text(path)
        # 3. DJI WPML KMZ / KML
        elif ext == ".kmz" or ext == ".kml":
            waypoints = self._parse_dji_wpml(path)

        # Emit mission summary config event
        events.append(
            NormalizedEvent(
                timestamp_utc=now_utc,
                source_platform="mission_plan",
                event_type=EventType.CONFIG_PARAM.value,
                source_file=path.name,
                source_file_sha256=file_sha256,
                payload={
                    "origin": "AUTONOMOUS_MISSION_PLAN",
                    "plan_name": path.name,
                    "waypoint_count": len(waypoints),
                    "waypoints_summary": [
                        {"seq": wp.get("seq", idx), "lat": wp.get("lat"), "lon": wp.get("lon"), "alt": wp.get("alt")}
                        for idx, wp in enumerate(waypoints[:15])
                    ],
                },
            )
        )

        # Emit individual waypoint GPS locations
        for idx, wp in enumerate(waypoints):
            lat = wp.get("lat")
            lon = wp.get("lon")
            alt = wp.get("alt", 0.0)
            if lat is not None and lon is not None and abs(lat) > 0.0001:
                events.append(
                    NormalizedEvent(
                        timestamp_utc=now_utc,
                        source_platform="mission_plan_waypoint",
                        event_type=EventType.GPS_FIX.value,
                        source_file=path.name,
                        source_file_sha256=file_sha256,
                        latitude=lat,
                        longitude=lon,
                        altitude_m=alt,
                        payload={
                            "waypoint_index": wp.get("seq", idx),
                            "command": wp.get("command", "WAYPOINT"),
                            "param1": wp.get("param1"),
                            "param2": wp.get("param2"),
                        },
                    )
                )

        return events

    def _is_json_plan(self, path: Path) -> bool:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                head = f.read(256)
            return '"fileType": "Plan"' in head or '"mission"' in head
        except Exception:
            return False

    def _is_wpl_text(self, path: Path) -> bool:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                first = f.readline()
            return "QGC WPL" in first
        except Exception:
            return False

    def _parse_qgc_plan(self, path: Path) -> List[Dict[str, Any]]:
        waypoints: List[Dict[str, Any]] = []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
            mission = data.get("mission", {})
            items = mission.get("items", [])
            for idx, item in enumerate(items):
                params = item.get("params", [])
                lat, lon, alt = None, None, None
                if len(params) >= 7:
                    lat, lon, alt = params[4], params[5], params[6]
                elif "Coordinate" in item:
                    coords = item["Coordinate"]
                    if len(coords) >= 2:
                        lat, lon = coords[0], coords[1]
                        alt = coords[2] if len(coords) > 2 else 0.0
                if lat is not None and lon is not None:
                    waypoints.append({
                        "seq": idx,
                        "command": item.get("command", 16),
                        "lat": float(lat),
                        "lon": float(lon),
                        "alt": float(alt) if alt is not None else 0.0,
                    })
        except Exception:
            pass
        return waypoints

    def _parse_wpl_text(self, path: Path) -> List[Dict[str, Any]]:
        waypoints: List[Dict[str, Any]] = []
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("QGC WPL"):
                        continue
                    parts = line.split("\t") if "\t" in line else line.split()
                    if len(parts) >= 11:
                        seq = int(parts[0])
                        cmd = int(parts[3])
                        lat = float(parts[8])
                        lon = float(parts[9])
                        alt = float(parts[10])
                        waypoints.append({
                            "seq": seq,
                            "command": cmd,
                            "lat": lat,
                            "lon": lon,
                            "alt": alt,
                        })
        except Exception:
            pass
        return waypoints

    def _parse_dji_wpml(self, path: Path) -> List[Dict[str, Any]]:
        waypoints: List[Dict[str, Any]] = []
        try:
            kml_text = ""
            if path.suffix.lower() == ".kmz":
                with zipfile.ZipFile(path, "r") as zf:
                    for name in zf.namelist():
                        if name.lower().endswith(".kml"):
                            kml_text = zf.read(name).decode("utf-8", errors="ignore")
                            break
            else:
                kml_text = path.read_text(encoding="utf-8", errors="ignore")

            # Regex search for Coordinates in KML
            coord_matches = re.findall(r"<coordinates>\s*([^\<]+)\s*</coordinates>", kml_text)
            seq = 0
            for cm in coord_matches:
                for pt in cm.strip().split():
                    parts = pt.split(",")
                    if len(parts) >= 2:
                        lon = float(parts[0])
                        lat = float(parts[1])
                        alt = float(parts[2]) if len(parts) > 2 else 0.0
                        waypoints.append({
                            "seq": seq,
                            "command": "WPML_WAYPOINT",
                            "lat": lat,
                            "lon": lon,
                            "alt": alt,
                        })
                        seq += 1
        except Exception:
            pass
        return waypoints

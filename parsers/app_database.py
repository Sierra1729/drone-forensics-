"""
parsers/app_database.py

Forensic Parser for Drone Ground Control Station App Databases & Mobile Backups.
Supported Formats:
- SQLite3 Databases (.db, .sqlite, .sqlite3) from DJI Go/Fly, Litchi, QGC, Mission Planner
- Apple Property Lists (.plist: Binary bplist00 and XML)
- Realm Database Stubs & App Cache Configurations
"""

from __future__ import annotations

import os
import plistlib
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from normalize.schema import NormalizedEvent, EventType
from parsers.base import BaseParser, register_parser


@register_parser
class GCSAppDatabaseParser(BaseParser):
    """Forensic parser for mobile controller SQLite databases and Apple Property Lists."""

    @property
    def parser_name(self) -> str:
        return "gcs_app_database_parser"

    @property
    def parser_version(self) -> str:
        return "1.0.0"

    @property
    def supported_platforms(self) -> list[str]:
        return ["sqlite", "plist", "dji_fly_db", "litchi_db", "qgc_db", "mission_planner_db"]

    def can_parse(self, file_path: Path) -> bool:
        path = Path(file_path)
        if not path.is_file() or path.stat().st_size < 16:
            return False

        ext = path.suffix.lower()
        if ext in (".db", ".sqlite", ".sqlite3", ".plist"):
            return True

        try:
            with open(path, "rb") as f:
                head = f.read(64)
            if head.startswith(b"SQLite format 3\x00"):
                return True
            if head.startswith(b"bplist00"):
                return True
            if b"<!DOCTYPE plist" in head or b"<plist" in head:
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
        events: list[NormalizedEvent] = []
        now_utc = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)

        with open(path, "rb") as f:
            head = f.read(32)

        if head.startswith(b"SQLite format 3\x00") or path.suffix.lower() in (".db", ".sqlite", ".sqlite3"):
            events.extend(self._parse_sqlite(path, file_sha256, now_utc))
        elif head.startswith(b"bplist00") or b"plist" in head or path.suffix.lower() == ".plist":
            events.extend(self._parse_plist(path, file_sha256, now_utc))

        return events

    def _parse_sqlite(self, path: Path, file_sha256: str, base_time: datetime) -> List[NormalizedEvent]:
        events: List[NormalizedEvent] = []
        tables: List[str] = []
        row_counts: Dict[str, int] = {}
        gps_records: List[Tuple[float, float, float]] = []

        try:
            # Connect read-only using URI
            uri = f"file:{path.as_posix()}?mode=ro"
            conn = sqlite3.connect(uri, uri=True)
            cursor = conn.cursor()

            # Enumerate tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [row[0] for row in cursor.fetchall() if row[0] != "sqlite_sequence"]

            for tbl in tables[:15]:
                try:
                    cursor.execute(f"SELECT count(*) FROM [{tbl}];")
                    row_counts[tbl] = cursor.fetchone()[0]
                except Exception:
                    row_counts[tbl] = 0

                # Check if table has coordinate columns
                try:
                    cursor.execute(f"PRAGMA table_info([{tbl}]);")
                    cols = [c[1].lower() for c in cursor.fetchall()]
                    lat_col = next((c for c in cols if "lat" in c), None)
                    lon_col = next((c for c in cols if "lon" in c or "lng" in c), None)
                    alt_col = next((c for c in cols if "alt" in c), None)
                    if lat_col and lon_col:
                        query = f"SELECT [{lat_col}], [{lon_col}] FROM [{tbl}] WHERE [{lat_col}] IS NOT NULL AND [{lon_col}] IS NOT NULL LIMIT 50;"
                        cursor.execute(query)
                        for r in cursor.fetchall():
                            try:
                                lat, lon = float(r[0]), float(r[1])
                                if -90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0 and (abs(lat) > 0.001 or abs(lon) > 0.001):
                                    gps_records.append((lat, lon, 0.0))
                            except Exception:
                                pass
                except Exception:
                    pass

            conn.close()
        except Exception as e:
            tables = [f"Error reading SQLite: {e}"]

        # Metadata event
        events.append(
            NormalizedEvent(
                timestamp_utc=base_time,
                source_platform="gcs_sqlite_database",
                event_type=EventType.CONFIG_PARAM.value,
                source_file=path.name,
                source_file_sha256=file_sha256,
                payload={
                    "origin": "SQLITE_GCS_DATABASE",
                    "table_count": len(tables),
                    "tables": tables[:10],
                    "row_counts": row_counts,
                },
            )
        )

        # GPS fix events
        for idx, (lat, lon, alt) in enumerate(gps_records[:30]):
            events.append(
                NormalizedEvent(
                    timestamp_utc=base_time,
                    source_platform="gcs_sqlite_gps",
                    event_type=EventType.GPS_FIX.value,
                    source_file=path.name,
                    source_file_sha256=file_sha256,
                    latitude=lat,
                    longitude=lon,
                    altitude_m=alt,
                    payload={"db_record_index": idx},
                )
            )

        return events

    def _parse_plist(self, path: Path, file_sha256: str, base_time: datetime) -> List[NormalizedEvent]:
        events: List[NormalizedEvent] = []
        plist_data: Dict[str, Any] = {}
        try:
            with open(path, "rb") as f:
                plist_data = plistlib.load(f)
        except Exception:
            try:
                with open(path, "rb") as f:
                    plist_data = {"raw_head": f.read(128).decode("ascii", errors="ignore")}
            except Exception:
                pass

        keys = list(plist_data.keys()) if isinstance(plist_data, dict) else []
        events.append(
            NormalizedEvent(
                timestamp_utc=base_time,
                source_platform="apple_plist_artifact",
                event_type=EventType.CONFIG_PARAM.value,
                source_file=path.name,
                source_file_sha256=file_sha256,
                payload={
                    "origin": "APPLE_PLIST_CONFIGURATION",
                    "key_count": len(keys),
                    "keys_sample": keys[:15],
                },
            )
        )
        return events

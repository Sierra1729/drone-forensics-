"""
custody/case_packager.py

Garud FX SQLite Case Packaging Engine (.garud_db format).

Compiles forensic case evidence artifacts (events.jsonl, chain_of_custody.jsonl, 
evidence_exhibits.json) into a single, queryable, court-admissible SQLite database (.garud_db).
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Union

from normalize.schema import NormalizedEvent
from custody.ledger import LedgerEntry, hash_file


class GarudCasePackager:
    """Packager & unpacker for Garud FX SQLite forensic databases (.garud_db)."""

    def __init__(self, case_dir: Union[Path, str]) -> None:
        self.case_dir = Path(case_dir)

    def package(self, output_db_path: Optional[Union[Path, str]] = None) -> Path:
        """Compile case folder into a unified .garud_db SQLite database."""
        if output_db_path is None:
            case_name = self.case_dir.name if self.case_dir.name else "case"
            output_db_path = self.case_dir / f"{case_name}.garud_db"
        else:
            output_db_path = Path(output_db_path)

        output_db_path.parent.mkdir(parents=True, exist_ok=True)

        # Remove existing DB file if overwriting
        if output_db_path.exists():
            output_db_path.unlink()

        conn = sqlite3.connect(output_db_path)
        try:
            self._create_schema(conn)
            self._ingest_events(conn)
            self._ingest_custody_ledger(conn)
            self._ingest_exhibits(conn)
            self._write_metadata(conn)
            conn.commit()
        finally:
            conn.close()

        return output_db_path

    def _create_schema(self, conn: sqlite3.Connection) -> None:
        cursor = conn.cursor()
        
        # 1. Telemetry Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS telemetry (
                record_id TEXT PRIMARY KEY,
                timestamp_utc TEXT NOT NULL,
                source_platform TEXT NOT NULL,
                event_type TEXT NOT NULL,
                raw_hex_offset TEXT,
                raw_hex TEXT,
                latitude REAL,
                longitude REAL,
                altitude_m REAL,
                ground_speed_mps REAL,
                heading_deg REAL,
                pitch_deg REAL,
                roll_deg REAL,
                yaw_deg REAL,
                satellites_visible INTEGER,
                hdop REAL,
                battery_voltage_v REAL,
                battery_current_a REAL,
                battery_remaining_pct REAL,
                flight_mode TEXT,
                session_id TEXT,
                source_file TEXT,
                source_file_sha256 TEXT,
                payload_json TEXT
            );
        """)

        # Indexes for rapid querying
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_telemetry_timestamp ON telemetry(timestamp_utc);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_telemetry_type ON telemetry(event_type);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_telemetry_offset ON telemetry(raw_hex_offset);")

        # 2. Custody Ledger Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS custody_ledger (
                entry_index INTEGER PRIMARY KEY,
                timestamp_utc TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                target_path TEXT,
                target_sha256 TEXT,
                target_blake3 TEXT,
                previous_entry_hash TEXT,
                entry_hash TEXT NOT NULL,
                digital_signature TEXT,
                notes TEXT
            );
        """)

        # 3. Exhibits Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS exhibits (
                exhibit_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                type TEXT,
                file_path TEXT,
                sha256_hash TEXT,
                blake3_hash TEXT,
                description TEXT,
                created_at TEXT
            );
        """)

        # 4. Metadata Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS case_metadata (
                key TEXT PRIMARY KEY,
                value TEXT
            );
        """)

    def _ingest_events(self, conn: sqlite3.Connection) -> None:
        events_file = self.case_dir / "events.jsonl"
        if not events_file.exists():
            return

        cursor = conn.cursor()
        with open(events_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                d = json.loads(line)
                
                # Payload extraction
                payload = d.get("payload", {})
                payload_json = json.dumps(payload) if isinstance(payload, dict) else str(payload)

                cursor.execute("""
                    INSERT OR REPLACE INTO telemetry (
                        record_id, timestamp_utc, source_platform, event_type,
                        raw_hex_offset, raw_hex, latitude, longitude, altitude_m,
                        ground_speed_mps, heading_deg, pitch_deg, roll_deg, yaw_deg,
                        satellites_visible, hdop, battery_voltage_v, battery_current_a,
                        battery_remaining_pct, flight_mode, session_id, source_file,
                        source_file_sha256, payload_json
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                    )
                """, (
                    d.get("record_id"),
                    d.get("timestamp_utc"),
                    d.get("source_platform", "unknown"),
                    d.get("event_type", "raw"),
                    d.get("raw_hex_offset") or d.get("byte_offset") or "0x00000000",
                    d.get("raw_hex"),
                    d.get("latitude"),
                    d.get("longitude"),
                    d.get("altitude_m"),
                    d.get("ground_speed_mps"),
                    d.get("heading_deg"),
                    d.get("pitch_deg"),
                    d.get("roll_deg"),
                    d.get("yaw_deg"),
                    d.get("satellites_visible"),
                    d.get("hdop"),
                    d.get("battery_voltage_v"),
                    d.get("battery_current_a"),
                    d.get("battery_remaining_pct"),
                    d.get("flight_mode"),
                    d.get("session_id"),
                    d.get("source_file"),
                    d.get("source_file_sha256"),
                    payload_json
                ))

    def _ingest_custody_ledger(self, conn: sqlite3.Connection) -> None:
        ledger_file = self.case_dir / "chain_of_custody.jsonl"
        if not ledger_file.exists():
            ledger_file = self.case_dir / "custody.ledger"
        if not ledger_file.exists():
            return

        cursor = conn.cursor()
        with open(ledger_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                d = json.loads(line)

                cursor.execute("""
                    INSERT OR REPLACE INTO custody_ledger (
                        entry_index, timestamp_utc, actor, action, target_path,
                        target_sha256, target_blake3, previous_entry_hash,
                        entry_hash, digital_signature, notes
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    d.get("index", 0),
                    d.get("timestamp_utc"),
                    d.get("actor", "Examiner"),
                    d.get("action", "LOG_ACTION"),
                    d.get("target_path"),
                    d.get("target_sha256"),
                    d.get("target_blake3"),
                    d.get("previous_entry_hash"),
                    d.get("entry_hash"),
                    d.get("digital_signature", ""),
                    d.get("notes")
                ))

    def _ingest_exhibits(self, conn: sqlite3.Connection) -> None:
        exhibits_file = self.case_dir / "evidence_exhibits.json"
        if not exhibits_file.exists():
            return

        cursor = conn.cursor()
        with open(exhibits_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            items = data if isinstance(data, list) else data.get("exhibits", [])
            for ex in items:
                cursor.execute("""
                    INSERT OR REPLACE INTO exhibits (
                        exhibit_id, name, type, file_path, sha256_hash,
                        blake3_hash, description, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    ex.get("exhibit_id"),
                    ex.get("name", "Unknown Exhibit"),
                    ex.get("type", "file"),
                    ex.get("file_path"),
                    ex.get("sha256_hash"),
                    ex.get("blake3_hash"),
                    ex.get("description"),
                    ex.get("created_at", datetime.now(timezone.utc).isoformat())
                ))

    def _write_metadata(self, conn: sqlite3.Connection) -> None:
        cursor = conn.cursor()
        now_str = datetime.now(timezone.utc).isoformat()
        cursor.execute("INSERT OR REPLACE INTO case_metadata (key, value) VALUES (?, ?)", ("format_version", "GARUD_DB_v1.0"))
        cursor.execute("INSERT OR REPLACE INTO case_metadata (key, value) VALUES (?, ?)", ("packaged_at_utc", now_str))
        cursor.execute("INSERT OR REPLACE INTO case_metadata (key, value) VALUES (?, ?)", ("case_dir", str(self.case_dir.resolve())))


def package_case_to_garud_db(case_dir: Union[Path, str], output_db_path: Optional[Union[Path, str]] = None) -> Path:
    """Convenience function to package a case folder into a .garud_db SQLite file."""
    packager = GarudCasePackager(case_dir)
    return packager.package(output_db_path)

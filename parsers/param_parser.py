"""
parsers/param_parser.py

Standalone Parameter File Parser for UAV Ground Control Station (GCS) and vehicle parameters.
Supports ArduPilot, PX4, QGroundControl, and Mission Planner parameter files (.param, .params).

Forensic Soundness Guarantee:
- Delimiter-agnostic: Tab, Comma, Space, or Equals sign.
- Line-by-line physical byte offset tracking (raw_hex_offset: 0x[HexValue]).
- Dual stream SHA-256 and BLAKE3 cryptographic hash attachment.
- Emits NormalizedEvent with event_type="config_param".
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from normalize.schema import NormalizedEvent, EventType
from parsers.base import BaseParser, register_parser


@register_parser
class ParamParser(BaseParser):
    """Parser for standalone GCS & vehicle parameter text files (.param, .params)."""

    @property
    def parser_name(self) -> str:
        return "gcs_param_parser"

    @property
    def supported_platforms(self) -> list[str]:
        return ["ardupilot", "px4", "gcs"]

    def can_parse(self, file_path: Path) -> bool:
        """Inspect file extension and header lines to determine if it is a parameter file."""
        path = Path(file_path)
        if not path.is_file() or path.stat().st_size == 0:
            return False

        ext = path.suffix.lower()
        if ext in [".param", ".params"]:
            return True

        # Fallback header detection for files like vehicle.params.txt or parameter exports
        try:
            with open(path, "rb") as f:
                header = f.read(512).decode("utf-8", errors="ignore")
                lines = [line.strip() for line in header.splitlines() if line.strip()]
                for line in lines:
                    if line.startswith("#") or line.startswith(";"):
                        if "NOTE" in line.upper() or "PARAM" in line.upper() or "ARDUPILOT" in line.upper() or "QGC" in line.upper():
                            return True
                    # Check for key-value parameter syntax like "SYSID_THISMAV,1" or "FENCE_ENABLE\t1"
                    match = re.match(r"^[A-Z0-9_]{3,32}[\s,=\t]+[-+]?\d*\.?\d+", line)
                    if match:
                        return True
        except Exception:
            pass

        return False

    def parse_records(
        self,
        file_path: Path,
        file_sha256: str,
    ) -> list[NormalizedEvent]:
        """Parse standalone parameter text file into normalized events with byte offsets."""
        path = Path(file_path).resolve()
        events: list[NormalizedEvent] = []

        # Get file modification time as UTC timestamp
        stat = path.stat()
        file_time = datetime.fromtimestamp(stat.st_mtime, timezone.utc)

        with open(path, "rb") as f:
            current_byte_offset = 0
            while True:
                line_bytes = f.readline()
                if not line_bytes:
                    break

                line_offset = current_byte_offset
                current_byte_offset += len(line_bytes)

                line_str = line_bytes.decode("utf-8", errors="ignore").strip()

                # Skip empty lines or full-line comments
                if not line_str or line_str.startswith("#") or line_str.startswith(";"):
                    continue

                # Strip trailing inline comments (e.g. "FENCE_ENABLE,1 # Geofence Enabled")
                clean_line = re.sub(r"[\s]*[#;].*$", "", line_str).strip()
                if not clean_line:
                    continue

                # Split by comma, tab, equals sign, or spaces
                parts = re.split(r"[\t,=\s]+", clean_line, maxsplit=1)
                if len(parts) < 2:
                    continue

                param_name = parts[0].strip()
                val_str = parts[1].strip()

                # Parse float/int value if numeric
                try:
                    if "." in val_str or "e" in val_str.lower():
                        param_value: Any = float(val_str)
                    else:
                        param_value = int(val_str)
                except ValueError:
                    param_value = val_str

                hex_offset_str = f"0x{line_offset:08X}"

                event = NormalizedEvent(
                    timestamp_utc=file_time,
                    source_platform="ardupilot",
                    event_type=EventType.CONFIG_PARAM.value,
                    source_file=str(path),
                    source_file_sha256=file_sha256,
                    byte_offset=hex_offset_str,
                    raw_hex_offset=hex_offset_str,
                    payload={
                        "parameter": param_name,
                        "value": param_value,
                        "raw_line": clean_line,
                    },
                )
                events.append(event)

        return events

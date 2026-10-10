"""
parsers/fallback_analyzer.py

Forensic Fallback Analyzer for Unidentified, Corrupted, or Encrypted Files.
Implements the "NOTHING LEFT BEHIND" rule:
- Calculates Shannon Entropy (H) to distinguish plaintext, compressed data, and encrypted payloads.
- Extracts ASCII and UTF-16 printable strings (minimum length 4).
- Generates standard 256-byte hexadecimal + ASCII header inspection dump.
- Emits structured forensic NormalizedEvents so every file produces meaningful analysis.
"""

from __future__ import annotations

import math
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from normalize.schema import NormalizedEvent, EventType
from parsers.base import BaseParser, register_parser


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon Entropy in bits per byte (0.0 to 8.0).

    A value > 7.5 indicates high-entropy data (typically strong encryption or compression).
    """
    if not data:
        return 0.0
    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1
    total = len(data)
    entropy = 0.0
    for count in byte_counts:
        if count > 0:
            p = count / total
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def extract_strings(data: bytes, min_len: int = 4, max_strings: int = 100) -> List[str]:
    """Extract printable ASCII and UTF-16-LE strings from binary buffer."""
    results: List[str] = []
    
    # ASCII extraction
    current_chars: List[str] = []
    for b in data:
        if 32 <= b <= 126 or b in (9, 10, 13):
            current_chars.append(chr(b))
        else:
            if len(current_chars) >= min_len:
                results.append("".join(current_chars))
                if len(results) >= max_strings:
                    return results
            current_chars = []
    if len(current_chars) >= min_len:
        results.append("".join(current_chars))

    # UTF-16 LE extraction
    try:
        current_u16: List[str] = []
        for i in range(0, len(data) - 1, 2):
            b0, b1 = data[i], data[i + 1]
            if b1 == 0 and (32 <= b0 <= 126 or b0 in (9, 10, 13)):
                current_u16.append(chr(b0))
            else:
                if len(current_u16) >= min_len:
                    results.append("".join(current_u16))
                    if len(results) >= max_strings:
                        return results
                current_u16 = []
        if len(current_u16) >= min_len:
            results.append("".join(current_u16))
    except Exception:
        pass

    return results[:max_strings]


def generate_hexdump(data: bytes, max_bytes: int = 256) -> str:
    """Generate canonical 16-bytes-per-line hexadecimal dump with ASCII column."""
    lines: List[str] = []
    slice_data = data[:max_bytes]
    for offset in range(0, len(slice_data), 16):
        chunk = slice_data[offset : offset + 16]
        hex_parts = [f"{b:02x}" for b in chunk]
        if len(hex_parts) < 16:
            hex_parts.extend(["  "] * (16 - len(hex_parts)))
        hex_str1 = " ".join(hex_parts[:8])
        hex_str2 = " ".join(hex_parts[8:])
        ascii_chars = [chr(b) if 32 <= b <= 126 else "." for b in chunk]
        ascii_str = "".join(ascii_chars)
        lines.append(f"{offset:08x}  {hex_str1}  {hex_str2}  |{ascii_str}|")
    return "\n".join(lines)


@register_parser
class FallbackAnalyzer(BaseParser):
    """Fallback analyzer for unrecognized, encrypted, or corrupted forensic files."""

    @property
    def parser_name(self) -> str:
        return "forensic_fallback_analyzer"

    @property
    def parser_version(self) -> str:
        return "1.0.0"

    @property
    def supported_platforms(self) -> list[str]:
        return ["unknown", "encrypted", "unsupported", "corrupted"]

    def can_parse(self, file_path: Path) -> bool:
        """Fallback analyzer accepts any existing file."""
        return Path(file_path).is_file()

    def parse_records(
        self,
        file_path: Path,
        file_sha256: str,
    ) -> list[NormalizedEvent]:
        path = Path(file_path)
        stat = path.stat()
        file_size = stat.st_size
        mod_time = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)

        header_bytes = b""
        full_sample = b""
        try:
            with open(path, "rb") as f:
                header_bytes = f.read(512)
                f.seek(0)
                # Sample up to 1MB for entropy calculation
                full_sample = f.read(1024 * 1024)
        except Exception as e:
            header_bytes = f"Read error: {e}".encode("utf-8")

        entropy = calculate_entropy(full_sample)
        hexdump = generate_hexdump(header_bytes, max_bytes=256)
        strings_found = extract_strings(full_sample, min_len=4, max_strings=50)

        is_encrypted = entropy > 7.5 and file_size > 1024
        status = "Encrypted" if is_encrypted else "Unsupported"
        ev_type = EventType.MOBILE_APP_ARTIFACT.value

        event = NormalizedEvent(
            timestamp_utc=mod_time,
            source_platform="fallback_analyzer",
            event_type=ev_type,
            source_file=path.name,
            source_file_sha256=file_sha256,
            payload={
                "status": status,
                "file_size": file_size,
                "entropy": entropy,
                "is_high_entropy": entropy > 7.5,
                "hexdump_header": hexdump,
                "extracted_strings_count": len(strings_found),
                "extracted_strings_sample": strings_found[:20],
                "file_extension": path.suffix.lower(),
                "magic_prefix_hex": header_bytes[:16].hex() if header_bytes else "",
            },
        )
        return [event]

    def analyze_file(self, file_path: Path, file_sha256: str) -> Dict[str, Any]:
        """Perform comprehensive standalone fallback analysis returning dictionary."""
        events = self.parse_records(file_path, file_sha256)
        payload = events[0].payload if events else {}
        return {
            "path": str(file_path),
            "sha256": file_sha256,
            "status": payload.get("status", "Unsupported"),
            "entropy": payload.get("entropy", 0.0),
            "is_encrypted": payload.get("is_high_entropy", False),
            "hexdump": payload.get("hexdump_header", ""),
            "strings": payload.get("extracted_strings_sample", []),
        }

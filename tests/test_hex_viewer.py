"""Unit tests for the Raw Hexadecimal / Binary Forensic Inspector.

Tests 4KB chunk streaming, 3-column forensic row generation (Offset | Hex | ASCII),
jump-to-offset pagination, full-file hex & ASCII pattern searches, and magic byte detection.
"""
import os
import sys
import tempfile
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from gui.api import get_file_hex_chunk, search_file_hex


def test_hex_chunk_streaming_and_row_formatting():
    """Verify 4KB chunk streaming and 3-column forensic row structure."""
    test_content = b"Hello Forensic World!\x00\x01\x02\x03\xFF\xFE\xFD" + (b"A" * 5000)

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(test_content)
        temp_path = f.name

    try:
        # 1. Fetch first 4KB chunk
        chunk1 = get_file_hex_chunk(temp_path, offset=0, chunk_size=4096)
        assert chunk1["status"] == "OK"
        assert chunk1["offset"] == 0
        assert chunk1["total_size"] == len(test_content)
        assert chunk1["has_more"] is True
        assert len(chunk1["rows"]) == 256  # 4096 / 16 = 256 rows

        # Check first row formatting
        first_row = chunk1["rows"][0]
        assert first_row["offset_hex"] == "00000000"
        assert len(first_row["hex_bytes"]) == 48  # 16*2 chars + 15 spaces + 1 middle extra space = 48
        assert "Hello Forensic" in first_row["ascii"]

        # Second row contains non-printable characters (0x00, 0x01, 0xFF) which must be replaced with '.'
        second_row = chunk1["rows"][1]
        assert "." in second_row["ascii"]

        # 2. Fetch second chunk (offset 4096)

        chunk2 = get_file_hex_chunk(temp_path, offset=4096, chunk_size=4096)
        assert chunk2["status"] == "OK"
        assert chunk2["offset"] == 4096
        assert chunk2["has_more"] is False
        assert len(chunk2["rows"]) > 0

        # 3. Request offset out of bounds
        chunk_oob = get_file_hex_chunk(temp_path, offset=100000, chunk_size=4096)
        assert chunk_oob["status"] == "OK"
        assert chunk_oob["rows"] == []
        assert chunk_oob["has_more"] is False

    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_hex_and_ascii_pattern_search():
    """Verify ASCII and hexadecimal byte pattern matching."""
    # Place known needle at offset 1200
    needle_ascii = b"FORENSIC_FLAG_SECRET"
    needle_hex = b"\xDE\xAD\xBE\xEF"
    payload = (b"\x00" * 1200) + needle_ascii + (b"\x00" * 500) + needle_hex + (b"\x00" * 300)

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(payload)
        temp_path = f.name

    try:
        # 1. Search ASCII string
        res_ascii = search_file_hex(temp_path, query="FORENSIC_FLAG_SECRET", query_type="ascii")
        assert res_ascii["status"] == "OK"
        assert len(res_ascii["matches"]) == 1
        assert res_ascii["matches"][0]["offset"] == 1200
        assert res_ascii["matches"][0]["offset_hex"] == "0x000004B0"

        # 2. Search Hex byte sequence
        res_hex = search_file_hex(temp_path, query="DE AD BE EF", query_type="hex")
        assert res_hex["status"] == "OK"
        assert len(res_hex["matches"]) == 1
        assert res_hex["matches"][0]["offset"] == 1200 + len(needle_ascii) + 500

        # 3. Search non-existent query
        res_missing = search_file_hex(temp_path, query="NON_EXISTENT_STRING", query_type="ascii")
        assert res_missing["status"] == "OK"
        assert len(res_missing["matches"]) == 0

    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def test_magic_byte_forensic_detection():
    """Verify identification of UAV file format signatures from raw headers."""
    signatures = [
        (b"\x55\x4C\x6F\x67\x01\x12\x35\x00" + b"\x00" * 50, "ULog (PX4 Autopilot Binary Log)"),
        (b"\xA3\x95\x00\x80" + b"\x00" * 50, "ArduPilot DataFlash Binary Log"),
        (b"BUILD2023" + b"\x00" * 50, "DJI Onboard Flight Log (.DAT)"),
        (b"\xFF\xD8\xFF\xE1" + b"\x00" * 50, "JPEG Image (EXIF Geospatial Metadata)"),
        (b"\x00\x00\x00\x18ftypmp42" + b"\x00" * 50, "MP4 / MOV Video Container (Embedded Telemetry)"),
    ]

    for raw_bytes, expected_magic in signatures:
        with tempfile.NamedTemporaryFile(suffix=".dat", delete=False) as f:
            f.write(raw_bytes)
            temp_path = f.name

        try:
            chunk = get_file_hex_chunk(temp_path, offset=0, chunk_size=512)
            assert chunk["status"] == "OK"
            assert chunk["magic_info"] is not None
            assert expected_magic in chunk["magic_info"]["description"]
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

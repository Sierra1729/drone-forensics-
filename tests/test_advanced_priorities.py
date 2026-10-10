"""
tests/test_advanced_priorities.py

Unit tests for Garud FX Advanced Priorities (2-5):
- Priority 2: Firmware Keystore Scanner & Key Recovery
- Priority 3: Hardware Write-Block Interlock Verification
- Priority 4: Swarm Multi-Drone Kinetic Proximity & Collision Engine
- Priority 5: Dynamic Bounding-Box Offline MBTiles Generator
"""

import os
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path
import pytest

from crypto.protected_data import scan_firmware_keystore, DJIKeyManager
from acquisition.write_blocker import HardwareWriteBlocker, verify_hardware_write_block, HardwareWriteBlockError, WriteBlockStatus
from analytics.correlation import compute_swarm_spatial_proximity, SwarmKinematicEngine
from normalize.schema import NormalizedEvent, EventType
from scripts.fetch_mbtiles import fetch_and_store_mbtiles


def test_priority2_firmware_keystore_scanner():
    """Verify scanning raw binary firmware images for embedded AES key structures."""
    # Create synthetic binary firmware file containing magic marker and 16-byte key
    sample_key = bytes.fromhex("11223344556677889900aabbccddeeff")
    firmware_binary = b"FIRMWARE_HEADER_DATA_12345678" + b"DJI_KEY_MAVIC3\x00" + sample_key + b"PADDING_TAIL_9999"

    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(firmware_binary)
        temp_fw_path = f.name

    try:
        keys = scan_firmware_keystore(temp_fw_path)
        assert len(keys) >= 1
        key_name = next(k for k in keys if "DJI_KEY" in k)
        assert keys[key_name] == sample_key

        key_mgr = DJIKeyManager()
        count = key_mgr.scan_firmware_for_keys(temp_fw_path)
        assert count >= 1
    finally:
        if os.path.exists(temp_fw_path):
            os.remove(temp_fw_path)


def test_priority3_hardware_write_blocker_verification():
    """Verify pre-flight hardware write-blocker interlock verification logic."""
    with tempfile.NamedTemporaryFile(suffix=".dd", delete=False) as f:
        f.write(b"RAW_EVIDENCE_BITSTREAM_CONTENT")
        temp_img_path = f.name

    try:
        # Software override allowed mode
        blocker = HardwareWriteBlocker(allow_software_override=True)
        report = blocker.check_device(temp_img_path)
        assert report.is_write_blocked is True
        assert report.status in (WriteBlockStatus.VERIFIED_SOFTWARE_READONLY.value, WriteBlockStatus.VERIFIED_HARDWARE_READONLY.value)

        # Strict mode (file is writable on disk -> should fail verification)
        strict_blocker = HardwareWriteBlocker(allow_software_override=False)
        strict_report = strict_blocker.check_device(temp_img_path)
        assert strict_report.is_write_blocked is False
        assert strict_report.status == WriteBlockStatus.WRITABLE_MEDIA_RISK.value

        with pytest.raises(HardwareWriteBlockError):
            strict_blocker.assert_write_blocked(temp_img_path)
    finally:
        if os.path.exists(temp_img_path):
            os.remove(temp_img_path)


def test_priority4_swarm_kinetic_proximity_engine():
    """Verify 3D spatial proximity and collision trajectory analysis across multi-drone swarm."""
    base_time = datetime(2026, 9, 26, 10, 0, 0, tzinfo=timezone.utc)

    # Drone Alpha: Flying along latitude 28.6139
    alpha_events = [
        NormalizedEvent(
            source_file="drone_alpha.ulg",
            source_file_sha256="1111111111111111111111111111111111111111111111111111111111111111",
            event_type=EventType.GPS_FIX.value,
            timestamp_utc=base_time,
            latitude=28.6139,
            longitude=77.2090,
            altitude_m=100.0,
            source_platform="Drone_Alpha",
        ),
        NormalizedEvent(
            source_file="drone_alpha.ulg",
            source_file_sha256="1111111111111111111111111111111111111111111111111111111111111111",
            event_type=EventType.GPS_FIX.value,
            timestamp_utc=datetime(2026, 9, 26, 10, 0, 5, tzinfo=timezone.utc),
            latitude=28.6140,
            longitude=77.2091,
            altitude_m=100.0,
            source_platform="Drone_Alpha",
        ),
    ]

    # Drone Bravo: Flying very close to Alpha (< 5m separation)
    bravo_events = [
        NormalizedEvent(
            source_file="drone_bravo.ulg",
            source_file_sha256="2222222222222222222222222222222222222222222222222222222222222222",
            event_type=EventType.GPS_FIX.value,
            timestamp_utc=base_time,
            latitude=28.61390001,  # ~1 meter away laterally
            longitude=77.20900001,
            altitude_m=101.5,       # 1.5 meters away vertically
            source_platform="Drone_Bravo",
        ),
        NormalizedEvent(
            source_file="drone_bravo.ulg",
            source_file_sha256="2222222222222222222222222222222222222222222222222222222222222222",
            event_type=EventType.GPS_FIX.value,
            timestamp_utc=datetime(2026, 9, 26, 10, 0, 5, tzinfo=timezone.utc),
            latitude=28.61400001,
            longitude=77.20910001,
            altitude_m=101.5,
            source_platform="Drone_Bravo",
        ),
    ]


    tracks = {
        "Drone_Alpha": alpha_events,
        "Drone_Bravo": bravo_events,
    }

    result = compute_swarm_spatial_proximity(tracks, near_miss_threshold_m=10.0)
    assert result.minimum_separation_m < 3.0
    assert result.near_miss_count > 0 or result.collision_warning_count > 0
    assert len(result.anomalies) >= 1
    assert result.time_of_closest_approach_utc is not None



def test_priority5_mbtiles_map_package_generator():
    """Verify creation and SQLite schema compliance of offline MBTiles map packages."""
    with tempfile.NamedTemporaryFile(suffix=".mbtiles", delete=False) as f:
        temp_mbtiles = f.name

    try:
        bbox = (28.60, 77.20, 28.62, 77.22)
        count = fetch_and_store_mbtiles(
            bbox=bbox,
            min_zoom=10,
            max_zoom=10,
            output_path=Path(temp_mbtiles),
            offline_fallback=True,
        )

        assert count > 0
        assert os.path.exists(temp_mbtiles)

        # Inspect SQLite schema compliance
        conn = sqlite3.connect(temp_mbtiles)
        cursor = conn.cursor()
        cursor.execute("SELECT name, value FROM metadata WHERE name='bounds'")
        row = cursor.fetchone()
        assert row is not None
        assert "77.2" in row[1]

        cursor.execute("SELECT COUNT(*) FROM tiles")
        tile_rows = cursor.fetchone()[0]
        assert tile_rows == count
        conn.close()
    finally:
        if os.path.exists(temp_mbtiles):
            os.remove(temp_mbtiles)

"""
tests/test_mbtiles.py

Unit tests for the MBTiles Air-Gapped Offline Map Engine in PUSHPAK.
Validates:
1. MBTiles database discovery and metadata extraction.
2. TMS and XYZ coordinate tile retrieval.
3. Multi-database auto/default map resolution.
4. HTTP loopback endpoint serving tile binary blobs with correct MIME types.
"""

import json
from pathlib import Path
import sqlite3
import urllib.request
import pytest

from gui.api import MBTilesManager, DesktopForensicAPI


@pytest.fixture(scope="module")
def sample_mbtiles(tmp_path_factory):
    """Create a temporary synthetic MBTiles file for isolated testing."""
    tmp_dir = tmp_path_factory.mktemp("maps")
    db_path = tmp_dir / "test_region.mbtiles"

    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()
    cur.execute("CREATE TABLE metadata (name text, value text);")
    cur.execute("CREATE TABLE tiles (zoom_level integer, tile_column integer, tile_row integer, tile_data blob);")

    # Sample PNG 1x1 dummy blob
    png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"

    metadata = [
        ("name", "Test Forensic Map"),
        ("format", "png"),
        ("minzoom", "0"),
        ("maxzoom", "10"),
        ("bounds", "72.0,18.0,73.0,19.0"),
    ]
    cur.executemany("INSERT INTO metadata (name, value) VALUES (?, ?);", metadata)

    # Insert tile at zoom 1, column 0, row 0 in TMS
    cur.execute(
        "INSERT INTO tiles (zoom_level, tile_column, tile_row, tile_data) VALUES (?, ?, ?, ?)",
        (1, 0, 0, png_bytes),
    )
    conn.commit()
    conn.close()

    return db_path


def test_mbtiles_list_maps():
    """Verify that existing base_offline.mbtiles is discovered and parsed."""
    maps = MBTilesManager.list_maps()
    assert isinstance(maps, list)
    assert len(maps) >= 1
    base_map = next((m for m in maps if m["id"] == "base_offline"), None)
    assert base_map is not None
    assert base_map["format"] == "png"
    assert base_map["minzoom"] <= 0
    assert base_map["maxzoom"] >= 12
    assert base_map["size_mb"] > 0


def test_mbtiles_get_tile_base():
    """Verify retrieval of world base tile (0, 0, 0)."""
    res = MBTilesManager.get_tile("base_offline", 0, 0, 0)
    assert res is not None
    data, mime = res
    assert mime == "image/png"
    assert len(data) > 100
    assert data[:4] == b"\x89PNG"


def test_mbtiles_get_tile_default_alias():
    """Verify multi-database 'default' alias retrieval."""
    res = MBTilesManager.get_tile("default", 0, 0, 0)
    assert res is not None
    data, mime = res
    assert mime == "image/png"
    assert len(data) > 100


def test_mbtiles_nonexistent_tile():
    """Verify that out-of-bounds tiles gracefully return None without crashing."""
    res = MBTilesManager.get_tile("base_offline", 22, 999999, 999999)
    assert res is None


def test_mbtiles_http_endpoints():
    """Verify HTTP daemon endpoints for offline maps list and tile retrieval."""
    api = DesktopForensicAPI()
    port = api.http_port

    # 1. Test /api/offline_maps
    maps_url = f"http://127.0.0.1:{port}/api/offline_maps"
    with urllib.request.urlopen(maps_url, timeout=5) as resp:
        assert resp.status == 200
        assert "application/json" in resp.headers.get("Content-Type", "")
        payload = json.loads(resp.read().decode("utf-8"))
        assert payload["status"] == "ok"
        assert any(m["id"] == "base_offline" for m in payload["maps"])

    # 2. Test /tiles/base_offline/0/0/0.png
    tile_url = f"http://127.0.0.1:{port}/tiles/base_offline/0/0/0.png"
    with urllib.request.urlopen(tile_url, timeout=5) as resp:
        assert resp.status == 200
        assert resp.headers.get("Content-Type") == "image/png"
        blob = resp.read()
        assert len(blob) > 100
        assert blob[:4] == b"\x89PNG"

    # 3. Test /tiles/default/0/0/0.png
    def_tile_url = f"http://127.0.0.1:{port}/tiles/default/0/0/0.png"
    with urllib.request.urlopen(def_tile_url, timeout=5) as resp:
        assert resp.status == 200
        assert resp.headers.get("Content-Type") == "image/png"

    # 4. Test 404 for missing tile
    bad_url = f"http://127.0.0.1:{port}/tiles/base_offline/25/0/0.png"
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(bad_url, timeout=5)
    assert exc_info.value.code == 404

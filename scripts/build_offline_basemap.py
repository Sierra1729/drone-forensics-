"""
scripts/build_offline_basemap.py

Air-gapped MBTiles builder for PUSHPAK Drone Forensics Workstation.
Downloads base cartography tiles (zooms 0-4 worldwide + zooms 5-10 for operational/sample areas)
via CDN-backed CartoDB Voyager raster tiles (OpenStreetMap-derived vector raster)
and packages them into a standard SQLite .mbtiles file inside gui/maps/base_offline.mbtiles.
"""

from __future__ import annotations

import concurrent.futures
import hashlib
import math
from pathlib import Path
import sqlite3
import time
import urllib.request

MAPS_DIR = Path(__file__).resolve().parent.parent / "gui" / "maps"
MBTILES_PATH = MAPS_DIR / "base_offline.mbtiles"

SUBDOMAINS = ["a", "b", "c", "d"]
BLOCKED_MD5 = "c069a15b2cc2d6b6f527ad09eb93c61a"


def lat_lon_to_tile(lat: float, lon: float, zoom: int) -> tuple[int, int]:
    """Convert latitude, longitude and zoom to OSM tile x, y."""
    lat_rad = math.radians(lat)
    n = 1 << zoom
    x = int((lon + 180.0) / 360.0 * n)
    y = int((1.0 - math.asinh(math.tan(lat_rad)) / math.pi) / 2.0 * n)
    x = max(0, min(n - 1, x))
    y = max(0, min(n - 1, y))
    return x, y


def fetch_tile(z: int, x: int, y: int) -> tuple[int, int, int, bytes | None]:
    """Fetch cartography tile from CDN with rotating subdomains and safety checks."""
    s = SUBDOMAINS[(x + y) % len(SUBDOMAINS)]
    url = f"https://{s}.basemaps.cartocdn.com/rastertiles/voyager/{z}/{x}/{y}.png"
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Referer": "https://pushpak.gov.in/",
        },
    )
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=6) as resp:
                if resp.status == 200:
                    data = resp.read()
                    if len(data) > 200 and data[:4] == b"\x89PNG":
                        if len(data) == 6987 and hashlib.md5(data).hexdigest() == BLOCKED_MD5:
                            return z, x, y, None
                        return z, x, y, data
        except Exception:
            time.sleep(0.15 * (attempt + 1))
    return z, x, y, None


def generate_tile_list() -> list[tuple[int, int, int]]:
    """Compile tile list: zooms 0-4 worldwide + regional zooms for Mumbai/India sample flight area."""
    tiles = set()

    # 1. Zooms 0 to 4 worldwide (341 tiles)
    for z in range(5):
        max_coord = 1 << z
        for x in range(max_coord):
            for y in range(max_coord):
                tiles.add((z, x, y))

    # 2. Key operational sample region: Mumbai & Western India (18.8 to 19.3 N, 72.7 to 73.1 E)
    # Also New Delhi region (28.4 to 28.8 N, 77.0 to 77.4 E)
    regions = [
        (18.8, 19.3, 72.7, 73.1),  # Mumbai / IIT Bombay flight test area
        (28.4, 28.8, 77.0, 77.4),  # Delhi NCR
    ]

    for min_lat, max_lat, min_lon, max_lon in regions:
        for z in range(5, 11):
            min_x, max_y = lat_lon_to_tile(min_lat, min_lon, z)
            max_x, min_y = lat_lon_to_tile(max_lat, max_lon, z)
            x_start, x_end = min(min_x, max_x), max(min_x, max_x)
            y_start, y_end = min(min_y, max_y), max(min_y, max_y)
            for x in range(max(0, x_start - 1), x_end + 2):
                for y in range(max(0, y_start - 1), y_end + 2):
                    tiles.add((z, x, y))

    return sorted(list(tiles), key=lambda t: (t[0], t[1], t[2]))


def init_mbtiles_db(db_path: Path):
    """Initialize standard MBTiles schema."""
    MAPS_DIR.mkdir(parents=True, exist_ok=True)
    if db_path.exists():
        try:
            db_path.unlink()
        except Exception:
            pass

    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()

    # Reset tables
    cur.execute("DROP TABLE IF EXISTS metadata;")
    cur.execute("DROP TABLE IF EXISTS tiles;")
    cur.execute("CREATE TABLE metadata (name text, value text);")
    cur.execute("CREATE TABLE tiles (zoom_level integer, tile_column integer, tile_row integer, tile_data blob);")
    cur.execute("CREATE UNIQUE INDEX IF NOT EXISTS tile_index ON tiles (zoom_level, tile_column, tile_row);")

    metadata = [
        ("name", "PUSHPAK Air-Gapped Base Map"),
        ("type", "baselayer"),
        ("version", "2.0"),
        ("description", "Embedded offline cartographic basemap (CartoDB Voyager / OSM) for PUSHPAK Workstation"),
        ("format", "png"),
        ("minzoom", "0"),
        ("maxzoom", "14"),
        ("bounds", "-180.0,-85.0,180.0,85.0"),
        ("attribution", "© OpenStreetMap contributors, © CARTO | PUSHPAK Air-Gapped Forensic GIS"),
    ]
    cur.executemany("INSERT INTO metadata (name, value) VALUES (?, ?);", metadata)
    conn.commit()
    conn.close()


def main():
    print(f"Target MBTiles location: {MBTILES_PATH}")
    tile_coords = generate_tile_list()
    print(f"Total tiles to package: {len(tile_coords)}")

    init_mbtiles_db(MBTILES_PATH)
    conn = sqlite3.connect(str(MBTILES_PATH))
    cur = conn.cursor()

    success_count = 0
    start_time = time.time()

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        futures = [executor.submit(fetch_tile, z, x, y) for z, x, y in tile_coords]
        for i, future in enumerate(concurrent.futures.as_completed(futures), 1):
            z, x, y, data = future.result()
            if data:
                tms_y = (1 << z) - 1 - y
                cur.execute(
                    "INSERT OR REPLACE INTO tiles (zoom_level, tile_column, tile_row, tile_data) VALUES (?, ?, ?, ?)",
                    (z, x, tms_y, data),
                )
                success_count += 1

            if i % 100 == 0 or i == len(tile_coords):
                conn.commit()
                elapsed = time.time() - start_time
                print(f"Progress: {i}/{len(tile_coords)} tiles processed ({success_count} stored, {elapsed:.1f}s)")

    conn.commit()
    conn.close()

    size_mb = MBTILES_PATH.stat().st_size / (1024 * 1024)
    print(f"\nSUCCESS: Created {MBTILES_PATH.name} ({size_mb:.2f} MB, {success_count} clean tiles).")


if __name__ == "__main__":
    main()

"""
parsers/gis_parser.py

Forensic Parser for Drone 3D Models, LiDAR Point Clouds, and GIS Datasets.
Supported Formats:
- LiDAR Point Clouds: ASPRS LAS / LAZ (.las, .laz)
- 3D Meshes & Geometry: Polygon File Format (.ply), Wavefront (.obj), ASCII Point Clouds (.xyz), ASTM E57 (.e57)
- GIS Vectors & Layers: ESRI Shapefile (.shp), GeoJSON (.geojson), GeoTIFF Orthomosaics (.tif, .tiff)
"""

from __future__ import annotations

import json
import math
import os
import re
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from normalize.schema import NormalizedEvent, EventType
from parsers.base import BaseParser, register_parser


@register_parser
class DroneGIS3DParser(BaseParser):
    """Forensic parser for Drone 3D Photogrammetry, LiDAR, and GIS spatial layers."""

    @property
    def parser_name(self) -> str:
        return "drone_gis_3d_parser"

    @property
    def parser_version(self) -> str:
        return "1.0.0"

    @property
    def supported_platforms(self) -> list[str]:
        return ["las_pointcloud", "laz_pointcloud", "ply_mesh", "obj_mesh", "xyz_pointcloud", "esri_shapefile", "geojson", "geotiff"]

    def can_parse(self, file_path: Path) -> bool:
        path = Path(file_path)
        if not path.is_file() or path.stat().st_size < 12:
            return False

        ext = path.suffix.lower()
        if ext in (".las", ".laz", ".ply", ".obj", ".xyz", ".e57", ".shp", ".geojson"):
            return True

        try:
            with open(path, "rb") as f:
                head = f.read(512)

            if head.startswith(b"LASF"):
                return True
            if head.startswith(b"ply\n") or head.startswith(b"ply\r\n"):
                return True
            if len(head) >= 4 and head[0:4] == b"\x00\x00\x27\x0a":
                return True
            if head.startswith(b"ASTM-E57"):
                return True
            if b'"type": "FeatureCollection"' in head or b'"type": "Feature"' in head:
                return True
            if (head.startswith(b"II*\x00") or head.startswith(b"MM\x00*")) and b"\x87\xaf" in head:
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

        metrics: Dict[str, Any] = {}
        with open(path, "rb") as f:
            head = f.read(512)

        if head.startswith(b"LASF") or ext in (".las", ".laz"):
            metrics = self._parse_las(path)
        elif head.startswith(b"ply\n") or head.startswith(b"ply\r\n") or ext == ".ply":
            metrics = self._parse_ply(path)
        elif ext == ".obj":
            metrics = self._parse_obj(path)
        elif ext == ".xyz":
            metrics = self._parse_xyz(path)
        elif (len(head) >= 4 and head[0:4] == b"\x00\x00\x27\x0a") or ext == ".shp":
            metrics = self._parse_shapefile(path)
        elif ext == ".geojson" or b'"type": "FeatureCollection"' in head:
            metrics = self._parse_geojson(path)
        else:
            metrics = {"format": "Generic 3D/GIS", "size_bytes": path.stat().st_size}

        # 1. Config / 3D Asset metadata event
        events.append(
            NormalizedEvent(
                timestamp_utc=now_utc,
                source_platform="drone_gis_3d",
                event_type=EventType.CONFIG_PARAM.value,
                source_file=path.name,
                source_file_sha256=file_sha256,
                payload={
                    "origin": "3D_GIS_SURVEY_ASSET",
                    "format": metrics.get("format", ext[1:].upper()),
                    "point_count": metrics.get("point_count", 0),
                    "bounds": metrics.get("bounds", {}),
                    "elevation_stats": metrics.get("elevation", {}),
                    "density_estimate": metrics.get("density_estimate", "N/A"),
                },
            )
        )

        # 2. Centroid GPS coordinate event if lat/lon bounding box is identified
        bounds = metrics.get("bounds", {})
        if "min_lat" in bounds and "max_lat" in bounds and "min_lon" in bounds and "max_lon" in bounds:
            c_lat = (bounds["min_lat"] + bounds["max_lat"]) / 2.0
            c_lon = (bounds["min_lon"] + bounds["max_lon"]) / 2.0
            c_alt = metrics.get("elevation", {}).get("mean", 0.0)
            events.append(
                NormalizedEvent(
                    timestamp_utc=now_utc,
                    source_platform="drone_gis_3d_centroid",
                    event_type=EventType.GPS_FIX.value,
                    source_file=path.name,
                    source_file_sha256=file_sha256,
                    latitude=round(c_lat, 7),
                    longitude=round(c_lon, 7),
                    altitude_m=round(c_alt, 2),
                    payload={"survey_layer": path.name, "points": metrics.get("point_count", 0)},
                )
            )

        return events

    def _parse_las(self, path: Path) -> Dict[str, Any]:
        """Parse ASPRS LAS 1.2–1.4 binary header."""
        res: Dict[str, Any] = {"format": "ASPRS LiDAR Point Cloud (LAS)"}
        try:
            with open(path, "rb") as f:
                header = f.read(375)
            if len(header) >= 227:
                v_maj, v_min = header[24], header[25]
                p_count = struct.unpack("<I", header[107:111])[0]
                # Scale factors
                sx, sy, sz = struct.unpack("<ddd", header[131:155])
                # Offsets
                ox, oy, oz = struct.unpack("<ddd", header[155:179])
                # Max / Min bounds
                max_x, min_x = struct.unpack("<dd", header[179:195])
                max_y, min_y = struct.unpack("<dd", header[195:211])
                max_z, min_z = struct.unpack("<dd", header[211:227])

                res["version"] = f"LAS {v_maj}.{v_min}"
                res["point_count"] = p_count
                res["bounds"] = {
                    "min_x": round(min_x, 3), "max_x": round(max_x, 3),
                    "min_y": round(min_y, 3), "max_y": round(max_y, 3),
                    "min_z": round(min_z, 3), "max_z": round(max_z, 3),
                }
                # Check if geographic coordinates
                if -180.0 <= min_x <= 180.0 and -90.0 <= min_y <= 90.0:
                    res["bounds"]["min_lon"] = min_x
                    res["bounds"]["max_lon"] = max_x
                    res["bounds"]["min_lat"] = min_y
                    res["bounds"]["max_lat"] = max_y

                res["elevation"] = {
                    "min": round(min_z, 2),
                    "max": round(max_z, 2),
                    "mean": round((min_z + max_z) / 2.0, 2),
                }
                area = max(1.0, (max_x - min_x) * (max_y - min_y))
                res["density_estimate"] = f"{round(p_count / area, 2)} pts/m²"
        except Exception as e:
            res["error"] = str(e)
        return res

    def _parse_ply(self, path: Path) -> Dict[str, Any]:
        """Parse Stanford PLY header."""
        res: Dict[str, Any] = {"format": "Polygon File Format (PLY)"}
        v_count = 0
        try:
            with open(path, "r", encoding="ascii", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("element vertex"):
                        parts = line.split()
                        if len(parts) >= 3:
                            v_count = int(parts[2])
                    if line == "end_header":
                        break
            res["point_count"] = v_count
        except Exception:
            pass
        return res

    def _parse_obj(self, path: Path) -> Dict[str, Any]:
        """Scan Wavefront OBJ vertices."""
        res: Dict[str, Any] = {"format": "Wavefront 3D Object (OBJ)"}
        v_count = 0
        min_z, max_z = 999999.0, -999999.0
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if line.startswith("v "):
                        v_count += 1
                        parts = line.split()
                        if len(parts) >= 4:
                            z = float(parts[3])
                            min_z = min(min_z, z)
                            max_z = max(max_z, z)
            res["point_count"] = v_count
            if v_count > 0 and min_z <= max_z:
                res["elevation"] = {"min": round(min_z, 2), "max": round(max_z, 2), "mean": round((min_z + max_z)/2.0, 2)}
        except Exception:
            pass
        return res

    def _parse_xyz(self, path: Path) -> Dict[str, Any]:
        """Scan ASCII XYZ point cloud."""
        res: Dict[str, Any] = {"format": "ASCII XYZ Point Cloud"}
        pts = 0
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        try:
                            float(parts[0]), float(parts[1]), float(parts[2])
                            pts += 1
                        except ValueError:
                            continue
            res["point_count"] = pts
        except Exception:
            pass
        return res

    def _parse_shapefile(self, path: Path) -> Dict[str, Any]:
        """Parse ESRI Shapefile binary main file header."""
        res: Dict[str, Any] = {"format": "ESRI Shapefile (.shp)"}
        try:
            with open(path, "rb") as f:
                header = f.read(100)
            if len(header) >= 100:
                file_len_16 = struct.unpack(">I", header[24:28])[0]
                version = struct.unpack("<I", header[28:32])[0]
                shape_type = struct.unpack("<I", header[32:36])[0]
                xmin, ymin, xmax, ymax = struct.unpack("<dddd", header[36:68])
                zmin, zmax = struct.unpack("<dd", header[68:84])

                res["shape_type"] = shape_type
                res["bounds"] = {
                    "min_lon": xmin, "max_lon": xmax,
                    "min_lat": ymin, "max_lat": ymax,
                    "min_z": zmin, "max_z": zmax,
                }
                res["elevation"] = {"min": zmin, "max": zmax, "mean": (zmin + zmax) / 2.0}
        except Exception as e:
            res["error"] = str(e)
        return res

    def _parse_geojson(self, path: Path) -> Dict[str, Any]:
        """Parse GeoJSON feature collection."""
        res: Dict[str, Any] = {"format": "GeoJSON Spatial Layer"}
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
            features = data.get("features", [])
            res["point_count"] = len(features)
            lats, lons = [], []
            for feat in features[:200]:
                geom = feat.get("geometry", {})
                coords = geom.get("coordinates", [])
                if geom.get("type") == "Point" and len(coords) >= 2:
                    lons.append(coords[0])
                    lats.append(coords[1])
            if lats and lons:
                res["bounds"] = {
                    "min_lat": min(lats), "max_lat": max(lats),
                    "min_lon": min(lons), "max_lon": max(lons),
                }
        except Exception:
            pass
        return res

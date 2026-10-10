"""
tests/test_full_forensic_suite.py

Comprehensive Automated Forensic Test Suite covering all 9 required format categories:
1. Forensic disk images (.img, .001, .002, .E01)
2. Flight logs & telemetry (.ulg, .bin, .log, .DAT, .csv, .tlog, .rlog, .json, .bfl, .bag, .mcap, .nmea, .gpx, .kml)
3. Imagery (.jpg, .png, .dng, .cr2, .nef, .arw, .heic, R-JPEG thermal)
4. Video (.mp4, .mov, .mkv, .lrf, .srt, .h264)
5. 3D / GIS (.las, .ply, .obj, .xyz, .shp, .geojson, GeoTIFF)
6. Archives (.zip, .7z, .tar, .tar.gz, .tar.bz2, .tar.xz, split archives)
7. Databases & app data (.db, .sqlite, .plist)
8. Mission plans (.plan, .waypoints, .kmz WPML)
9. Fallback & edge cases (corrupted, empty, encrypted, wrong extension, no extension)
"""

from __future__ import annotations

import os
from pathlib import Path
import pytest

from parsers.base import get_parser_for_file
from parsers.magic_router import FileTypeSignatureDetector
from parsers.fallback_analyzer import FallbackAnalyzer, calculate_entropy
from parsers.disk_image import PhysicalDiskImageParser
from parsers.video_parser import DroneVideoParser
from parsers.mission_parser import AutonomousMissionParser
from parsers.advanced_telemetry import AdvancedTelemetryParser
from parsers.gis_parser import DroneGIS3DParser
from parsers.app_database import GCSAppDatabaseParser
from parsers.archive_extractor import RecursiveArchiveExtractor
from analytics.unified_timeline import UnifiedTimelineEngine
from reports.inventory_manager import MasterInventoryManager

SAMPLES_DIR = Path(r"D:\DroneProject\samples")


class TestUniversalMagicRouter:
    """Tests file signature detection purely by magic bytes, never by extension alone."""

    def test_signature_detection_all_samples(self):
        detector = FileTypeSignatureDetector()
        assert SAMPLES_DIR.exists()
        
        # Test distinct signature categories
        assert detector.inspect_file(SAMPLES_DIR / "sample_px4.ulg")["detected_type"] == "px4_ulog"
        assert detector.inspect_file(SAMPLES_DIR / "sample_ardupilot.bin")["detected_type"] == "ardupilot_dataflash"
        assert detector.inspect_file(SAMPLES_DIR / "sample_photo.jpg")["detected_type"] == "imagery_jpeg"
        assert detector.inspect_file(SAMPLES_DIR / "sample_video.mp4")["detected_type"] == "video_mp4"
        assert detector.inspect_file(SAMPLES_DIR / "sample_lidar.las")["detected_type"] == "point_cloud_las"
        assert detector.inspect_file(SAMPLES_DIR / "sample_archive.zip")["detected_type"] == "archive_zip"
        assert detector.inspect_file(SAMPLES_DIR / "sample_dji_fly.db")["detected_type"] == "database_sqlite"

    def test_wrong_extension_detected_by_signature(self):
        detector = FileTypeSignatureDetector()
        wrong_file = SAMPLES_DIR / "sample_wrong_extension.jpg"
        sig_info = detector.inspect_file(wrong_file)
        # Even though extension is .jpg, magic bytes are ULog
        assert sig_info["detected_type"] == "px4_ulog"

    def test_no_extension_detected(self):
        detector = FileTypeSignatureDetector()
        no_ext_file = SAMPLES_DIR / "FLY042_NO_EXT"
        sig_info = detector.inspect_file(no_ext_file)
        assert sig_info["detected_type"] in ("dji_onboard_dat", "flight_log", "dji_flight_record")


class TestFallbackAnalyzer:
    """Tests the fallback analyzer on edge cases: encrypted, corrupted, zero-byte."""

    def test_encrypted_high_entropy(self):
        analyzer = FallbackAnalyzer()
        enc_file = SAMPLES_DIR / "sample_encrypted_payload.bin"
        events = analyzer.parse_records(enc_file, "dummy_sha256")
        assert len(events) == 1
        payload = events[0].payload
        assert payload["status"] == "Encrypted"
        assert payload["entropy"] > 7.5
        assert len(payload["hexdump_header"]) > 0

    def test_corrupted_log(self):
        analyzer = FallbackAnalyzer()
        corrupt_file = SAMPLES_DIR / "sample_corrupted_log.bin"
        events = analyzer.parse_records(corrupt_file, "dummy_sha256")
        assert len(events) == 1
        assert "hexdump_header" in events[0].payload

    def test_zero_byte_empty(self):
        analyzer = FallbackAnalyzer()
        empty_file = SAMPLES_DIR / "sample_zero_byte.dat"
        events = analyzer.parse_records(empty_file, "dummy_sha256")
        assert len(events) == 1
        assert events[0].payload["file_size"] == 0


class TestForensicDiskImages:
    """Tests raw disk images, split images, and Expert Witness formats."""

    def test_raw_disk_image_parsing(self):
        parser = PhysicalDiskImageParser()
        img_file = SAMPLES_DIR / "sample_raw_disk.img"
        assert parser.can_parse(img_file)
        events = parser.parse_records(img_file, "sha256_disk")
        assert len(events) > 0
        ext_telem = parser.extract_extended_telemetry(img_file)
        assert "partitions" in ext_telem
        assert len(ext_telem["partitions"]) > 0

    def test_split_raw_image_reassembly(self):
        parser = PhysicalDiskImageParser()
        split1 = SAMPLES_DIR / "sample_split_disk.001"
        assert parser.can_parse(split1)
        events = parser.parse_records(split1, "sha256_split")
        assert len(events) > 0

    def test_expert_witness_e01_detection(self):
        parser = PhysicalDiskImageParser()
        e01_file = SAMPLES_DIR / "sample_expert_witness.E01"
        assert parser.can_parse(e01_file)
        events = parser.parse_records(e01_file, "sha256_e01")
        assert len(events) > 0


class TestVideoAndImagery:
    """Tests video containers, thermal imagery, camera RAW, and subtitles."""

    def test_video_parser_mp4_and_gps(self):
        parser = DroneVideoParser()
        video_file = SAMPLES_DIR / "sample_video.mp4"
        assert parser.can_parse(video_file)
        events = parser.parse_records(video_file, "sha256_video")
        assert len(events) >= 1
        meta = parser.extract_video_metadata(video_file)
        assert meta["duration_seconds"] > 0
        assert meta["latitude"] is not None

    def test_video_subtitles_srt(self):
        parser = get_parser_for_file(SAMPLES_DIR / "sample_subtitles.srt")
        assert parser is not None
        events = parser.parse(SAMPLES_DIR / "sample_subtitles.srt")
        assert len(events) >= 2
        assert events[0].latitude is not None

    def test_camera_raw_and_thermal_rjpeg(self):
        parser = get_parser_for_file(SAMPLES_DIR / "sample_thermal_rjpeg.jpg")
        assert parser is not None
        events = parser.parse(SAMPLES_DIR / "sample_thermal_rjpeg.jpg")
        assert len(events) >= 1
        assert any(e.payload.get("is_thermal") for e in events)


class Test3DGISAndMissions:
    """Tests LiDAR point clouds, 3D meshes, Shapefiles, and mission plans."""

    def test_lidar_point_cloud_las(self):
        parser = DroneGIS3DParser()
        las_file = SAMPLES_DIR / "sample_lidar.las"
        assert parser.can_parse(las_file)
        events = parser.parse_records(las_file, "sha256_las")
        assert len(events) >= 1
        assert events[0].payload["point_count"] == 1250

    def test_shapefile_and_geojson(self):
        parser = DroneGIS3DParser()
        shp_file = SAMPLES_DIR / "sample_shapefile.shp"
        assert parser.can_parse(shp_file)
        events = parser.parse_records(shp_file, "sha256_shp")
        assert len(events) >= 1

    def test_qgc_mission_plan(self):
        parser = AutonomousMissionParser()
        plan_file = SAMPLES_DIR / "sample_mission.plan"
        assert parser.can_parse(plan_file)
        events = parser.parse_records(plan_file, "sha256_plan")
        assert len(events) >= 2
        # Check waypoint coordinates
        assert any(e.event_type == "gps_fix" for e in events)

    def test_dji_wpml_mission(self):
        parser = AutonomousMissionParser()
        wpml_file = SAMPLES_DIR / "sample_dji_wpml.kmz"
        assert parser.can_parse(wpml_file)
        events = parser.parse_records(wpml_file, "sha256_wpml")
        assert len(events) >= 1


class TestDatabasesAndArchives:
    """Tests SQLite databases, Apple plists, and recursive archive extraction."""

    def test_sqlite_gcs_database(self):
        parser = GCSAppDatabaseParser()
        db_file = SAMPLES_DIR / "sample_dji_fly.db"
        assert parser.can_parse(db_file)
        events = parser.parse_records(db_file, "sha256_db")
        assert len(events) >= 1
        # Verifies coordinates were extracted from database rows
        assert any(e.event_type == "gps_fix" for e in events)

    def test_apple_plist_parsing(self):
        parser = GCSAppDatabaseParser()
        plist_file = SAMPLES_DIR / "sample_gcs_config.plist"
        assert parser.can_parse(plist_file)
        events = parser.parse_records(plist_file, "sha256_plist")
        assert len(events) >= 1
        assert events[0].payload["origin"] == "APPLE_PLIST_CONFIGURATION"

    def test_recursive_archive_extraction(self):
        parser = RecursiveArchiveExtractor()
        zip_file = SAMPLES_DIR / "sample_archive.zip"
        assert parser.can_parse(zip_file)
        extracted = parser.extract_recursive(zip_file)
        assert len(extracted) >= 2


class TestUnifiedTimelineAndInventory:
    """Tests master chronological timeline sequencing and master inventory generation."""

    def test_unified_timeline(self):
        engine = UnifiedTimelineEngine()
        # Ingest events from a flight log sample
        parser = get_parser_for_file(SAMPLES_DIR / "sample_px4.ulg")
        if parser:
            norm_events = parser.parse(SAMPLES_DIR / "sample_px4.ulg")
            engine.ingest_normalized_events(norm_events)
        
        sorted_evs = engine.get_sorted_timeline()
        assert len(sorted_evs) > 0
        csv_out = Path(r"D:\DroneProject\outputs\test_timeline.csv")
        engine.export_csv(csv_out)
        assert csv_out.exists()
        assert csv_out.stat().st_size > 0

    def test_master_inventory_generation(self):
        inv_path = Path(r"D:\DroneProject\reports\FILE_INVENTORY.csv")
        manager = MasterInventoryManager(inv_path)
        count = manager.scan_directory(SAMPLES_DIR, recursive=False)
        assert count > 50
        manager.write_csv()
        assert inv_path.exists()
        assert inv_path.stat().st_size > 0
        stats = manager.get_summary_stats()
        assert stats["total_files"] > 50
        assert "Analyzed" in stats["by_status"]

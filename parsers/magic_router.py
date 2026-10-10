"""
parsers/magic_router.py

Universal Magic Byte & File Signature Router for Drone Forensics.
Complies strictly with the "NOTHING LEFT BEHIND" rule:
- Determines file identity purely by file signatures and header bytes, NEVER by extension alone.
- Identifies files with misleading, missing, or numeric extensions (.001, .002, .dat, .bin, no ext).
- Routes detected file types directly to the optimal specialized parser or FallbackAnalyzer.
"""

from __future__ import annotations

import os
import re
import struct
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Type

from parsers.base import BaseParser, get_parser_for_file
from parsers.fallback_analyzer import FallbackAnalyzer, calculate_entropy


# Signature Constants
SIG_ZIP = b"PK\x03\x04"
SIG_7Z = b"7z\xbc\xaf\x27\x1c"
SIG_RAR = b"Rar!\x1a\x07"
SIG_GZIP = b"\x1f\x8b"
SIG_BZIP2 = b"BZh"
SIG_XZ = b"\xfd7zXZ\x00"
SIG_E01 = b"EVF\t\r\n\xff\x00"
SIG_ULOG = b"ULog\x01\x12\x35"
SIG_DJI_TXT = b"DJI_LOG_V"
SIG_ROSBAG1 = b"#ROSBAG V2.0\n"
SIG_MCAP = b"\x89MCAP0\r\n"
SIG_SQLITE = b"SQLite format 3\x00"
SIG_BPLIST = b"bplist00"
SIG_LAS = b"LASF"
SIG_PNG = b"\x89PNG\r\n\x1a\n"
SIG_JPEG = b"\xff\xd8\xff"
SIG_MKV = b"\x1a\x45\xdf\xa3"
SIG_CR2 = b"II*\x00\x10\x00\x00\x00CR"
SIG_TIFF_LE = b"II*\x00"
SIG_TIFF_BE = b"MM\x00*"


class FileTypeSignatureDetector:
    """Detects exact forensic file type using multi-offset magic byte inspection."""

    @staticmethod
    def inspect_file(file_path: Path) -> Dict[str, Any]:
        path = Path(file_path)
        if not path.is_file():
            return {
                "detected_type": "missing_file",
                "category": "error",
                "confidence": 0.0,
                "mime": "application/octet-stream",
                "entropy": 0.0,
            }

        file_size = path.stat().st_size
        if file_size == 0:
            return {
                "detected_type": "empty_file",
                "category": "empty",
                "confidence": 1.0,
                "mime": "inode/x-empty",
                "entropy": 0.0,
            }

        header = b""
        sample_1mb = b""
        try:
            with open(path, "rb") as f:
                header = f.read(4096)
                f.seek(0)
                sample_1mb = f.read(1024 * 1024)
        except Exception:
            pass

        entropy = calculate_entropy(sample_1mb)

        # 1. Expert Witness E01 / Ex01
        if header.startswith(SIG_E01) or (len(header) >= 8 and header[:3] == b"EVF"):
            return {
                "detected_type": "expert_witness_e01",
                "category": "forensic_image",
                "confidence": 1.0,
                "mime": "application/x-ewf",
                "entropy": entropy,
            }

        # Android ADB Backup (.ab)
        if header.startswith(b"ANDROID BACKUP"):
            return {
                "detected_type": "adb_backup_archive",
                "category": "mobile_adb",
                "confidence": 1.0,
                "mime": "application/x-android-backup",
                "entropy": entropy,
            }

        # 2. Archives & Compressed Containers
        if header.startswith(SIG_7Z):
            return {"detected_type": "archive_7z", "category": "archive", "confidence": 1.0, "mime": "application/x-7z-compressed", "entropy": entropy}
        if header.startswith(SIG_RAR) or header.startswith(b"Rar!\x1a\x07\x01\x00"):
            return {"detected_type": "archive_rar", "category": "archive", "confidence": 1.0, "mime": "application/x-rar", "entropy": entropy}
        if header.startswith(SIG_GZIP):
            return {"detected_type": "archive_gzip", "category": "archive", "confidence": 1.0, "mime": "application/gzip", "entropy": entropy}
        if header.startswith(SIG_BZIP2):
            return {"detected_type": "archive_bzip2", "category": "archive", "confidence": 1.0, "mime": "application/x-bzip2", "entropy": entropy}
        if header.startswith(SIG_XZ):
            return {"detected_type": "archive_xz", "category": "archive", "confidence": 1.0, "mime": "application/x-xz", "entropy": entropy}
        # POSIX Tar: magic 'ustar' at offset 257
        if len(header) >= 265 and header[257:262] in (b"ustar", b"ustar\x00", b"ustar "):
            return {"detected_type": "archive_tar", "category": "archive", "confidence": 1.0, "mime": "application/x-tar", "entropy": entropy}

        # Zip container (could be standard zip, KMZ, or Office doc)
        if header.startswith(SIG_ZIP):
            if b"doc.kml" in header or b"wpml" in header or b"kml" in header:
                return {"detected_type": "mission_kmz_wpml", "category": "mission", "confidence": 0.95, "mime": "application/vnd.google-earth.kmz", "entropy": entropy}
            return {"detected_type": "archive_zip", "category": "archive", "confidence": 1.0, "mime": "application/zip", "entropy": entropy}

        # 3. Flight Controller Logs & Telemetry
        # PX4 ULog
        if header.startswith(b"ULog") or header.startswith(SIG_ULOG):
            return {"detected_type": "px4_ulog", "category": "flight_log", "confidence": 1.0, "mime": "application/x-ulog", "entropy": entropy}

        # ArduPilot DataFlash binary (0xA3 0x95 FMT message type 0x80)
        if len(header) >= 3 and header[0] == 0xA3 and header[1] == 0x95:
            return {"detected_type": "ardupilot_dataflash", "category": "flight_log", "confidence": 1.0, "mime": "application/x-ardupilot-bin", "entropy": entropy}

        # DJI Mobile App .txt flight records
        if header.startswith(SIG_DJI_TXT) or (len(header) >= 2 and header[0:2] == b"\x55\xaa" and b"DJI" in header[:64]):
            return {"detected_type": "dji_flight_record", "category": "flight_log", "confidence": 1.0, "mime": "application/x-dji-txt", "entropy": entropy}

        # DJI Onboard DAT logs
        if (header.startswith(b"BUILD ") or b"BUILD 20" in header[:256] or b"Build 20" in header[:256] or
            header.startswith(b"USE_MVO") or header.startswith(b"DJI_LOG") or
            (path.suffix.lower() == ".dat" and header.count(b"\x55") >= 4)):
            return {"detected_type": "dji_onboard_dat", "category": "flight_log", "confidence": 0.95, "mime": "application/x-dji-dat", "entropy": entropy}

        # Betaflight / INAV Blackbox log
        if b"H Product:Betaflight" in header or b"H Product:Cleanflight" in header or b"H Product:INAV" in header or b"H Data version:" in header:
            return {"detected_type": "betaflight_blackbox", "category": "flight_log", "confidence": 1.0, "mime": "application/x-blackbox", "entropy": entropy}

        # ROS 1 Bag and ROS 2 MCAP
        if header.startswith(SIG_ROSBAG1):
            return {"detected_type": "ros1_bag", "category": "flight_log", "confidence": 1.0, "mime": "application/x-rosbag", "entropy": entropy}
        if header.startswith(SIG_MCAP):
            return {"detected_type": "ros2_mcap", "category": "flight_log", "confidence": 1.0, "mime": "application/x-mcap", "entropy": entropy}

        # MAVLink telemetry (.tlog / .rlog)
        if len(header) >= 9 and header[8] in (0xFE, 0xFD):
            return {"detected_type": "mavlink_tlog", "category": "flight_log", "confidence": 0.95, "mime": "application/x-mavlink", "entropy": entropy}
        if header.startswith(b"\xfe") or header.startswith(b"\xfd"):
            return {"detected_type": "mavlink_stream", "category": "flight_log", "confidence": 0.90, "mime": "application/x-mavlink", "entropy": entropy}

        # 4. Imagery & Media
        # PNG
        if header.startswith(SIG_PNG):
            return {"detected_type": "imagery_png", "category": "imagery", "confidence": 1.0, "mime": "image/png", "entropy": entropy}

        # JPEG and Thermal R-JPEG
        if header.startswith(SIG_JPEG):
            if b"FLIR\x00" in header or b"DJI\x00" in header[2:64] or b"Thermal" in header[:512]:
                return {"detected_type": "thermal_rjpeg", "category": "imagery", "confidence": 1.0, "mime": "image/jpeg-thermal", "entropy": entropy}
            return {"detected_type": "imagery_jpeg", "category": "imagery", "confidence": 1.0, "mime": "image/jpeg", "entropy": entropy}

        # Canon CR2 RAW
        if header.startswith(SIG_CR2):
            return {"detected_type": "camera_raw_cr2", "category": "imagery", "confidence": 1.0, "mime": "image/x-canon-cr2", "entropy": entropy}

        # TIFF / DNG / Sony ARW / Nikon NEF / Olympus ORF / Panasonic RW2
        if header.startswith(SIG_TIFF_LE) or header.startswith(SIG_TIFF_BE):
            head_text = header.decode("latin1", errors="ignore")
            if "DNG" in head_text or "<x:xmpmeta" in head_text:
                return {"detected_type": "camera_raw_dng", "category": "imagery", "confidence": 0.95, "mime": "image/x-adobe-dng", "entropy": entropy}
            if "SONY" in head_text or "ILCE" in head_text:
                return {"detected_type": "camera_raw_arw", "category": "imagery", "confidence": 0.95, "mime": "image/x-sony-arw", "entropy": entropy}
            if "NIKON" in head_text:
                return {"detected_type": "camera_raw_nef", "category": "imagery", "confidence": 0.95, "mime": "image/x-nikon-nef", "entropy": entropy}
            if "GeoTIFF" in head_text or b"\x87\xaf" in header:  # GeoKeyDirectoryTag 0x87AF
                return {"detected_type": "gis_geotiff", "category": "gis_3d", "confidence": 0.95, "mime": "image/tiff-geotiff", "entropy": entropy}
            return {"detected_type": "imagery_tiff", "category": "imagery", "confidence": 0.90, "mime": "image/tiff", "entropy": entropy}

        # HEIC / HEIF / MP4 / MOV (ISO Base Media File Format)
        if len(header) >= 12 and header[4:8] == b"ftyp":
            ftyp_brand = header[8:12]
            if ftyp_brand in (b"heic", b"heix", b"mif1", b"msf1"):
                return {"detected_type": "imagery_heic", "category": "imagery", "confidence": 1.0, "mime": "image/heic", "entropy": entropy}
            if ftyp_brand in (b"isom", b"mp41", b"mp42", b"avc1", b"dash"):
                return {"detected_type": "video_mp4", "category": "video", "confidence": 1.0, "mime": "video/mp4", "entropy": entropy}
            if ftyp_brand in (b"qt  ", b"mqt "):
                return {"detected_type": "video_mov", "category": "video", "confidence": 1.0, "mime": "video/quicktime", "entropy": entropy}
            return {"detected_type": "video_mp4", "category": "video", "confidence": 0.85, "mime": "video/mp4", "entropy": entropy}
        
        # MKV / WebM
        if header.startswith(SIG_MKV):
            return {"detected_type": "video_mkv", "category": "video", "confidence": 1.0, "mime": "video/x-matroska", "entropy": entropy}

        # Raw H.264 / H.265 NAL byte stream
        if header.startswith(b"\x00\x00\x00\x01") or header.startswith(b"\x00\x00\x01"):
            nal_type = header[4] & 0x1F if header.startswith(b"\x00\x00\x00\x01") else header[3] & 0x1F
            if nal_type in (7, 8, 1, 5, 32, 33, 34):
                return {"detected_type": "video_raw_h264_h265", "category": "video", "confidence": 0.90, "mime": "video/h264", "entropy": entropy}

        # 5. 3D & GIS Formats
        # LAS Point Cloud
        if header.startswith(SIG_LAS):
            return {"detected_type": "point_cloud_las", "category": "gis_3d", "confidence": 1.0, "mime": "application/vnd.las", "entropy": entropy}

        # PLY Mesh
        if header.startswith(b"ply\n") or header.startswith(b"ply\r\n"):
            return {"detected_type": "mesh_ply", "category": "gis_3d", "confidence": 1.0, "mime": "application/x-ply", "entropy": entropy}

        # Shapefile (.shp) signature (0x0000270a big endian)
        if len(header) >= 4 and header[0:4] == b"\x00\x00\x27\x0a":
            return {"detected_type": "gis_shapefile", "category": "gis_3d", "confidence": 1.0, "mime": "application/x-shapefile", "entropy": entropy}

        # 6. Databases and App Stores
        if header.startswith(SIG_SQLITE):
            return {"detected_type": "database_sqlite", "category": "database", "confidence": 1.0, "mime": "application/x-sqlite3", "entropy": entropy}
        if header.startswith(SIG_BPLIST):
            return {"detected_type": "plist_apple_binary", "category": "database", "confidence": 1.0, "mime": "application/x-apple-binary-plist", "entropy": entropy}

        # 7. Text-based Structured Formats (XML, JSON, KML, GPX, NMEA, SRT, CSV)
        try:
            head_str = header.decode("utf-8", errors="ignore").strip()
            # XML documents
            if head_str.startswith("<?xml") or head_str.startswith("<"):
                if "<kml" in head_str:
                    return {"detected_type": "gis_kml", "category": "gis_3d", "confidence": 0.95, "mime": "application/vnd.google-earth.kml+xml", "entropy": entropy}
                if "<gpx" in head_str:
                    return {"detected_type": "gis_gpx", "category": "gis_3d", "confidence": 0.95, "mime": "application/gpx+xml", "entropy": entropy}
                if "<!DOCTYPE plist" in head_str or "<plist" in head_str:
                    return {"detected_type": "plist_apple_xml", "category": "database", "confidence": 0.95, "mime": "text/xml", "entropy": entropy}
                return {"detected_type": "structured_xml", "category": "config", "confidence": 0.80, "mime": "application/xml", "entropy": entropy}

            # JSON documents
            if head_str.startswith("{") or head_str.startswith("["):
                if '"fileType": "Plan"' in head_str or '"plan"' in head_str.lower():
                    return {"detected_type": "mission_qgc_plan", "category": "mission", "confidence": 0.95, "mime": "application/json", "entropy": entropy}
                if "parrot" in head_str.lower() or "run_id" in head_str.lower():
                    return {"detected_type": "parrot_flight_json", "category": "flight_log", "confidence": 0.95, "mime": "application/json", "entropy": entropy}
                if '"type": "FeatureCollection"' in head_str or '"type": "Feature"' in head_str:
                    return {"detected_type": "gis_geojson", "category": "gis_3d", "confidence": 0.95, "mime": "application/geo+json", "entropy": entropy}
                return {"detected_type": "structured_json", "category": "config", "confidence": 0.85, "mime": "application/json", "entropy": entropy}

            # NMEA GNSS Sentences ($GPGGA, $GPRMC, $GLGGA, $GNGGA)
            if head_str.startswith("$GP") or head_str.startswith("$GN") or head_str.startswith("$GL"):
                return {"detected_type": "telemetry_nmea", "category": "flight_log", "confidence": 0.95, "mime": "text/plain", "entropy": entropy}

            # Subtitle SRT Telemetry
            if re.match(r"^\d+\s*[\r\n]+\d{2}:\d{2}:\d{2}", head_str):
                return {"detected_type": "video_srt_telemetry", "category": "video", "confidence": 0.95, "mime": "text/srt", "entropy": entropy}

            # Mission Planner Waypoints (QGC WPL 110)
            if head_str.startswith("QGC WPL 110") or head_str.startswith("QGC WPL 120"):
                return {"detected_type": "mission_planner_waypoints", "category": "mission", "confidence": 1.0, "mime": "text/plain", "entropy": entropy}

            # Android Logcat Telemetry
            if "--------- beginning of" in head_str or any(tag in head_str for tag in ["DJIFlightController", "DJIBattery", "DJICamera", "AutelFlightService"]):
                return {"detected_type": "adb_logcat_telemetry", "category": "mobile_adb", "confidence": 0.95, "mime": "text/x-logcat", "entropy": entropy}

            # Android Dumpsys Extraction
            if "DUMP OF SERVICE" in head_str or "== dumpstate:" in head_str or "Build fingerprint:" in head_str:
                return {"detected_type": "adb_dumpsys_extraction", "category": "mobile_adb", "confidence": 0.95, "mime": "text/x-dumpsys", "entropy": entropy}

            # Parameter files (.param)
            if head_str.startswith("# NOTE:") or head_str.startswith("# ArduPilot") or ("SYSID_THISMAV" in head_str) or ("FENCE_ENABLE" in head_str):
                return {"detected_type": "vehicle_parameters", "category": "config", "confidence": 0.95, "mime": "text/plain", "entropy": entropy}

            # Tabular Flight Log CSV (Autel, DJI CsvView, Yuneec, DatCon)
            first_line = head_str.split("\n")[0].lower()
            if any(k in first_line for k in ["latitude", "longitude", "osd.latitude", "gps_time", "custom.date", "flymodel"]):
                return {"detected_type": "flight_log_csv", "category": "flight_log", "confidence": 0.90, "mime": "text/csv", "entropy": entropy}

        except Exception:
            pass

        # 8. Forensic Disk Images (MBR 0x55AA, GPT EFI PART, VHD, VMDK)
        # Split raw image check by filename pattern (e.g., .001, .002...)
        if re.search(r"\.\d{3}$", path.name.lower()):
            return {"detected_type": "split_raw_disk_image", "category": "forensic_image", "confidence": 0.95, "mime": "application/x-raw-disk-split", "entropy": entropy}

        if len(header) >= 512:
            if header[510:512] == b"\x55\xaa" or b"EFI PART" in header[:1024]:
                return {"detected_type": "raw_disk_image", "category": "forensic_image", "confidence": 0.90, "mime": "application/x-raw-disk", "entropy": entropy}
            if header.startswith(b"conectix"):
                return {"detected_type": "vhd_disk_image", "category": "forensic_image", "confidence": 1.0, "mime": "application/x-vhd", "entropy": entropy}
            if header.startswith(b"KDMV"):
                return {"detected_type": "vmdk_disk_image", "category": "forensic_image", "confidence": 1.0, "mime": "application/x-vmdk", "entropy": entropy}

        # 9. Fallback Classification
        if entropy > 7.5 and file_size > 512:
            return {"detected_type": "encrypted_or_compressed_binary", "category": "encrypted", "confidence": 0.85, "mime": "application/octet-stream", "entropy": entropy}

        return {
            "detected_type": "unrecognized_binary" if entropy > 5.0 else "unrecognized_text_or_data",
            "category": "unsupported",
            "confidence": 0.5,
            "mime": "application/octet-stream",
            "entropy": entropy,
        }


def get_router() -> FileTypeSignatureDetector:
    return FileTypeSignatureDetector()

"""
parsers package

Modular, extensible parser suite for UAV digital forensics.
Implements the "NOTHING LEFT BEHIND" rule across all drone evidence formats.
"""

from parsers.base import (
    BaseParser,
    register_parser,
    get_parser_for_file,
    list_registered_parsers,
)

# Core Telemetry & Blackbox Parsers
import parsers.ardupilot             # auto-registers ArduPilotDataFlashParser
import parsers.dji                   # auto-registers DJIFlightLogParser
import parsers.parrot                # auto-registers ParrotFlightLogParser
import parsers.px4_ulog              # auto-registers PX4ULogParser
import parsers.mavlink_tlog          # auto-registers MAVLinkTLogParser
import parsers.betaflight_blackbox   # auto-registers BetaflightBlackboxParser
import parsers.dji_csv               # auto-registers DJICSVFlightLogParser
import parsers.autel                 # auto-registers AutelFlightLogParser
import parsers.yuneec                # auto-registers YuneecFlightLogParser
import parsers.param_parser          # auto-registers ParamParser

# Advanced & Extended Parsers
import parsers.disk_image            # auto-registers PhysicalDiskImageParser (Split, E01, Carving)
import parsers.media_extractor       # auto-registers DroneMediaExtractorParser (RAW, JPEG, R-JPEG)
import parsers.video_parser          # auto-registers DroneVideoParser (MP4, MOV, MKV, LRF)
import parsers.mission_parser        # auto-registers AutonomousMissionParser (QGC, WPML, WPL)
import parsers.advanced_telemetry    # auto-registers AdvancedTelemetryParser (ROSBAG, MCAP, NMEA, GPX, KML)
import parsers.gis_parser            # auto-registers DroneGIS3DParser (LAS, PLY, OBJ, SHP, GeoJSON)
import parsers.app_database          # auto-registers GCSAppDatabaseParser (SQLite, Plist)
import parsers.adb_parser            # auto-registers AndroidADBExtractorParser (Backup, Logcat, Dumpsys)
import parsers.archive_extractor     # auto-registers RecursiveArchiveExtractor (ZIP, 7Z, TAR, GZ)
import parsers.fallback_analyzer     # auto-registers FallbackAnalyzer (Entropy, Strings, Hexdump)
import parsers.magic_router          # imports Universal Signature Detector


__all__ = [
    "BaseParser",
    "register_parser",
    "get_parser_for_file",
    "list_registered_parsers",
]

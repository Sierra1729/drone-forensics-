"""
parsers package

Modular, extensible parser suite for UAV digital forensics.
"""

from parsers.base import (
    BaseParser,
    register_parser,
    get_parser_for_file,
    list_registered_parsers,
)
import parsers.ardupilot             # auto-registers ArduPilotDataFlashParser
import parsers.dji                   # auto-registers DJIFlightLogParser
import parsers.parrot                # auto-registers ParrotFlightLogParser
import parsers.px4_ulog              # auto-registers PX4ULogParser
import parsers.mavlink_tlog          # auto-registers MAVLinkTLogParser
import parsers.betaflight_blackbox   # auto-registers BetaflightBlackboxParser
import parsers.autel                 # auto-registers AutelFlightLogParser
import parsers.yuneec                # auto-registers YuneecFlightLogParser
import parsers.media_extractor        # auto-registers DroneMediaExtractorParser

__all__ = [
    "BaseParser",
    "register_parser",
    "get_parser_for_file",
    "list_registered_parsers",
]

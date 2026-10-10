"""
acquisition/__init__.py

Forensic Hardware Acquisition and Direct Device Extraction Engine.
Compliant with ISO/IEC 27037:2012 (Identification, Collection, Acquisition, Preservation)
and Section 63 Bharatiya Sakshya Adhiniyam (BSA) 2023.

Modules:
- mavlink_extractor: Logical binary flight log extraction (.bin, .ulg) from UAV
  flight controllers over Serial USB, TCP, or UDP using MAVLink Log Transfer Protocol.
- adb_extractor: Mobile and smart controller forensic extraction for Android companion
  apps (DJI Fly, DJI Go, DJI Pilot, Autel Explorer, Yuneec DataPilot) via Android Debug Bridge.
"""

from __future__ import annotations

from acquisition.mavlink_extractor import (
    MavlinkExtractor,
    MAVLinkExtractor,
    MavlinkLogEntry,
    MavlinkAcquisitionResult,
    list_available_serial_ports,
)
from acquisition.adb_extractor import (
    AdbExtractor,
    ADBExtractor,
    AdbDeviceInfo,
    AdbAcquisitionResult,
    list_available_adb_devices,
    triage_offline_dump,
    GcsPilotIdentity,
    GcsHardwareMetadata,
    GcsOfflineTriageResult,
    parse_shared_prefs_xml,
    parse_sqlite_db_artifacts,
)
from acquisition.spiflash_extractor import (
    SPIFlashExtractor,
    SPIFlashExtractionResult,
    SPIFlashStatusRegister,
    SPIFlashReadError,
    WriteProtectError,
    KNOWN_SPI_CHIPSETS,
)
from acquisition.uart_jtag_extractor import (
    UARTJTAGExtractor,
    UARTJTAGExtractionResult,
    BootloaderEnvResult,
    SUPPORTED_BAUD_RATES,
)
from acquisition.write_blocker import (
    verify_write_blocker_status,
    WriteBlockerMissingError,
    HardwareWriteBlocker,
    verify_hardware_write_block,
    WriteBlockStatus,
    HardwareWriteBlockError,
)

__all__ = [
    "MavlinkExtractor",
    "MAVLinkExtractor",
    "MavlinkLogEntry",
    "MavlinkAcquisitionResult",
    "list_available_serial_ports",
    "AdbExtractor",
    "ADBExtractor",
    "AdbDeviceInfo",
    "AdbAcquisitionResult",
    "list_available_adb_devices",
    "triage_offline_dump",
    "GcsPilotIdentity",
    "GcsHardwareMetadata",
    "GcsOfflineTriageResult",
    "parse_shared_prefs_xml",
    "parse_sqlite_db_artifacts",
    "SPIFlashExtractor",
    "SPIFlashExtractionResult",
    "SPIFlashStatusRegister",
    "SPIFlashReadError",
    "WriteProtectError",
    "KNOWN_SPI_CHIPSETS",
    "UARTJTAGExtractor",
    "UARTJTAGExtractionResult",
    "BootloaderEnvResult",
    "SUPPORTED_BAUD_RATES",
    "verify_write_blocker_status",
    "WriteBlockerMissingError",
    "HardwareWriteBlocker",
    "verify_hardware_write_block",
    "WriteBlockStatus",
    "HardwareWriteBlockError",
]




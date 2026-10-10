"""
tests/test_hardware_acquisition.py

Unit tests for hardware acquisition drivers:
- SPIFlashExtractor
- UARTJTAGExtractor
- verify_write_blocker_status / WriteBlockerMissingError
"""

import pytest
from pathlib import Path

from acquisition.spiflash_extractor import (
    SPIFlashExtractor,
    SPIFlashStatusRegister,
    WriteProtectError,
    KNOWN_SPI_CHIPSETS,
)
from acquisition.uart_jtag_extractor import (
    UARTJTAGExtractor,
    SUPPORTED_BAUD_RATES,
)
from acquisition.write_blocker import (
    verify_write_blocker_status,
    WriteBlockerMissingError,
)


def test_spiflash_chipset_detection():
    extractor = SPIFlashExtractor()
    info = extractor.detect_chipset("0xEF4018")
    assert info["vendor"] == "Winbond"
    assert info["model"] == "W25Q128"
    assert info["capacity_bytes"] == 16 * 1024 * 1024


def test_spiflash_status_register_read_only_check():
    extractor = SPIFlashExtractor()
    # 0x8C has SRWD (bit 7) and BP0 (bit 2) set -> Write Protected
    status = extractor.query_status_registers(rdsr1_val=0x8C)
    assert status.srwd_asserted is True
    assert status.write_protected is True
    assert extractor.verify_read_only(status) is True

    # 0x00 has no write protection -> Raises WriteProtectError when strict
    unprotected = extractor.query_status_registers(rdsr1_val=0x00)
    assert unprotected.write_protected is False
    with pytest.raises(WriteProtectError):
        extractor.verify_read_only(unprotected, enforce_strict=True)


def test_spiflash_64kb_block_ingest_and_hashing(tmp_path):
    extractor = SPIFlashExtractor(interface="ft2232h")
    out_file = tmp_path / "spiflash_dump.bin"
    mock_data = b"FORENSIC_SPI_FLASH_DATA_BLOCK_" * 4096  # ~120KB

    res = extractor.dump_flash(
        output_file=out_file,
        capacity_bytes=len(mock_data),
        source_stream=mock_data,
        block_size=65536,
        rdsr1_val=0x8C,
    )

    assert res.read_only_verified is True
    assert res.capacity_bytes == len(mock_data)
    assert res.blocks_ingested == 2
    assert len(res.sha256_hex) == 64
    assert out_file.exists()


def test_uart_jtag_extractor_baud_rates():
    extractor = UARTJTAGExtractor(default_baud=115200)

    for b in SUPPORTED_BAUD_RATES:
        res = extractor.capture_serial_console(port="COM3", baud_rate=b)
        assert res.baud_rate == b
        assert res.bytes_captured > 0

    with pytest.raises(ValueError):
        extractor.capture_serial_console(port="COM3", baud_rate=9600)


def test_uart_bootloader_env_parsing():
    extractor = UARTJTAGExtractor()
    console_out = (
        "[0.000] U-Boot 2024.05-garud\n"
        "=> printenv\n"
        "board_name=PX4_FMU_V5X\n"
        "baudrate=115200\n"
        "bootcmd=run boot_firmware\n"
    )

    res = extractor.parse_bootloader_response(console_out)
    assert res.bootloader_type == "U-Boot"
    assert res.version == "2024.05-garud"
    assert res.environment_vars["board_name"] == "PX4_FMU_V5X"
    assert res.environment_vars["baudrate"] == "115200"


def test_write_blocker_status_verification():
    # Test read-only verified device path
    res = verify_write_blocker_status("/dev/sdb_readonly", force_mock_status=True, mock_read_only=True)
    assert res["write_blocked"] is True

    # Test read-write device path (must raise WriteBlockerMissingError)
    with pytest.raises(WriteBlockerMissingError):
        verify_write_blocker_status("/dev/sdb_rw", force_mock_status=True, mock_read_only=False)

"""Unit and integration tests for Pushpak Hardware Acquisition Subsystem.

Tests MAVLink serial log extraction, Android ADB mobile companion log extraction,
cryptographic dual hashing (SHA-256 + BLAKE3), and Merkle ledger recording.
"""
import os
import sys
import tempfile
import pytest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from acquisition.mavlink_extractor import MavlinkExtractor, list_available_serial_ports
from acquisition.adb_extractor import AdbExtractor, list_available_adb_devices
from custody.ledger import ChainOfCustodyLedger
import gui.api as gui_api



def test_list_available_serial_ports():
    """Verify serial port enumeration."""
    ports = list_available_serial_ports()
    assert isinstance(ports, list)
    assert len(ports) >= 1
    assert "port" in ports[0]
    assert "description" in ports[0]



def test_mavlink_extractor_simulated_list_and_acquire():
    """Verify MavlinkExtractor log enumeration and acquisition in simulation mode."""
    with tempfile.TemporaryDirectory() as tmpdir:
        ledger_path = os.path.join(tmpdir, "chain_of_custody.jsonl")
        ledger = ChainOfCustodyLedger(ledger_path)

        extractor = MavlinkExtractor(connection_uri="COM3", baud=115200, mock_mode=True)
        assert extractor.connect() is True

        logs = extractor.list_logs()
        assert len(logs) >= 2
        assert logs[0].log_id == 1
        assert logs[0].size_bytes > 0

        # Extract log #1
        res = extractor.extract_log(
            log_id=1,
            output_directory=tmpdir,
            custody_ledger=ledger,
            operator_id="INV-UNITTEST-01",
        )
        assert res.success is True
        assert os.path.exists(res.output_file)
        assert len(res.sha256) == 64
        assert len(res.blake3) == 64
        assert res.file_size_bytes > 0

        # Verify ledger entry
        assert os.path.exists(ledger_path)
        ledger_reader = ChainOfCustodyLedger(ledger_path)
        is_valid, broken_idx = ledger_reader.verify_chain()
        assert is_valid is True
        assert broken_idx is None
        assert any(e.action == "ACQUIRE_MAVLINK" for e in ledger_reader._entries)

        extractor.close()


def test_adb_extractor_list_devices():
    """Verify ADB device enumeration via simulated subprocess output."""
    with patch("shutil.which", return_value="adb"):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="List of devices attached\n988a1b414d3345474d\tdevice product:m3_pro model:SM_G998B device:p3s\nRF8R30V6XYZ\tdevice\n",
            )
            extractor = AdbExtractor()
            devices = extractor.list_devices()
            assert len(devices) == 2
            assert devices[0].device_id == "988a1b414d3345474d"
            assert devices[0].state == "device"
            assert devices[1].device_id == "RF8R30V6XYZ"


def test_adb_extractor_scan_and_extract():
    """Verify ADB file extraction, dual hashing, and ledger recording."""
    with tempfile.TemporaryDirectory() as tmpdir:
        ledger_path = os.path.join(tmpdir, "chain_of_custody.jsonl")
        ledger = ChainOfCustodyLedger(ledger_path)

        extractor = AdbExtractor(mock_mode=True)
        res = extractor.extract_logs(
            device_id="SIM_DEVICE_001",
            output_directory=tmpdir,
            custody_ledger=ledger,
            operator_id="INV-UNITTEST-01",
        )

        assert res.success is True
        assert len(res.extracted_files) >= 1
        first_file = res.extracted_files[0]
        assert len(first_file.sha256) == 64
        assert len(first_file.blake3) == 64
        assert os.path.exists(first_file.local_path)

        # Verify chain of custody ledger
        assert os.path.exists(ledger_path)
        ledger_reader = ChainOfCustodyLedger(ledger_path)
        is_valid, broken_idx = ledger_reader.verify_chain()
        assert is_valid is True
        assert broken_idx is None
        assert any(e.action == "ACQUIRE_ADB" for e in ledger_reader._entries)



def test_gui_api_acquisition_endpoints():
    """Verify GUI API acquisition methods."""
    api = gui_api.DroneForensicsAPI()

    # Test serial ports endpoint
    ports = api.list_serial_ports()
    assert isinstance(ports, list)
    assert len(ports) >= 1

    # Test MAVLink logs endpoint
    logs = api.list_mavlink_logs(connection_uri="COM3", baud=115200)
    assert isinstance(logs, list)
    assert len(logs) >= 2

    # Test ADB devices endpoint
    devices = api.list_adb_devices()
    assert isinstance(devices, list)
    assert len(devices) >= 1

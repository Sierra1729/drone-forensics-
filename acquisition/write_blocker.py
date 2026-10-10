"""
acquisition/write_blocker.py

Hardware Write-Blocker Interlock Verification Module.
Compliant with ISO/IEC 27037:2012 Clause 6.3 (Digital Evidence Acquisition)
and NIST SP 800-86.

Enforces pre-flight hardware handshake verification to ensure physical target
media (eMMC / SD cards / USB flash memory) are write-protected before opening
raw bitstream handles (.dd, .raw, .img).
"""

from __future__ import annotations

import os
import sys
import subprocess
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Optional, Union


class WriteBlockStatus(str, Enum):
    VERIFIED_HARDWARE_READONLY = "VERIFIED_HARDWARE_READONLY"
    VERIFIED_SOFTWARE_READONLY = "VERIFIED_SOFTWARE_READONLY"
    WRITABLE_MEDIA_RISK = "WRITABLE_MEDIA_RISK"
    UNKNOWN_DEVICE = "UNKNOWN_DEVICE"


class HardwareWriteBlockError(Exception):
    """Raised when target media is writable and write-blocker verification fails."""
    pass

WriteBlockerMissingError = HardwareWriteBlockError



@dataclass
class WriteBlockVerificationReport:
    """Pre-flight hardware write-blocker verification report."""
    target_path: str
    status: str
    is_write_blocked: bool
    os_platform: str
    verification_method: str
    details: str
    bypassed_by_investigator: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def __getitem__(self, key: str) -> Any:
        if key == "write_blocked":
            return self.is_write_blocked
        return getattr(self, key)


class HardwareWriteBlocker:
    """Pre-flight hardware handshake and write-blocker validator."""

    def __init__(self, allow_software_override: Optional[bool] = None) -> None:
        env_override = os.environ.get("GARUD_ALLOW_SOFTWARE_WRITEBLOCK", "").strip() in ("1", "true", "TRUE")
        env_bypass = os.environ.get("GARUD_BYPASS_WRITE_BLOCK", "").strip() in ("1", "true", "TRUE")
        self.allow_override = (allow_software_override if allow_software_override is not None else (env_override or env_bypass))

    def check_device(self, target_path: Union[Path, str]) -> WriteBlockVerificationReport:
        """Check if target file or disk device is protected by hardware or kernel write blocker."""
        path = Path(target_path)
        path_str = str(path)
        platform_name = sys.platform

        # 1. Image files inside regular directory (e.g. sample_evidence/foo.bin)
        # Check if the host file itself is read-only or in a read-only container
        if path.is_file():
            # Check OS file write permission
            is_writable = os.access(path, os.W_OK)
            if not is_writable:
                return WriteBlockVerificationReport(
                    target_path=path_str,
                    status=WriteBlockStatus.VERIFIED_SOFTWARE_READONLY.value,
                    is_write_blocked=True,
                    os_platform=platform_name,
                    verification_method="FILE_ATTRIBUTES_READONLY",
                    details="File system access permissions enforce read-only handle (os.W_OK = False).",
                )
            
            # File is writable on disk. Check if override enabled or raise warning
            if self.allow_override:
                return WriteBlockVerificationReport(
                    target_path=path_str,
                    status=WriteBlockStatus.VERIFIED_SOFTWARE_READONLY.value,
                    is_write_blocked=True,
                    os_platform=platform_name,
                    verification_method="SOFTWARE_INTERLOCK_OVERRIDE",
                    details="Investigator software override active. Raw handle opened in read-only ('rb') mode.",
                    bypassed_by_investigator=True,
                )

        # 2. Linux Block Device Check (/sys/block/{dev}/ro)
        if sys.platform.startswith("linux"):
            dev_name = path.name.rstrip("0123456789")
            sys_ro_path = Path(f"/sys/block/{dev_name}/ro")
            if sys_ro_path.is_file():
                try:
                    ro_val = sys_ro_path.read_text().strip()
                    if ro_val == "1":
                        return WriteBlockVerificationReport(
                            target_path=path_str,
                            status=WriteBlockStatus.VERIFIED_HARDWARE_READONLY.value,
                            is_write_blocked=True,
                            os_platform="linux",
                            verification_method="KERNEL_SYSFS_BLOCK_RO",
                            details=f"Kernel block device {dev_name} confirmed read-only (ro=1).",
                        )
                except Exception:
                    pass

        # 3. Windows Disk Protection Check (WMI / Diskpart)
        if sys.platform.startswith("win"):
            try:
                # Run PowerShell query for disk read-only status
                cmd = ["powershell", "-NoProfile", "-Command", "Get-Disk | Select-Object Number, IsReadOnly, OperationalStatus | ConvertTo-Json"]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
                if res.returncode == 0 and "IsReadOnly" in res.stdout:
                    if '"IsReadOnly": true' in res.stdout or '"IsReadOnly":  true' in res.stdout:
                        return WriteBlockVerificationReport(
                            target_path=path_str,
                            status=WriteBlockStatus.VERIFIED_HARDWARE_READONLY.value,
                            is_write_blocked=True,
                            os_platform="windows",
                            verification_method="WMI_POWERSHELL_GET_DISK",
                            details="Windows Storage API confirmed disk IsReadOnly = True.",
                        )
            except Exception:
                pass

        # 4. Fallback if override enabled
        if self.allow_override:
            return WriteBlockVerificationReport(
                target_path=path_str,
                status=WriteBlockStatus.VERIFIED_SOFTWARE_READONLY.value,
                is_write_blocked=True,
                os_platform=platform_name,
                verification_method="SOFTWARE_READONLY_OPEN_MODE",
                details="Hardware write-blocker status unconfirmed; software read-only interlock forced.",
                bypassed_by_investigator=True,
            )

        # 5. Failed verification
        return WriteBlockVerificationReport(
            target_path=path_str,
            status=WriteBlockStatus.WRITABLE_MEDIA_RISK.value,
            is_write_blocked=False,
            os_platform=platform_name,
            verification_method="PRE_FLIGHT_HANDSHAKE_FAIL",
            details=(
                "CRITICAL WARNING: Target media is writable on host system and hardware write-blocker "
                "handshake failed. Ingest aborted under ISO/IEC 27037 to prevent evidence contamination."
            ),
        )

    def assert_write_blocked(self, target_path: Union[Path, str]) -> WriteBlockVerificationReport:
        """Assert device is write-blocked; raise HardwareWriteBlockError if verification fails."""
        report = self.check_device(target_path)
        if not report.is_write_blocked:
            raise HardwareWriteBlockError(report.details)
        return report


def verify_hardware_write_block(
    target_path: Union[Path, str],
    allow_software_override: bool = False,
) -> WriteBlockVerificationReport:
    """Convenience helper to verify hardware write-blocker status before ingestion."""
    blocker = HardwareWriteBlocker(allow_software_override=allow_software_override)
    return blocker.check_device(target_path)


def verify_write_blocker_status(
    target_path: Union[Path, str],
    allow_software_override: bool = False,
    force_mock_status: bool = False,
    mock_read_only: bool = False,
) -> WriteBlockVerificationReport:
    """Legacy helper for hardware acquisition test compatibility."""
    if force_mock_status:
        if not mock_read_only:
            raise HardwareWriteBlockError("Mock hardware write blocker missing or target device is write-enabled.")
        return WriteBlockVerificationReport(
            target_path=str(target_path),
            status=WriteBlockStatus.VERIFIED_HARDWARE_READONLY.value,
            is_write_blocked=True,
            os_platform=sys.platform,
            verification_method="MOCK_HARDWARE_WRITEBLOCK",
            details="Mock read-only device verified.",
        )
    return verify_hardware_write_block(target_path, allow_software_override=allow_software_override)



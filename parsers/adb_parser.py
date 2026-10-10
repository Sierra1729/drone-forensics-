"""
parsers/adb_parser.py

Android ADB Mobile Companion App & Smart Controller Artifact Parser.
Compliant with ISO/IEC 27037:2012 (Preservation of Digital Evidence) and
Section 63 Bharatiya Sakshya Adhiniyam (BSA) 2023.

Parses forensic extractions acquired from Android-based UAV Ground Control Stations (GCS):
- Android Backup Archives (.ab)
- Android Logcat System & Drone Telemetry Logs (.log, .txt)
- Android Dumpsys System & Service State Dumps (.dump, .txt)
- Android App Shared Preferences and Configuration XMLs
"""

from __future__ import annotations

import io
import re
import tarfile
import zlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from normalize.schema import NormalizedEvent, EventType
from parsers.base import BaseParser, register_parser


SIG_ANDROID_BACKUP = b"ANDROID BACKUP"
LOGCAT_LINE_RE = re.compile(
    r"^(?:\[\s*)?(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+(?:\d+:\s*\d+|\d+)\s+([VDIWEF])[\s/]([A-Za-z0-9_.$]+)(?:\(\s*\d+\))?\]?:\s*(.*)$"
)
GPS_RE = re.compile(r"(?:lat(?:itude)?[:\s=]+)([-+]?\d+\.\d+)[,\s]+(?:lon(?:gitude)?[:\s=]+)([-+]?\d+\.\d+)", re.IGNORECASE)
ALT_RE = re.compile(r"(?:alt(?:itude)?[:\s=]+)([-+]?\d+(?:\.\d+)?)(?:\s*m)?", re.IGNORECASE)
SATS_RE = re.compile(r"(?:sat(?:ellite)?s?[:\s=]+)(\d+)", re.IGNORECASE)
BATTERY_RE = re.compile(r"(?:battery[:\s=]+|battery\s+level\s+at\s+)(\d+)(?:\s*%)?", re.IGNORECASE)
VOLT_RE = re.compile(r"(?:volt(?:age)?[:\s=]+)(\d+(?:\.\d+)?)(?:\s*V)?", re.IGNORECASE)


@register_parser
class AndroidADBExtractorParser(BaseParser):
    """Forensic parser for Android ADB extractions, backups, and Smart Controller logs."""

    supported_extensions = [".ab", ".logcat", ".txt", ".log", ".dump"]

    @property
    def parser_name(self) -> str:
        return "AndroidADBExtractorParser"

    @property
    def supported_platforms(self) -> list[str]:
        return ["android", "adb", "smart_controller", "gcs"]

    @property
    def parser_version(self) -> str:
        return "1.0.0"

    def can_parse(self, file_path: Path) -> bool:
        path = Path(file_path)
        if not path.is_file():
            return False

        file_size = path.stat().st_size
        if file_size == 0:
            return False

        try:
            with open(path, "rb") as f:
                header = f.read(512)
        except Exception:
            return False

        if header.startswith(SIG_ANDROID_BACKUP):
            return True

        try:
            sample_text = header.decode("utf-8", errors="ignore")
        except Exception:
            return False

        if "--------- beginning of" in sample_text:
            return True
        if any(tag in sample_text for tag in ["DJIFlightController", "DJIBattery", "DJICamera", "AutelFlightService", "DataPilot"]):
            return True
        if any(LOGCAT_LINE_RE.match(line.strip()) for line in sample_text.splitlines()[:10] if line.strip()):
            return True
        if "DUMP OF SERVICE" in sample_text or "== dumpstate:" in sample_text or "Build fingerprint:" in sample_text:
            return True

        fname = path.name.lower()
        if "adb_" in fname or "logcat" in fname or "dumpsys" in fname:
            if any(k in sample_text.lower() for k in ["android", "dji", "autel", "controller", "battery", "gps", "drone"]):
                return True

        return False

    def parse_records(
        self,
        file_path: Path,
        file_sha256: str,
    ) -> List[NormalizedEvent]:
        path = Path(file_path)
        header_sample = b""
        try:
            with open(path, "rb") as f:
                header_sample = f.read(512)
        except Exception:
            pass

        if header_sample.startswith(SIG_ANDROID_BACKUP):
            return self._parse_android_backup(path, file_sha256)

        sample_str = header_sample.decode("utf-8", errors="ignore")
        if "DUMP OF SERVICE" in sample_str or "== dumpstate:" in sample_str or "Build fingerprint:" in sample_str:
            return self._parse_dumpsys(path, file_sha256)

        return self._parse_logcat(path, file_sha256)

    def _parse_android_backup(self, path: Path, file_sha256: str) -> List[NormalizedEvent]:
        events: List[NormalizedEvent] = []
        now_utc = datetime.now(timezone.utc)

        backup_version = "Unknown"
        is_compressed = False
        encryption_type = "none"
        tar_files: List[str] = []

        try:
            with open(path, "rb") as f:
                lines = [f.readline().strip() for _ in range(4)]
                if len(lines) >= 1 and lines[0] == SIG_ANDROID_BACKUP:
                    backup_version = lines[1].decode("ascii", errors="ignore") if len(lines) > 1 else "1"
                    is_compressed = (lines[2] == b"1") if len(lines) > 2 else False
                    encryption_type = lines[3].decode("ascii", errors="ignore") if len(lines) > 3 else "none"

                if encryption_type.lower() == "none":
                    stream = f
                    if is_compressed:
                        decompressor = zlib.decompressobj()
                        rest_data = f.read()
                        try:
                            decompressed = decompressor.decompress(rest_data)
                            stream = io.BytesIO(decompressed)
                        except Exception:
                            stream = None

                    if stream:
                        try:
                            with tarfile.open(fileobj=stream, mode="r:*") as tar:
                                tar_files = tar.getnames()
                        except Exception:
                            pass
        except Exception:
            pass

        events.append(
            NormalizedEvent(
                timestamp_utc=now_utc,
                source_platform="mobile_app_android",
                event_type=EventType.MOBILE_APP_ARTIFACT.value,
                source_file=path.name,
                source_file_sha256=file_sha256,
                payload={
                    "format": "Android ADB Backup Archive",
                    "backup_version": backup_version,
                    "is_compressed": is_compressed,
                    "encryption_type": encryption_type,
                    "contained_files_count": len(tar_files),
                    "contained_files_sample": tar_files[:20],
                },
            )
        )

        for tf in tar_files:
            lower_tf = tf.lower()
            if any(k in lower_tf for k in ["flight", "dji", "autel", "waypoint", "gcs"]):
                events.append(
                    NormalizedEvent(
                        timestamp_utc=now_utc,
                        source_platform="mobile_app_android",
                        event_type=EventType.MOBILE_APP_ARTIFACT.value,
                        source_file=path.name,
                        source_file_sha256=file_sha256,
                        payload={
                            "subfile_path": tf,
                            "artifact_type": "GCS Drone App Artifact inside ADB Backup",
                        },
                    )
                )

        return events

    def _parse_logcat(self, path: Path, file_sha256: str) -> List[NormalizedEvent]:
        events: List[NormalizedEvent] = []
        year = datetime.now(timezone.utc).year

        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception:
            return events

        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue

            m = LOGCAT_LINE_RE.match(line)
            ts_utc = datetime.now(timezone.utc)
            tag = "AndroidSystem"
            level = "I"
            msg = line

            if m:
                ts_str, level, tag, msg = m.groups()
                try:
                    parts = ts_str.split()
                    month_day = parts[0]
                    hms = parts[1]
                    month, day = map(int, month_day.split("-"))
                    time_parts = hms.split(":")
                    hour = int(time_parts[0])
                    minute = int(time_parts[1])
                    sec = float(time_parts[2])
                    second = int(sec)
                    microsec = int((sec - second) * 1_000_000)
                    ts_utc = datetime(year, month, day, hour, minute, second, microsec, tzinfo=timezone.utc)
                except Exception:
                    pass

            # 1. GPS Coordinates Extraction
            gps_m = GPS_RE.search(msg)
            if gps_m:
                lat = float(gps_m.group(1))
                lon = float(gps_m.group(2))
                alt = 0.0
                alt_m = ALT_RE.search(msg)
                if alt_m:
                    alt = float(alt_m.group(1))
                sats = 0
                sats_m = SATS_RE.search(msg)
                if sats_m:
                    sats = int(sats_m.group(1))

                events.append(
                    NormalizedEvent(
                        timestamp_utc=ts_utc,
                        source_platform="smart_controller",
                        event_type=EventType.GPS_FIX.value,
                        source_file=path.name,
                        source_file_sha256=file_sha256,
                        latitude=lat,
                        longitude=lon,
                        altitude_m=alt,
                        satellites_visible=sats,
                        payload={
                            "logcat_tag": tag,
                            "logcat_level": level,
                            "line_number": line_num,
                            "raw_message": msg,
                        },
                    )
                )

            # 2. Home Set Point
            if any(k in msg.lower() for k in ["home point recorded", "home_point", "set home"]):
                home_gps = GPS_RE.search(msg)
                if not home_gps:
                    coord_m = re.search(r"([-+]?\d{1,2}\.\d+)[,\s]+([-+]?\d{1,3}\.\d+)", msg)
                    if coord_m:
                        home_gps = coord_m
                if home_gps:
                    events.append(
                        NormalizedEvent(
                            timestamp_utc=ts_utc,
                            source_platform="smart_controller",
                            event_type=EventType.APP_COMMAND.value,
                            source_file=path.name,
                            source_file_sha256=file_sha256,
                            latitude=float(home_gps.group(1)),
                            longitude=float(home_gps.group(2)),
                            payload={"action": "SET_HOME_POINT", "logcat_tag": tag, "line_number": line_num, "message": msg},
                        )
                    )

            # 3. Battery Telemetry
            bat_m = BATTERY_RE.search(msg)
            if bat_m:
                bat_pct = float(bat_m.group(1))
                volt = None
                volt_m = VOLT_RE.search(msg)
                if volt_m:
                    volt = float(volt_m.group(1))

                events.append(
                    NormalizedEvent(
                        timestamp_utc=ts_utc,
                        source_platform="smart_controller",
                        event_type=EventType.BATTERY_STATE.value,
                        source_file=path.name,
                        source_file_sha256=file_sha256,
                        battery_remaining_pct=bat_pct,
                        battery_voltage_v=volt,
                        payload={"logcat_tag": tag, "line_number": line_num, "message": msg},
                    )
                )

            # 4. Flight State Change
            if any(k in msg.lower() for k in ["takeoff", "landing", "motor arm", "motor disarm", "rth started", "failsafe"]):
                events.append(
                    NormalizedEvent(
                        timestamp_utc=ts_utc,
                        source_platform="smart_controller",
                        event_type=EventType.MODE_CHANGE.value,
                        source_file=path.name,
                        source_file_sha256=file_sha256,
                        flight_mode="RTH" if "rth" in msg.lower() else "AUTO",
                        payload={"logcat_tag": tag, "line_number": line_num, "state_event": msg},
                    )
                )

            # 5. Warnings and Errors
            if level in ("W", "E", "F") and any(k in msg.lower() for k in ["drone", "flight", "battery", "gps", "signal", "motor", "fail"]):
                events.append(
                    NormalizedEvent(
                        timestamp_utc=ts_utc,
                        source_platform="smart_controller",
                        event_type=EventType.FORENSIC_ANOMALY.value,
                        source_file=path.name,
                        source_file_sha256=file_sha256,
                        payload={
                            "anomaly_description": f"[{tag}] {msg}",
                            "anomaly_severity": "CRITICAL" if level in ("E", "F") else "WARNING",
                            "logcat_tag": tag,
                            "line_number": line_num,
                        },
                    )
                )

        if not events:
            events.append(
                NormalizedEvent(
                    timestamp_utc=datetime.now(timezone.utc),
                    source_platform="smart_controller",
                    event_type=EventType.SYSTEM_STATUS.value,
                    source_file=path.name,
                    source_file_sha256=file_sha256,
                    payload={"lines_parsed": len(lines), "type": "Android Logcat"},
                )
            )

        return events

    def _parse_dumpsys(self, path: Path, file_sha256: str) -> List[NormalizedEvent]:
        events: List[NormalizedEvent] = []
        now_utc = datetime.now(timezone.utc)

        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return events

        serial = None
        model = None
        build = None

        m_serial = re.search(r"(?:ro\.serialno|Serial Number|device_serial)\s*[:=]\s*([A-Za-z0-9_-]+)", text, re.IGNORECASE)
        if m_serial:
            serial = m_serial.group(1)

        m_model = re.search(r"(?:ro\.product\.model|Model|device_model)\s*[:=]\s*([^\r\n]+)", text, re.IGNORECASE)
        if m_model:
            model = m_model.group(1).strip()

        m_build = re.search(r"(?:ro\.build\.display\.id|Build fingerprint)\s*[:=]\s*([^\r\n]+)", text, re.IGNORECASE)
        if m_build:
            build = m_build.group(1).strip()

        drone_apps = []
        for app in ["dji.go.v4", "dji.go.v5", "com.dji.industry.pilot", "dji.pilot.pad", "com.autel.explorer", "org.droidplanner.android", "com.yuneec.datapilot"]:
            if app in text:
                drone_apps.append(app)

        events.append(
            NormalizedEvent(
                timestamp_utc=now_utc,
                source_platform="smart_controller",
                event_type=EventType.SYSTEM_STATUS.value,
                source_file=path.name,
                source_file_sha256=file_sha256,
                payload={
                    "hardware_serial": serial,
                    "hardware_model": model,
                    "os_build": build,
                    "installed_drone_apps": drone_apps,
                    "artifact_type": "Android ADB Dumpsys Hardware Extraction",
                },
            )
        )

        return events

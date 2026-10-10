"""
analytics/attribution_engine.py

Universal Polymorphic Correlation Framework & Telemetry Continuity Engine.
Compliant with ISO/IEC 27037:2012 (Digital Evidence Handling) and NIST SP 800-86.

Ingests N arbitrary evidence artifacts across onboard blackbox logs, GCS mobile logs,
configuration registers, raw disk images, and payload media to autonomously evaluate:
1. Identity Attribution: Do all uploaded evidence files originate from the exact same physical drone and flight mission?
2. Telemetry Continuity: Is telemetry continuous across streams, or are there dropouts, wiped sectors, packet gaps, or desynchronized early terminations?
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional, Union

from normalize.schema import NormalizedEvent, EventType
from parsers.base import get_parser_for_file
from parsers.param_parser import ParamParser
from parsers.media_extractor import DroneMediaExtractorParser
from parsers.disk_image import PhysicalDiskImageParser
from custody.ledger import hash_file

EARTH_RADIUS_METERS = 6371000.0


def haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate the great-circle distance between two points on Earth in meters."""
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    a = math.sin(delta_phi / 2.0) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2.0) ** 2
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    return EARTH_RADIUS_METERS * c


class ArtifactCategory(str, Enum):
    ONBOARD_BLACKBOX = "onboard_blackbox"
    GCS_TELEMETRY = "gcs_telemetry"
    CONFIG = "config"
    PAYLOAD_MEDIA = "payload_media"
    RAW_IMAGE = "raw_image"
    UNKNOWN = "unknown"


@dataclass
class ForensicArtifact:
    """Canonical intermediate data structure extracted from any parsed evidence file."""

    file_path: Path
    file_type: str  # "onboard_blackbox", "gcs_telemetry", "config", "payload_media", "raw_image"
    platform: str   # "px4", "ardupilot", "dji", "autel", "yuneec", "betaflight", "parrot", "generic"
    hardware_uid: Optional[str] = None        # Board serial, MCU UID, or GCS-registered drone serial
    session_start_utc: Optional[datetime] = None
    session_end_utc: Optional[datetime] = None
    home_coordinates: Optional[tuple[float, float, float]] = None  # (lat, lon, alt)
    trajectory_points: list[dict[str, Any]] = field(default_factory=list)  # Standardized [(ts, lat, lon, alt_msl, speed)]
    parameter_map: dict[str, Any] = field(default_factory=dict)       # Extracted parameters / fail-safe settings
    raw_event_count: int = 0
    file_sha256: str = ""
    parser_used: str = ""
    is_corrupted: bool = False
    corruption_offset: Optional[int] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_path": str(self.file_path),
            "file_type": self.file_type,
            "platform": self.platform,
            "hardware_uid": self.hardware_uid,
            "session_start_utc": self.session_start_utc.isoformat() if self.session_start_utc else None,
            "session_end_utc": self.session_end_utc.isoformat() if self.session_end_utc else None,
            "home_coordinates": self.home_coordinates,
            "trajectory_points_count": len(self.trajectory_points),
            "parameter_count": len(self.parameter_map),
            "raw_event_count": self.raw_event_count,
            "file_sha256": self.file_sha256,
            "parser_used": self.parser_used,
            "is_corrupted": self.is_corrupted,
            "corruption_offset": self.corruption_offset,
        }


@dataclass
class IdentityAttributionReport:
    """Comprehensive Identity Attribution report evaluating single-drone provenance across N artifacts."""

    match_verdict: str  # "MATCH", "MISMATCH", "INCONCLUSIVE", "PARTIAL_MATCH"
    overall_confidence_score: float  # [0.0, 100.0]
    hardware_uid_match: dict[str, Any]
    spatio_temporal_match: dict[str, Any]
    parameter_signature_match: dict[str, Any]
    conflicting_artifacts: list[str] = field(default_factory=list)
    attribution_score_breakdown: dict[str, float] = field(default_factory=dict)
    summary_findings: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class TelemetryGap:
    """One identified telemetry gap or dropout in an evidence artifact."""

    artifact_file: str
    gap_type: str  # "PACKET_DROPOUT", "POWER_DISCONNECT", "STORAGE_CORRUPTION", "WIPED_SECTOR", "STREAM_DESYNC"
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    gap_duration_s: float = 0.0
    severity: str = "MEDIUM"  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if self.start_time:
            d["start_time"] = self.start_time.isoformat()
        if self.end_time:
            d["end_time"] = self.end_time.isoformat()
        return d


@dataclass
class TelemetryContinuityReport:
    """Comprehensive Telemetry Continuity report evaluating dropouts and gaps across N artifacts."""

    overall_continuity_score: float  # [0.0, 100.0]
    is_uninterrupted: bool
    detected_gaps: list[TelemetryGap] = field(default_factory=list)
    early_termination_detected: bool = False
    wiped_sectors_detected: bool = False
    desynchronized_streams: list[dict[str, Any]] = field(default_factory=list)
    coverage_timeline: dict[str, Any] = field(default_factory=dict)
    summary_findings: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["detected_gaps"] = [g.to_dict() for g in self.detected_gaps]
        return d


@dataclass
class ComprehensiveAttributionResult:
    """Unified master result combining Identity Attribution and Telemetry Continuity."""

    artifacts: list[ForensicArtifact]
    identity_attribution: IdentityAttributionReport
    telemetry_continuity: TelemetryContinuityReport
    executive_summary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifacts": [a.to_dict() for a in self.artifacts],
            "identity_attribution": self.identity_attribution.to_dict(),
            "telemetry_continuity": self.telemetry_continuity.to_dict(),
            "executive_summary": self.executive_summary,
        }


class UniversalAttributionEngine:
    """Universal Polymorphic Correlation Framework for UAV digital forensics."""

    def __init__(self) -> None:
        pass

    def extract_artifact(self, file_path: Union[Path, str]) -> ForensicArtifact:
        """Parse any arbitrary evidence file and construct a ForensicArtifact abstraction."""
        path = Path(file_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"Evidence file not found: {path}")

        sha256_hex, _ = hash_file(path)
        ext = path.suffix.lower()

        # Classify artifact category and default platform hint
        file_type = ArtifactCategory.UNKNOWN.value
        platform = "generic"

        if ext in (".param", ".params", ".waypoints", ".plan", ".xml"):
            file_type = ArtifactCategory.CONFIG.value
            platform = "ardupilot" if ext in (".param", ".params") else "generic"
        elif ext in (".jpg", ".jpeg", ".mp4", ".srt"):
            file_type = ArtifactCategory.PAYLOAD_MEDIA.value
            platform = "dji"
        elif ext in (".dd", ".raw", ".img", ".e01"):
            file_type = ArtifactCategory.RAW_IMAGE.value
            platform = "generic"
        elif ext in (".ulg", ".bin", ".dat", ".bbl", ".bfl"):
            file_type = ArtifactCategory.ONBOARD_BLACKBOX.value
            if ext == ".ulg":
                platform = "px4"
            elif ext == ".bin":
                platform = "ardupilot"
            elif ext in (".dat", ".DAT"):
                platform = "dji"
            elif ext in (".bbl", ".bfl"):
                platform = "betaflight"
        elif ext in (".csv", ".txt", ".tlog", ".json", ".pud"):
            file_type = ArtifactCategory.GCS_TELEMETRY.value
            if ext in (".json", ".pud"):
                platform = "parrot"
            elif ext == ".tlog":
                platform = "mavlink"
            elif ext in (".txt", ".csv"):
                platform = "dji"

        # Obtain parser
        parser = get_parser_for_file(path)
        events: list[NormalizedEvent] = []
        is_corrupted = False
        corruption_offset = None

        if parser:
            try:
                events = parser.parse(path)
                is_corrupted = getattr(parser, "is_corrupted", False)
                corruption_offset = getattr(parser, "corruption_offset", None)
            except Exception:
                events = []
                is_corrupted = True

        # Extract normalized attributes
        hardware_uid: Optional[str] = None
        session_start_utc: Optional[datetime] = None
        session_end_utc: Optional[datetime] = None
        home_coordinates: Optional[tuple[float, float, float]] = None
        trajectory_points: list[dict[str, Any]] = []
        parameter_map: dict[str, Any] = {}

        if events:
            # Detect platform override from parsed events if available
            if events[0].source_platform:
                platform = events[0].source_platform

            # Find session bounds
            timestamps = [e.timestamp_utc for e in events if e.timestamp_utc]
            if timestamps:
                session_start_utc = min(timestamps)
                session_end_utc = max(timestamps)

            for e in events:
                # Hardware UID extraction from payloads
                if not hardware_uid:
                    uid = (
                        e.payload.get("hardware_uid")
                        or e.payload.get("serial_number")
                        or e.payload.get("SYS_UID")
                        or e.payload.get("board_serial")
                        or e.payload.get("drone_serial")
                        or e.payload.get("device_id")
                        or e.payload.get("mc_serial")
                    )
                    if uid:
                        hardware_uid = str(uid).strip()

                # Parameter map extraction
                if e.event_type == EventType.CONFIG_PARAM.value or "param_name" in e.payload or "parameter" in e.payload:
                    pname = e.payload.get("param_name") or e.payload.get("parameter") or e.payload.get("key")
                    pval = e.payload.get("param_value") or e.payload.get("value")
                    if pname is not None and pval is not None:
                        parameter_map[str(pname)] = pval

                # Trajectory point extraction
                if e.latitude is not None and e.longitude is not None:
                    point_dict = {
                        "timestamp_utc": e.timestamp_utc,
                        "latitude": e.latitude,
                        "longitude": e.longitude,
                        "altitude_m": e.altitude_m if e.altitude_m is not None else 0.0,
                        "ground_speed_mps": e.ground_speed_mps if e.ground_speed_mps is not None else 0.0,
                    }
                    trajectory_points.append(point_dict)

                    if home_coordinates is None:
                        home_coordinates = (e.latitude, e.longitude, e.altitude_m if e.altitude_m is not None else 0.0)

        # Fallback parameter extraction for standalone .param / .params files
        if not parameter_map and ext in (".param", ".params"):
            param_parser = ParamParser()
            if param_parser.can_parse(path):
                p_events = param_parser.parse(path)
                for pe in p_events:
                    pname = pe.payload.get("param_name")
                    pval = pe.payload.get("param_value")
                    if pname and pval is not None:
                        parameter_map[pname] = pval

        # Fallback UID extraction from parameter map if present
        if not hardware_uid and parameter_map:
            for k in ("SYS_UID", "BOARD_SERIAL", "FC_SERIAL", "DRONE_SN", "SERIAL_NUM"):
                if k in parameter_map:
                    hardware_uid = str(parameter_map[k]).strip()
                    break

        return ForensicArtifact(
            file_path=path,
            file_type=file_type,
            platform=platform,
            hardware_uid=hardware_uid,
            session_start_utc=session_start_utc,
            session_end_utc=session_end_utc,
            home_coordinates=home_coordinates,
            trajectory_points=trajectory_points,
            parameter_map=parameter_map,
            raw_event_count=len(events),
            file_sha256=sha256_hex,
            parser_used=parser.parser_name if parser else "unregistered_fallback",
            is_corrupted=is_corrupted,
            corruption_offset=corruption_offset,
        )

    def analyze_identity_attribution(self, artifacts: list[ForensicArtifact]) -> IdentityAttributionReport:
        """Evaluate single-drone hardware provenance and mission coincidence across N artifacts."""
        if not artifacts:
            return IdentityAttributionReport(
                match_verdict="INCONCLUSIVE",
                overall_confidence_score=0.0,
                hardware_uid_match={"status": "NO_ARTIFACTS", "confidence": 0.0, "details": "No artifacts provided."},
                spatio_temporal_match={"status": "NO_ARTIFACTS", "confidence": 0.0, "details": "No artifacts provided."},
                parameter_signature_match={"status": "NO_ARTIFACTS", "confidence": 0.0, "details": "No artifacts provided."},
                summary_findings="No artifacts submitted for identity attribution.",
            )

        if len(artifacts) == 1:
            a = artifacts[0]
            uid_str = a.hardware_uid if a.hardware_uid else "UNSPECIFIED"
            return IdentityAttributionReport(
                match_verdict="MATCH",
                overall_confidence_score=100.0,
                hardware_uid_match={"status": "SINGLE_ARTIFACT", "matched_uid": uid_str, "details": f"Single evidence artifact parsed ({a.file_path.name})."},
                spatio_temporal_match={"status": "SINGLE_ARTIFACT", "details": "Single artifact timeline baseline established."},
                parameter_signature_match={"status": "SINGLE_ARTIFACT", "details": f"Extracted {len(a.parameter_map)} configuration parameters."},
                summary_findings=f"Single artifact '{a.file_path.name}' parsed successfully. Hardware UID: {uid_str}.",
            )

        # 1. Hardware UID Matching
        uids_found: dict[str, str] = {}
        for a in artifacts:
            if a.hardware_uid:
                uids_found[a.file_path.name] = a.hardware_uid.strip().lower()

        hardware_uid_match: dict[str, Any] = {}
        conflicting_artifacts: list[str] = []
        uid_score = 0.0

        if not uids_found:
            hardware_uid_match = {
                "status": "NOT_AVAILABLE",
                "confidence": 0.0,
                "details": "No hardware serial numbers or board UIDs embedded across artifacts.",
            }
            uid_score = 50.0  # Neutral
        else:
            unique_uids = set(uids_found.values())
            if len(unique_uids) == 1:
                matched_uid = list(uids_found.values())[0]
                hardware_uid_match = {
                    "status": "MATCH",
                    "confidence": 1.0,
                    "matched_uid": matched_uid,
                    "details": f"Identical Hardware Serial / Board UID ({matched_uid}) verified across {len(uids_found)} artifacts.",
                }
                uid_score = 100.0
            else:
                conflicting_artifacts = list(uids_found.keys())
                hardware_uid_match = {
                    "status": "MISMATCH",
                    "confidence": -1.0,
                    "unique_uids": list(unique_uids),
                    "details": f"Conflicting Hardware Serials detected across artifacts: {uids_found}",
                }
                uid_score = 0.0

        # 2. Spatio-Temporal Coincidence Matching
        starts = [a.session_start_utc for a in artifacts if a.session_start_utc]
        ends = [a.session_end_utc for a in artifacts if a.session_end_utc]
        homes = [a.home_coordinates for a in artifacts if a.home_coordinates]

        spatio_temporal_match: dict[str, Any] = {}
        st_score = 0.0

        max_time_skew_s = 0.0
        max_spatial_delta_m = 0.0

        if starts and ends:
            min_start, max_start = min(starts), max(starts)
            max_time_skew_s = abs((max_start - min_start).total_seconds())

            # Check overlap between overall session windows
            overall_start = min(starts)
            overall_end = max(ends)
            time_span_s = abs((overall_end - overall_start).total_seconds())

            if max_time_skew_s <= 600.0:  # Within 10 minutes session start skew
                st_score += 50.0
            elif max_time_skew_s <= 3600.0:  # Within 1 hour
                st_score += 25.0

        if homes and len(homes) >= 2:
            distances = []
            for i in range(len(homes)):
                for j in range(i + 1, len(homes)):
                    d = haversine_distance(homes[i][0], homes[i][1], homes[j][0], homes[j][1])
                    distances.append(d)
            max_spatial_delta_m = max(distances)

            if max_spatial_delta_m <= 100.0:  # Within 100m home location radius
                st_score += 50.0
            elif max_spatial_delta_m <= 1000.0:  # Within 1km
                st_score += 25.0
        elif homes and len(homes) == 1:
            st_score += 50.0  # Baseline

        if not starts and not homes:
            spatio_temporal_match = {
                "status": "NOT_AVAILABLE",
                "details": "No geodetic trajectory or UTC timestamp boundaries available for spatio-temporal correlation.",
            }
            st_score = 50.0
        else:
            status_str = "MATCH" if st_score >= 80.0 else ("PARTIAL_MATCH" if st_score >= 40.0 else "MISMATCH")
            spatio_temporal_match = {
                "status": status_str,
                "max_time_skew_seconds": round(max_time_skew_s, 2),
                "max_spatial_delta_meters": round(max_spatial_delta_m, 2),
                "details": f"Spatio-temporal alignment score: {st_score:.1f}/100 (Time skew: {max_time_skew_s:.1f}s, Spatial delta: {max_spatial_delta_m:.1f}m).",
            }

        # 3. Parameter Signature Matching
        param_artifacts = [a for a in artifacts if a.parameter_map]
        param_match: dict[str, Any] = {}
        param_score = 50.0

        if len(param_artifacts) >= 2:
            all_keys = set()
            for pa in param_artifacts:
                all_keys.update(pa.parameter_map.keys())

            common_keys = set(param_artifacts[0].parameter_map.keys())
            for pa in param_artifacts[1:]:
                common_keys.intersection_update(pa.parameter_map.keys())

            if common_keys:
                matches = 0
                mismatches = 0
                for k in common_keys:
                    val0 = str(param_artifacts[0].parameter_map[k])
                    if all(str(pa.parameter_map[k]) == val0 for pa in param_artifacts[1:]):
                        matches += 1
                    else:
                        mismatches += 1

                ratio = matches / len(common_keys)
                param_score = ratio * 100.0
                param_match = {
                    "status": "MATCH" if ratio >= 0.8 else ("PARTIAL_MATCH" if ratio >= 0.4 else "MISMATCH"),
                    "common_parameters_count": len(common_keys),
                    "matching_parameters": matches,
                    "mismatched_parameters": mismatches,
                    "details": f"Compared {len(common_keys)} common parameters: {matches} matched ({ratio*100.0:.1f}%).",
                }
            else:
                param_match = {
                    "status": "NO_COMMON_KEYS",
                    "details": f"Extracted parameters across {len(param_artifacts)} artifacts but found zero overlapping parameter names.",
                }
        else:
            param_match = {
                "status": "INSUFFICIENT_CONFIGS",
                "details": f"Parameter maps present in {len(param_artifacts)} artifact(s); minimum 2 required for parameter signature comparison.",
            }

        # Overall Confidence Score & Final Verdict Calculation
        # Weights: Hardware UID (40%), Spatio-Temporal (40%), Parameter Signature (20%)
        overall_score = (uid_score * 0.40) + (st_score * 0.40) + (param_score * 0.20)
        overall_score = max(0.0, min(100.0, round(overall_score, 1)))

        if hardware_uid_match.get("status") == "MISMATCH" or spatio_temporal_match.get("status") == "MISMATCH":
            match_verdict = "MISMATCH"
        elif overall_score >= 80.0:
            match_verdict = "MATCH"
        elif overall_score >= 50.0:
            match_verdict = "PARTIAL_MATCH"
        else:
            match_verdict = "INCONCLUSIVE"

        summary = (
            f"Identity Attribution Verdict: {match_verdict} (Confidence: {overall_score}%). "
            f"Hardware UID: {hardware_uid_match.get('status')}. "
            f"Spatio-Temporal: {spatio_temporal_match.get('status')}. "
            f"Parameter Signature: {param_match.get('status')}."
        )

        return IdentityAttributionReport(
            match_verdict=match_verdict,
            overall_confidence_score=overall_score,
            hardware_uid_match=hardware_uid_match,
            spatio_temporal_match=spatio_temporal_match,
            parameter_signature_match=param_match,
            conflicting_artifacts=conflicting_artifacts,
            attribution_score_breakdown={
                "hardware_uid_score": round(uid_score, 1),
                "spatio_temporal_score": round(st_score, 1),
                "parameter_signature_score": round(param_score, 1),
            },
            summary_findings=summary,
        )

    def analyze_telemetry_continuity(
        self,
        artifacts: list[ForensicArtifact],
        dropout_threshold_s: float = 3.0,
    ) -> TelemetryContinuityReport:
        """Evaluate flight telemetry continuity, detect packet dropouts, early terminations, and wiped sectors."""
        detected_gaps: list[TelemetryGap] = []
        desync_streams: list[dict[str, Any]] = []
        early_termination = False
        wiped_sectors = False

        total_artifacts = len(artifacts)
        if total_artifacts == 0:
            return TelemetryContinuityReport(
                overall_continuity_score=0.0,
                is_uninterrupted=False,
                summary_findings="No artifacts provided for telemetry continuity analysis.",
            )

        # 1. Per-Artifact Telemetry Gap & Dropout Analysis
        for a in artifacts:
            fname = a.file_path.name

            # Check parser corruption flag / wiped sector
            if a.is_corrupted:
                wiped_sectors = True
                offset_desc = f" at byte offset {hex(a.corruption_offset)}" if a.corruption_offset else ""
                detected_gaps.append(
                    TelemetryGap(
                        artifact_file=fname,
                        gap_type="STORAGE_CORRUPTION" if a.corruption_offset else "WIPED_SECTOR",
                        gap_duration_s=0.0,
                        severity="CRITICAL",
                        description=f"Evidence corruption or abrupt file truncation detected{offset_desc}.",
                    )
                )

            # Analyze consecutive point time gaps
            points = a.trajectory_points
            if len(points) >= 2:
                for i in range(len(points) - 1):
                    p1 = points[i]
                    p2 = points[i + 1]
                    ts1 = p1.get("timestamp_utc")
                    ts2 = p2.get("timestamp_utc")

                    if ts1 and ts2:
                        dt = abs((ts2 - ts1).total_seconds())
                        if dt >= dropout_threshold_s:
                            sev = "CRITICAL" if dt > 30.0 else ("HIGH" if dt > 10.0 else "MEDIUM")
                            detected_gaps.append(
                                TelemetryGap(
                                    artifact_file=fname,
                                    gap_type="PACKET_DROPOUT",
                                    start_time=ts1,
                                    end_time=ts2,
                                    gap_duration_s=round(dt, 2),
                                    severity=sev,
                                    description=f"Telemetry packet dropout detected: {dt:.1f}s gap between trajectory frames.",
                                )
                            )

                # Early termination / power disconnect check on last frame
                last_pt = points[-1]
                last_speed = last_pt.get("ground_speed_mps", 0.0)
                last_alt = last_pt.get("altitude_m", 0.0)

                if last_speed > 2.0 or last_alt > 5.0 or a.is_corrupted:
                    early_termination = True
                    detected_gaps.append(
                        TelemetryGap(
                            artifact_file=fname,
                            gap_type="POWER_DISCONNECT",
                            start_time=last_pt.get("timestamp_utc"),
                            end_time=last_pt.get("timestamp_utc"),
                            gap_duration_s=0.0,
                            severity="CRITICAL",
                            description=(
                                f"Abrupt session termination while airborne (Speed: {last_speed:.1f} m/s, Altitude: {last_alt:.1f} m). "
                                f"Indicates mid-flight power ejection or crash."
                            ),
                        )
                    )

        # 2. Multi-Stream Desynchronization Analysis
        if total_artifacts >= 2:
            blackbox_artifacts = [a for a in artifacts if a.file_type == ArtifactCategory.ONBOARD_BLACKBOX.value]
            gcs_artifacts = [a for a in artifacts if a.file_type == ArtifactCategory.GCS_TELEMETRY.value]

            if blackbox_artifacts and gcs_artifacts:
                for bb in blackbox_artifacts:
                    for gcs in gcs_artifacts:
                        if bb.session_end_utc and gcs.session_end_utc:
                            dt_end = (gcs.session_end_utc - bb.session_end_utc).total_seconds()
                            if dt_end > 5.0:  # GCS continued recording after onboard blackbox stopped
                                desync = {
                                    "onboard_file": bb.file_path.name,
                                    "gcs_file": gcs.file_path.name,
                                    "desync_duration_seconds": round(dt_end, 2),
                                    "finding": f"GCS mobile app continued receiving telemetry for {dt_end:.1f}s after onboard blackbox log terminated.",
                                }
                                desync_streams.append(desync)
                                detected_gaps.append(
                                    TelemetryGap(
                                        artifact_file=bb.file_path.name,
                                        gap_type="STREAM_DESYNC",
                                        start_time=bb.session_end_utc,
                                        end_time=gcs.session_end_utc,
                                        gap_duration_s=round(dt_end, 2),
                                        severity="HIGH",
                                        description=desync["finding"],
                                    )
                                )

        # Calculate Overall Continuity Score
        penalty = 0.0
        for gap in detected_gaps:
            if gap.severity == "CRITICAL":
                penalty += 20.0
            elif gap.severity == "HIGH":
                penalty += 10.0
            elif gap.severity == "MEDIUM":
                penalty += 5.0
            else:
                penalty += 2.0

        continuity_score = max(0.0, round(100.0 - penalty, 1))
        is_uninterrupted = len(detected_gaps) == 0

        summary = (
            f"Telemetry Continuity Score: {continuity_score}%. "
            f"Uninterrupted: {is_uninterrupted}. "
            f"Total Gaps/Dropouts: {len(detected_gaps)}. "
            f"Early Termination: {early_termination}. "
            f"Wiped Sectors/Corruptions: {wiped_sectors}."
        )

        return TelemetryContinuityReport(
            overall_continuity_score=continuity_score,
            is_uninterrupted=is_uninterrupted,
            detected_gaps=detected_gaps,
            early_termination_detected=early_termination,
            wiped_sectors_detected=wiped_sectors,
            desynchronized_streams=desync_streams,
            summary_findings=summary,
        )

    def correlate_evidence(
        self,
        evidence_paths: list[Union[Path, str]],
        dropout_threshold_s: float = 3.0,
    ) -> ComprehensiveAttributionResult:
        """Master entrypoint: Ingest N evidence paths, extract artifacts, run identity attribution & continuity analysis."""
        artifacts: list[ForensicArtifact] = []

        for p in evidence_paths:
            try:
                art = self.extract_artifact(p)
                artifacts.append(art)
            except Exception as e:
                # Add unparseable artifact placeholder safely
                path_obj = Path(p).resolve()
                artifacts.append(
                    ForensicArtifact(
                        file_path=path_obj,
                        file_type=ArtifactCategory.UNKNOWN.value,
                        platform="generic",
                        raw_event_count=0,
                        file_sha256="",
                        parser_used="error_failed",
                        is_corrupted=True,
                    )
                )

        identity_report = self.analyze_identity_attribution(artifacts)
        continuity_report = self.analyze_telemetry_continuity(artifacts, dropout_threshold_s=dropout_threshold_s)

        exec_summary = (
            f"UNIVERSAL FORENSIC ATTRIBUTION SUMMARY:\n"
            f"Ingested {len(artifacts)} evidence artifacts across platforms: {list(set(a.platform for a in artifacts))}.\n"
            f"1. Identity Attribution: {identity_report.match_verdict} ({identity_report.overall_confidence_score}% confidence).\n"
            f"2. Telemetry Continuity: {continuity_report.overall_continuity_score}% score ({len(continuity_report.detected_gaps)} gap/dropout events detected)."
        )

        return ComprehensiveAttributionResult(
            artifacts=artifacts,
            identity_attribution=identity_report,
            telemetry_continuity=continuity_report,
            executive_summary=exec_summary,
        )

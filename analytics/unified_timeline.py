"""
analytics/unified_timeline.py

Universal Multi-Source Chronological Timeline Engine for Drone Forensics.
Complies with ISO/IEC 27037:2012 and NIST SP 800-86:
- Merges events across onboard blackbox logs, GCS mobile telemetry, camera EXIF, video atoms,
  filesystem MACB timestamps, mission milestones, and anomaly alerts.
- Produces a single, standardized, chronologically sorted Master Forensic Timeline.
- Exports to CSV, JSON, and report-ready markdown summaries.
"""

from __future__ import annotations

import csv
import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from normalize.schema import NormalizedEvent


@dataclass
class TimelineEvent:
    timestamp_utc: datetime
    source_platform: str
    event_category: str
    source_file: str
    description: str
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    altitude_m: Optional[float] = None
    speed_mps: Optional[float] = None
    extra_details: Dict[str, Any] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["timestamp_utc"] = self.timestamp_utc.isoformat()
        return d


class UnifiedTimelineEngine:
    """Consolidates and chronologically orders forensic events across heterogeneous sources."""

    def __init__(self) -> None:
        self.events: List[TimelineEvent] = []

    def ingest_normalized_events(self, norm_events: List[NormalizedEvent]) -> None:
        """Translate normalized events into the master timeline."""
        for ev in norm_events:
            cat = "TELEMETRY"
            desc = f"Event from {ev.source_platform}"

            ev_type = str(ev.event_type).lower()
            if "gps" in ev_type:
                cat = "GNSS_TRACK"
                desc = f"GPS Fix: {ev.latitude:.6f}, {ev.longitude:.6f} (Alt: {ev.altitude_m or 0.0:.1f}m)"
            elif "config" in ev_type or "param" in ev_type:
                cat = "CONFIGURATION"
                desc = f"Config / Parameter: {ev.payload.get('origin', 'Setting')}"
            elif "mode" in ev_type:
                cat = "FLIGHT_MODE"
                desc = f"Mode Change: {ev.payload.get('mode', 'N/A')}"
            elif "error" in ev_type or "alert" in ev_type:
                cat = "SECURITY_ANOMALY"
                desc = f"Alert / Anomaly: {ev.payload.get('error', 'Anomaly detected')}"
            elif "media" in ev_type or "exif" in ev_type:
                cat = "MEDIA_ASSET"
                desc = f"Media Capture: {ev.payload.get('file_name', ev.source_file)}"
            elif "video" in ev_type:
                cat = "VIDEO_STREAM"
                desc = f"Video Frame / Segment: {ev.payload.get('milestone', 'Video Active')}"
            elif "mission" in ev_type:
                cat = "MISSION_PLAN"
                desc = f"Mission Waypoint: #{ev.payload.get('waypoint_index', 0)}"

            self.events.append(
                TimelineEvent(
                    timestamp_utc=ev.timestamp_utc,
                    source_platform=ev.source_platform,
                    event_category=cat,
                    source_file=ev.source_file,
                    description=desc,
                    latitude=ev.latitude,
                    longitude=ev.longitude,
                    altitude_m=ev.altitude_m,
                    speed_mps=ev.ground_speed_mps,
                    extra_details=ev.payload,
                )
            )

    def ingest_filesystem_event(
        self,
        timestamp_utc: datetime,
        file_path: str,
        macb_type: str,
        file_size: int,
    ) -> None:
        """Add filesystem metadata timestamp event (Modified, Accessed, Created)."""
        self.events.append(
            TimelineEvent(
                timestamp_utc=timestamp_utc,
                source_platform="filesystem_macb",
                event_category="FILESYSTEM",
                source_file=file_path,
                description=f"File {macb_type} timestamp recorded ({file_size} bytes)",
                extra_details={"macb_type": macb_type, "size_bytes": file_size},
            )
        )

    def get_sorted_timeline(self) -> List[TimelineEvent]:
        """Return all events sorted strictly by UTC timestamp."""
        return sorted(self.events, key=lambda e: e.timestamp_utc)

    def export_csv(self, output_path: Path) -> Path:
        """Export chronological timeline to CSV file."""
        sorted_evs = self.get_sorted_timeline()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Timestamp (UTC)",
                "Category",
                "Source Platform",
                "Source File",
                "Description",
                "Latitude",
                "Longitude",
                "Altitude (m)",
                "Speed (m/s)",
            ])
            for e in sorted_evs:
                writer.writerow([
                    e.timestamp_utc.strftime("%Y-%m-%d %H:%M:%S UTC"),
                    e.event_category,
                    e.source_platform,
                    e.source_file,
                    e.description,
                    f"{e.latitude:.7f}" if e.latitude is not None else "",
                    f"{e.longitude:.7f}" if e.longitude is not None else "",
                    f"{e.altitude_m:.2f}" if e.altitude_m is not None else "",
                    f"{e.speed_mps:.2f}" if e.speed_mps is not None else "",
                ])
        return output_path

    def export_json(self, output_path: Path) -> Path:
        """Export timeline to JSON structure."""
        sorted_evs = self.get_sorted_timeline()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        data = [e.to_dict() for e in sorted_evs]
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return output_path

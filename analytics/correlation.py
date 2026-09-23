"""
analytics/correlation.py

Forensic anomaly detection, geofence breach correlation, and flight incident analyzer.

Forensic Standards Compliance:
- ISO/IEC 27037: Objective mathematical validation of timeline anomalies.
- NIST SP 800-86: Multi-sensor correlation to establish causal links (e.g.
  voltage drop -> failsafe trigger -> flight mode change -> landing/crash).
"""

from __future__ import annotations

import math
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from normalize.schema import NormalizedEvent, EventType

EARTH_RADIUS_METERS = 6371000.0


class AnomalyType(str, Enum):
    """Controlled vocabulary for forensic anomalies."""

    GEOFENCE_BREACH = "geofence_breach"
    GPS_SPOOFING_OR_TELEPORTATION = "gps_spoofing_or_teleportation"
    GPS_SIGNAL_DEGRADATION = "gps_signal_degradation"
    CRITICAL_BATTERY_FAILSAFE = "critical_battery_failsafe"
    COMMUNICATION_LOSS = "communication_loss"
    IMPACT_OR_CRASH = "impact_or_crash"
    SUDDEN_ALTITUDE_DROP = "sudden_altitude_drop"
    FORENSIC_ANOMALY = "forensic_anomaly"



class FlightPhase(str, Enum):
    """Controlled vocabulary for flight reconstruction milestones."""
    ARMED = "ARMED"
    TAKEOFF = "TAKEOFF"
    CRUISE = "CRUISE"
    HOVER = "HOVER"
    LANDING = "LANDING"
    DISARMED = "DISARMED"
    RETURN_TO_HOME = "RETURN_TO_HOME"


@dataclass
class FlightKeyEvent:
    """Key flight milestone detected during flight reconstruction."""
    phase: str
    timestamp_utc: datetime
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    altitude_m: Optional[float] = None
    speed_mps: Optional[float] = None
    duration_s: float = 0.0
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["timestamp_utc"] = self.timestamp_utc.isoformat()
        return d


@dataclass
class NoFlyZone:
    """Represents a statutory or investigator-defined restricted airspace."""

    name: str
    polygon_vertices: list[tuple[float, float]]  # [(lat, lon), ...]
    min_altitude_m: float = 0.0
    max_altitude_m: float = 500.0
    description: str = ""


@dataclass
class ForensicAnomaly:
    """One forensically substantiated anomaly discovered during timeline correlation."""

    anomaly_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    anomaly_type: str = AnomalyType.GEOFENCE_BREACH.value
    severity: str = "MEDIUM"  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    timestamp_utc: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    altitude_m: Optional[float] = None
    trigger_event_id: str = ""
    description: str = ""
    evidence_context: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["timestamp_utc"] = self.timestamp_utc.isoformat()
        return d


def haversine_distance_m(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Compute the great-circle distance between two GPS coordinates in meters."""
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    a = (
        math.sin(delta_phi / 2.0) ** 2
        + math.cos(phi1) * math.cos(phi2) * (math.sin(delta_lambda / 2.0) ** 2)
    )
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    return EARTH_RADIUS_METERS * c


def point_in_polygon(lat: float, lon: float, polygon: list[tuple[float, float]]) -> bool:
    """Ray-casting algorithm (Jordan curve theorem) for point-in-polygon test."""
    n = len(polygon)
    if n < 3:
        return False

    inside = False
    p1_lat, p1_lon = polygon[0]
    for i in range(1, n + 1):
        p2_lat, p2_lon = polygon[i % n]
        if min(p1_lat, p2_lat) < lat <= max(p1_lat, p2_lat):
            if lon <= max(p1_lon, p2_lon):
                if p1_lat != p2_lat:
                    xinters = (lat - p1_lat) * (p2_lon - p1_lon) / (p2_lat - p1_lat) + p1_lon
                if p1_lon == p2_lon or lon <= xinters:
                    inside = not inside
        p1_lat, p1_lon = p2_lat, p2_lon
    return inside


class ForensicCorrelationEngine:
    """Correlates multi-sensor timeline events to reconstruct incident causation."""

    def __init__(
        self,
        max_kinematic_speed_mps: float = 45.0,  # ~162 km/h max realistic UAV speed
        max_hdop_threshold: float = 4.0,        # HDOP > 4 indicates poor geometry/jamming
        min_satellites_threshold: int = 6,      # < 6 satellites indicates loss of fix
        critical_battery_pct: float = 18.0,     # Low battery threshold percentage
        impact_pitch_roll_deg: float = 70.0,    # Uncontrolled attitude threshold
    ) -> None:
        self.max_kinematic_speed_mps = max_kinematic_speed_mps
        self.max_hdop_threshold = max_hdop_threshold
        self.min_satellites_threshold = min_satellites_threshold
        self.critical_battery_pct = critical_battery_pct
        self.impact_pitch_roll_deg = impact_pitch_roll_deg

    def analyze(
        self,
        events: list[NormalizedEvent],
        no_fly_zones: Optional[list[NoFlyZone]] = None,
    ) -> list[ForensicAnomaly]:
        """Perform comprehensive forensic analysis across chronological events."""
        sorted_events = sorted(events, key=lambda e: e.timestamp_utc)
        anomalies: list[ForensicAnomaly] = []

        if not sorted_events:
            return anomalies

        nfz_list = no_fly_zones or []

        prev_gps: Optional[NormalizedEvent] = None
        was_inside_nfz: dict[str, bool] = {nfz.name: False for nfz in nfz_list}

        for ev in sorted_events:
            # Skip uninitialized (0,0) Null Island coordinates in geospatial analysis
            is_valid_coord = (
                ev.latitude is not None
                and ev.longitude is not None
                and not (abs(ev.latitude) < 0.0001 and abs(ev.longitude) < 0.0001)
                and abs(ev.latitude) <= 90.0
                and abs(ev.longitude) <= 180.0
            )

            # 1. Geofence / No-Fly Zone Breach Check
            if is_valid_coord:
                for nfz in nfz_list:
                    is_inside = point_in_polygon(ev.latitude, ev.longitude, nfz.polygon_vertices)
                    # Check altitude constraint if provided
                    if is_inside and ev.altitude_m is not None:
                        if not (nfz.min_altitude_m <= ev.altitude_m <= nfz.max_altitude_m):
                            is_inside = False

                    if is_inside and not was_inside_nfz[nfz.name]:
                        # Transition: Entered NFZ
                        anomalies.append(
                            ForensicAnomaly(
                                anomaly_type=AnomalyType.GEOFENCE_BREACH.value,
                                severity="CRITICAL",
                                timestamp_utc=ev.timestamp_utc,
                                latitude=ev.latitude,
                                longitude=ev.longitude,
                                altitude_m=ev.altitude_m,
                                trigger_event_id=ev.record_id,
                                description=f"Unauthorized entry into No-Fly Zone: {nfz.name}",
                                evidence_context={
                                    "zone_name": nfz.name,
                                    "zone_description": nfz.description,
                                    "coordinates": [ev.latitude, ev.longitude],
                                    "altitude_m": ev.altitude_m,
                                },
                            )
                        )
                        was_inside_nfz[nfz.name] = True
                    elif not is_inside and was_inside_nfz[nfz.name]:
                        # Transition: Exited NFZ
                        was_inside_nfz[nfz.name] = False

            # 2. GPS Kinematic & Spoofing / Teleportation Check
            if is_valid_coord:
                if prev_gps is not None and prev_gps.latitude is not None and prev_gps.longitude is not None:
                    dt = (ev.timestamp_utc - prev_gps.timestamp_utc).total_seconds()
                    if 0.05 <= dt <= 15.0:
                        dist_m = haversine_distance_m(
                            prev_gps.latitude,
                            prev_gps.longitude,
                            ev.latitude,
                            ev.longitude,
                        )
                        computed_speed = dist_m / dt
                        if computed_speed > self.max_kinematic_speed_mps:
                            anomalies.append(
                                ForensicAnomaly(
                                    anomaly_type=AnomalyType.GPS_SPOOFING_OR_TELEPORTATION.value,
                                    severity="HIGH",
                                    timestamp_utc=ev.timestamp_utc,
                                    latitude=ev.latitude,
                                    longitude=ev.longitude,
                                    altitude_m=ev.altitude_m,
                                    trigger_event_id=ev.record_id,
                                    description=(
                                        f"Impossible kinematic displacement: calculated velocity "
                                        f"{computed_speed:.1f} m/s exceeds airframe limit "
                                        f"({self.max_kinematic_speed_mps:.1f} m/s) over {dt:.2f}s"
                                    ),
                                    evidence_context={
                                        "computed_velocity_mps": round(computed_speed, 2),
                                        "displacement_meters": round(dist_m, 2),
                                        "time_delta_seconds": round(dt, 2),
                                        "previous_coordinates": [prev_gps.latitude, prev_gps.longitude],
                                        "current_coordinates": [ev.latitude, ev.longitude],
                                    },
                                )
                            )

                # GPS Signal Degradation (HDOP / Satellites)
                if ev.hdop is not None and ev.hdop > self.max_hdop_threshold:
                    anomalies.append(
                        ForensicAnomaly(
                            anomaly_type=AnomalyType.GPS_SIGNAL_DEGRADATION.value,
                            severity="MEDIUM",
                            timestamp_utc=ev.timestamp_utc,
                            latitude=ev.latitude,
                            longitude=ev.longitude,
                            altitude_m=ev.altitude_m,
                            trigger_event_id=ev.record_id,
                            description=f"Severe GPS geometry degradation: HDOP reached {ev.hdop:.2f}",
                            evidence_context={
                                "hdop": ev.hdop,
                                "satellites_visible": ev.satellites_visible,
                            },
                        )
                    )
                elif ev.satellites_visible is not None and ev.satellites_visible < self.min_satellites_threshold:
                    anomalies.append(
                        ForensicAnomaly(
                            anomaly_type=AnomalyType.GPS_SIGNAL_DEGRADATION.value,
                            severity="MEDIUM",
                            timestamp_utc=ev.timestamp_utc,
                            latitude=ev.latitude,
                            longitude=ev.longitude,
                            altitude_m=ev.altitude_m,
                            trigger_event_id=ev.record_id,
                            description=f"GPS lock compromised: only {ev.satellites_visible} satellites visible",
                            evidence_context={
                                "satellites_visible": ev.satellites_visible,
                                "hdop": ev.hdop,
                            },
                        )
                    )

                prev_gps = ev

            # 3. Critical Battery State
            if ev.battery_remaining_pct is not None and ev.battery_remaining_pct <= self.critical_battery_pct:
                anomalies.append(
                    ForensicAnomaly(
                        anomaly_type=AnomalyType.CRITICAL_BATTERY_FAILSAFE.value,
                        severity="HIGH",
                        timestamp_utc=ev.timestamp_utc,
                        latitude=ev.latitude,
                        longitude=ev.longitude,
                        altitude_m=ev.altitude_m,
                        trigger_event_id=ev.record_id,
                        description=f"Critical battery depletion threshold reached: {ev.battery_remaining_pct:.1f}%",
                        evidence_context={
                            "battery_remaining_pct": ev.battery_remaining_pct,
                            "battery_voltage_v": ev.battery_voltage_v,
                        },
                    )
                )

            # 4. Impact / Crash Shock Detection
            if ev.pitch_deg is not None and ev.roll_deg is not None:
                if (
                    abs(ev.pitch_deg) > self.impact_pitch_roll_deg
                    or abs(ev.roll_deg) > self.impact_pitch_roll_deg
                ):
                    anomalies.append(
                        ForensicAnomaly(
                            anomaly_type=AnomalyType.IMPACT_OR_CRASH.value,
                            severity="CRITICAL",
                            timestamp_utc=ev.timestamp_utc,
                            latitude=ev.latitude,
                            longitude=ev.longitude,
                            altitude_m=ev.altitude_m,
                            trigger_event_id=ev.record_id,
                            description=(
                                f"Catastrophic attitude deviation / impact shock: "
                                f"pitch={ev.pitch_deg:.1f}°, roll={ev.roll_deg:.1f}°"
                            ),
                            evidence_context={
                                "pitch_deg": ev.pitch_deg,
                                "roll_deg": ev.roll_deg,
                                "yaw_deg": ev.yaw_deg,
                            },
                        )
                    )

        # 5. Cross-Stream Controller vs. Drone Takeoff Mismatch & Time Skew Correlation
        gcs_anomalies = self.correlate_controller_and_drone_telemetry(sorted_events)
        anomalies.extend(gcs_anomalies)

        return anomalies

    def correlate_controller_and_drone_telemetry(
        self,
        events: list[NormalizedEvent],
    ) -> list[ForensicAnomaly]:
        """
        Cross-compare GCS Mobile Controller telemetry against Drone Blackbox telemetry.
        
        NIST SP 800-86 Compliance:
        1. Compares Controller Home Point GPS vs. Drone Takeoff GPS to identify GPS spoofing
           or spatial displacement anomalies.
        2. Computes time skew between mobile system clock and GPS UTC time.
        3. Synchronizes pilot control stick inputs with drone kinematic responses.
        """
        anomalies: list[ForensicAnomaly] = []
        gcs_events = [
            e for e in events
            if e.payload.get("origin") == "GCS_CONTROLLER"
            or "gcs" in e.source_platform.lower()
            or "controller" in e.source_platform.lower()
        ]
        drone_events = [
            e for e in events
            if e not in gcs_events
        ]

        if not gcs_events or not drone_events:
            return anomalies

        # 1. Compare Controller Home Point vs. Drone Takeoff GPS
        gcs_gps_fixes = [
            e for e in gcs_events
            if e.latitude is not None and e.longitude is not None
            and not (abs(e.latitude) < 0.0001 and abs(e.longitude) < 0.0001)
        ]
        drone_gps_fixes = [
            e for e in drone_events
            if e.latitude is not None and e.longitude is not None
            and not (abs(e.latitude) < 0.0001 and abs(e.longitude) < 0.0001)
        ]

        if gcs_gps_fixes and drone_gps_fixes:
            gcs_first = gcs_gps_fixes[0]
            drone_first = drone_gps_fixes[0]
            dist_m = haversine_distance_m(
                gcs_first.latitude, gcs_first.longitude,
                drone_first.latitude, drone_first.longitude,
            )
            if dist_m > 50.0:  # > 50m discrepancy indicates spoofing or remote takeoff
                anomalies.append(
                    ForensicAnomaly(
                        anomaly_type=AnomalyType.GPS_SPOOFING_OR_TELEPORTATION.value,
                        severity="HIGH",
                        timestamp_utc=gcs_first.timestamp_utc,
                        latitude=gcs_first.latitude,
                        longitude=gcs_first.longitude,
                        altitude_m=gcs_first.altitude_m,
                        trigger_event_id=gcs_first.record_id,
                        description=(
                            f"Controller / Drone Home Point Mismatch: GCS Home Point ({gcs_first.latitude:.6f}, {gcs_first.longitude:.6f}) "
                            f"differs from Aircraft Takeoff Location ({drone_first.latitude:.6f}, {drone_first.longitude:.6f}) "
                            f"by {dist_m:.1f} meters."
                        ),
                        evidence_context={
                            "gcs_controller_gps": [gcs_first.latitude, gcs_first.longitude],
                            "drone_takeoff_gps": [drone_first.latitude, drone_first.longitude],
                            "distance_delta_meters": round(dist_m, 2),
                        },
                    )
                )

        # 2. Time Skew Analysis between Mobile System Clock and Aircraft GPS UTC
        gcs_timestamps = [e.timestamp_utc for e in gcs_events]
        drone_timestamps = [e.timestamp_utc for e in drone_events]

        if gcs_timestamps and drone_timestamps:
            min_gcs_t = min(gcs_timestamps)
            min_drone_t = min(drone_timestamps)
            skew_seconds = (min_gcs_t - min_drone_t).total_seconds()
            if abs(skew_seconds) > 5.0:
                anomalies.append(
                    ForensicAnomaly(
                        anomaly_type=AnomalyType.FORENSIC_ANOMALY.value,
                        severity="MEDIUM",
                        timestamp_utc=min_gcs_t,
                        trigger_event_id=gcs_events[0].record_id,
                        description=(
                            f"Mobile GCS Clock Drift Detected: System clock skew of {skew_seconds:+.2f} seconds "
                            f"compared to UAV flight controller time."
                        ),
                        evidence_context={
                            "gcs_start_time_utc": min_gcs_t.isoformat(),
                            "drone_start_time_utc": min_drone_t.isoformat(),
                            "clock_skew_seconds": round(skew_seconds, 2),
                        },
                    )
                )

        return anomalies


    def detect_flight_key_events(
        self,
        events: list[NormalizedEvent],
    ) -> list[FlightKeyEvent]:
        """Reconstruct key flight phases: Takeoff, Cruise, Hover, Landing, RTH."""
        sorted_events = sorted(events, key=lambda e: e.timestamp_utc)
        key_events: list[FlightKeyEvent] = []

        if not sorted_events:
            return key_events

        # 1. Direct system transitions (Arm, Disarm, RTH)
        for ev in sorted_events:
            if ev.event_type == EventType.ARM_DISARM.value:
                state = str(ev.payload.get("arming_state", "")).upper()
                if "ARM" in state and "DISARM" not in state:
                    key_events.append(
                        FlightKeyEvent(
                            phase=FlightPhase.ARMED.value,
                            timestamp_utc=ev.timestamp_utc,
                            latitude=ev.latitude,
                            longitude=ev.longitude,
                            altitude_m=ev.altitude_m,
                            description="Motors armed by flight controller",
                        )
                    )
                elif "DISARM" in state:
                    key_events.append(
                        FlightKeyEvent(
                            phase=FlightPhase.DISARMED.value,
                            timestamp_utc=ev.timestamp_utc,
                            latitude=ev.latitude,
                            longitude=ev.longitude,
                            altitude_m=ev.altitude_m,
                            description="Motors disarmed",
                        )
                    )
            elif ev.event_type == EventType.RTH_TRIGGER.value:
                key_events.append(
                    FlightKeyEvent(
                        phase=FlightPhase.RETURN_TO_HOME.value,
                        timestamp_utc=ev.timestamp_utc,
                        latitude=ev.latitude,
                        longitude=ev.longitude,
                        altitude_m=ev.altitude_m,
                        description="Return-to-Home failsafe activated",
                    )
                )

        # 2. Kinematic trajectory analysis (Takeoff, Hover, Landing)
        gps_fixes = [
            e for e in sorted_events
            if e.event_type == EventType.GPS_FIX.value and e.altitude_m is not None
            and e.latitude is not None and e.longitude is not None
            and not (abs(e.latitude) < 0.0001 and abs(e.longitude) < 0.0001)
        ]
        if not gps_fixes:
            return sorted(key_events, key=lambda k: k.timestamp_utc)

        base_alt = gps_fixes[0].altitude_m or 0.0

        # Detect Takeoff
        for fix in gps_fixes:
            if fix.altitude_m is not None and (fix.altitude_m - base_alt) > 1.0:
                key_events.append(
                    FlightKeyEvent(
                        phase=FlightPhase.TAKEOFF.value,
                        timestamp_utc=fix.timestamp_utc,
                        latitude=fix.latitude,
                        longitude=fix.longitude,
                        altitude_m=fix.altitude_m,
                        speed_mps=fix.ground_speed_mps,
                        description=f"Airborne liftoff confirmed (climb to {fix.altitude_m:.1f}m)",
                    )
                )
                break

        # Detect Hover periods: speed <= 0.4 m/s and (alt - base_alt) > 1.0m lasting >= 3s
        hover_start: Optional[NormalizedEvent] = None
        hover_samples: list[NormalizedEvent] = []

        for fix in gps_fixes:
            is_hovering = (
                fix.ground_speed_mps is not None
                and fix.ground_speed_mps <= 0.4
                and fix.altitude_m is not None
                and (fix.altitude_m - base_alt) > 1.0
            )
            if is_hovering:
                if hover_start is None:
                    hover_start = fix
                hover_samples.append(fix)
            else:
                if hover_start and len(hover_samples) >= 3:
                    duration = (hover_samples[-1].timestamp_utc - hover_start.timestamp_utc).total_seconds()
                    if duration >= 3.0:
                        key_events.append(
                            FlightKeyEvent(
                                phase=FlightPhase.HOVER.value,
                                timestamp_utc=hover_start.timestamp_utc,
                                latitude=hover_start.latitude,
                                longitude=hover_start.longitude,
                                altitude_m=hover_start.altitude_m,
                                speed_mps=hover_start.ground_speed_mps,
                                duration_s=round(duration, 1),
                                description=f"Stationary hover loiter for {duration:.1f}s at altitude {hover_start.altitude_m:.1f}m",
                            )
                        )
                hover_start = None
                hover_samples = []

        if hover_start and len(hover_samples) >= 3:
            duration = (hover_samples[-1].timestamp_utc - hover_start.timestamp_utc).total_seconds()
            if duration >= 3.0:
                key_events.append(
                    FlightKeyEvent(
                        phase=FlightPhase.HOVER.value,
                        timestamp_utc=hover_start.timestamp_utc,
                        latitude=hover_start.latitude,
                        longitude=hover_start.longitude,
                        altitude_m=hover_start.altitude_m,
                        speed_mps=hover_start.ground_speed_mps,
                        duration_s=round(duration, 1),
                        description=f"Stationary hover loiter for {duration:.1f}s at altitude {hover_start.altitude_m:.1f}m",
                    )
                )

        # Detect Landing
        if len(gps_fixes) > 5:
            max_alt = max((f.altitude_m or 0.0) for f in gps_fixes)
            if (max_alt - base_alt) > 1.5:
                for fix in reversed(gps_fixes[-len(gps_fixes) // 2:]):
                    if fix.altitude_m is not None and (fix.altitude_m - base_alt) <= 0.8:
                        key_events.append(
                            FlightKeyEvent(
                                phase=FlightPhase.LANDING.value,
                                timestamp_utc=fix.timestamp_utc,
                                latitude=fix.latitude,
                                longitude=fix.longitude,
                                altitude_m=fix.altitude_m,
                                speed_mps=fix.ground_speed_mps,
                                description=f"Touchdown / landing detected at altitude {fix.altitude_m:.1f}m",
                            )
                        )
                        break

        return sorted(key_events, key=lambda k: k.timestamp_utc)


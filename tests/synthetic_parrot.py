"""
tests/synthetic_parrot.py

Synthetic Parrot ANAFI JSON flight log generator for deterministic forensic testing.
"""

from __future__ import annotations

import json
from pathlib import Path


def generate_synthetic_parrot_log(output_path: Path) -> Path:
    """Generate a realistic Parrot ANAFI USA flight record JSON file."""
    base_lat = 19.0760
    base_lng = 72.8777

    telemetry: list[dict] = []
    for i in range(10):
        offset_ms = (i + 1) * 1000
        telemetry.append({
            "timestamp_ms": offset_ms,
            "latitude": round(base_lat + (i * 0.0003), 6),
            "longitude": round(base_lng + (i * 0.0003), 6),
            "altitude_m": round(5.0 + (i * 3.5), 1),
            "speed_mps": 13.5,
            "heading_deg": 45.0,
            "pitch_deg": -2.0,
            "roll_deg": 1.2,
            "yaw_deg": 44.8,
            "battery_pct": max(15, 95 - (i * 8)),
            "battery_voltage_v": round(11.4 - (i * 0.15), 2),
            "satellites": 17,
            "hdop": 0.7,
            "flight_mode": "manual" if i < 7 else "rth",
            "is_flying": True,
        })

    events = [
        {
            "timestamp_ms": 500,
            "event_type": "takeoff",
            "message": "Parrot ANAFI USA airborne: Takeoff successful",
        },
        {
            "timestamp_ms": 7500,
            "event_type": "rth_triggered",
            "message": "Failsafe: Low battery triggered Return-To-Home",
        },
        {
            "timestamp_ms": 11000,
            "event_type": "landing",
            "message": "Touchdown: Motors disarmed",
        },
    ]

    data = {
        "version": "1.0",
        "drone_model": "Parrot ANAFI USA",
        "serial_number": "PI040384AA9J123456",
        "firmware_version": "1.8.2",
        "flight_date": "2026-09-01T10:00:00Z",
        "run_id": "c7a8b9d0-1234-5678-9abc-def012345678",
        "controller": {
            "model": "Skycontroller 3",
            "serial_number": "PI020184AA9J654321",
        },
        "details": {
            "total_flight_duration_s": 360.0,
            "total_distance_m": 1250.0,
            "max_altitude_m": 40.0,
            "max_speed_mps": 13.5,
        },
        "telemetry": telemetry,
        "events": events,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return output_path

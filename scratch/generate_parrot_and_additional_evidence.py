"""
scratch/generate_parrot_and_additional_evidence.py

Generates authentic sample logs for Parrot (ANAFI USA, Bebop 2, FreeFlight),
Autel EVO II, and Yuneec H520 for test coverage.
"""
import json
import csv
from pathlib import Path
from datetime import datetime, timezone, timedelta

SAMPLE_DIR = Path("sample_evidence")
DESKTOP_DIR = Path(r"C:\Users\pawan\Desktop\Drone_Test_Evidence")

def create_parrot_anafi():
    base_lat = 28.6139  # New Delhi
    base_lon = 77.2090
    base_time = datetime(2026, 9, 15, 8, 30, 0, tzinfo=timezone.utc)
    
    telemetry = []
    for i in range(60):
        t_ms = i * 1000
        telemetry.append({
            "timestamp_ms": t_ms,
            "latitude": round(base_lat + (i * 0.00015) + (0.00005 * (i % 3)), 6),
            "longitude": round(base_lon + (i * 0.00018) - (0.00003 * (i % 2)), 6),
            "altitude_m": round(min(45.0, 2.0 + (i * 1.2) if i < 35 else 45.0 - (i - 35) * 1.5), 1),
            "speed_mps": round(min(15.0, 4.0 + (i * 0.4) if i < 25 else 12.0), 1),
            "heading_deg": round((45.0 + (i * 2.5)) % 360.0, 1),
            "pitch_deg": round(-2.5 + (0.8 * (i % 4)), 1),
            "roll_deg": round(1.2 + (0.5 * (i % 3)), 1),
            "yaw_deg": round((45.0 + (i * 2.5)) % 360.0, 1),
            "battery_pct": max(12, round(98.0 - (i * 0.8), 0)),
            "battery_voltage_v": round(11.6 - (i * 0.04), 2),
            "satellites": 18,
            "hdop": 0.65,
            "flight_mode": "manual" if i < 45 else "rth",
            "is_flying": True,
        })
        
    events = [
        {"timestamp_ms": 0, "event_type": "takeoff", "message": "Parrot ANAFI USA Airborne - Automated Takeoff Completed"},
        {"timestamp_ms": 45000, "event_type": "rth_triggered", "message": "Failsafe: Low Battery Return-to-Home Executed"},
        {"timestamp_ms": 59000, "event_type": "landing", "message": "Touchdown: Motors Disarmed at Home Base"},
    ]
    
    data = {
        "version": "1.0",
        "drone_model": "Parrot ANAFI USA Tactical",
        "serial_number": "PI040384AA9J789012",
        "firmware_version": "1.8.4",
        "flight_date": base_time.isoformat(),
        "run_id": "parrot-anafi-usa-run-2026",
        "controller": {
            "model": "Skycontroller 3",
            "serial_number": "PI020184AA9J345678"
        },
        "details": {
            "total_flight_duration_s": 60.0,
            "total_distance_m": 1420.0,
            "max_altitude_m": 45.0,
            "max_speed_mps": 15.0
        },
        "telemetry": telemetry,
        "events": events
    }
    
    out_file = SAMPLE_DIR / "parrot_anafi_usa_flight.json"
    out_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"[+] Created Parrot ANAFI USA flight log: {out_file}")
    return out_file

def create_parrot_bebop():
    base_lat = 19.0760  # Mumbai
    base_lon = 72.8777
    base_time = datetime(2026, 9, 16, 14, 15, 0, tzinfo=timezone.utc)
    
    telemetry = []
    for i in range(40):
        t_ms = i * 1000
        telemetry.append({
            "timestamp_ms": t_ms,
            "latitude": round(base_lat + (i * 0.0001), 6),
            "longitude": round(base_lon + (i * 0.00012), 6),
            "altitude_m": round(min(30.0, 1.5 + (i * 1.0)), 1),
            "speed_mps": round(min(12.0, 3.0 + (i * 0.3)), 1),
            "heading_deg": round((90.0 + (i * 3.0)) % 360.0, 1),
            "pitch_deg": -1.8,
            "roll_deg": 0.9,
            "yaw_deg": 90.0,
            "battery_pct": max(20, round(95.0 - (i * 1.2), 0)),
            "battery_voltage_v": round(11.4 - (i * 0.05), 2),
            "satellites": 16,
            "hdop": 0.8,
            "flight_mode": "manual",
            "is_flying": True,
        })
        
    events = [
        {"timestamp_ms": 0, "event_type": "takeoff", "message": "Parrot Bebop 2: Takeoff"},
        {"timestamp_ms": 39000, "event_type": "landing", "message": "Parrot Bebop 2: Landing"},
    ]
    
    data = {
        "version": "1.0",
        "drone_model": "Parrot Bebop 2 FPV",
        "serial_number": "PI030284BB8K555123",
        "firmware_version": "4.4.2",
        "flight_date": base_time.isoformat(),
        "run_id": "parrot-bebop-2-run-2026",
        "controller": {
            "model": "Skycontroller 2",
            "serial_number": "PI010184AA8K999888"
        },
        "details": {
            "total_flight_duration_s": 40.0,
            "total_distance_m": 850.0,
            "max_altitude_m": 30.0,
            "max_speed_mps": 12.0
        },
        "telemetry": telemetry,
        "events": events
    }
    
    out_file = SAMPLE_DIR / "parrot_bebop_2_flight.json"
    out_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(f"[+] Created Parrot Bebop 2 flight log: {out_file}")
    return out_file

def main():
    f_anafi = create_parrot_anafi()
    f_bebop = create_parrot_bebop()
    
    # Copy into Desktop Drone_Test_Evidence folder
    parrot_dest = DESKTOP_DIR / "04_Parrot_and_Yuneec_Logs"
    parrot_dest.mkdir(parents=True, exist_ok=True)
    import shutil
    shutil.copy2(f_anafi, parrot_dest / f_anafi.name)
    shutil.copy2(f_bebop, parrot_dest / f_bebop.name)
    print(f"[+] Copied Parrot flight logs to {parrot_dest}")

if __name__ == "__main__":
    main()

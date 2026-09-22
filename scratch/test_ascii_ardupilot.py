"""
Test ASCII DataFlash parsing for ArduPilot .log files
"""
import sys
import csv
from pathlib import Path
from datetime import datetime, timezone, timedelta
sys.path.insert(0, ".")

GPS_EPOCH = datetime(1980, 1, 6, 0, 0, 0, tzinfo=timezone.utc)
GPS_LEAP_SECONDS = 18

def parse_ascii_ardupilot(file_path):
    formats = {}
    gps_rows = []
    events = []
    
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            parts = [p.strip() for p in line.strip().split(",")]
            if not parts or not parts[0]:
                continue
            msg_name = parts[0]
            if msg_name == "FMT" and len(parts) >= 6:
                # FMT, Type, Length, Name, Format, Columns...
                name = parts[3]
                cols = parts[5:]
                formats[name] = cols
            elif msg_name in formats:
                cols = formats[msg_name]
                vals = parts[1:]
                row = dict(zip(cols, vals))
                if msg_name == "GPS":
                    gps_rows.append(row)
                    
    print(f"Parsed {len(formats)} FMT schemas.")
    print(f"Parsed {len(gps_rows)} GPS rows.")
    if gps_rows:
        print(f"First GPS: {gps_rows[0]}")
        print(f"Last GPS: {gps_rows[-1]}")

parse_ascii_ardupilot("sample_evidence/mission_planner_logs/2018-06-04 15-29-57.log")

"""
Test updated Betaflight trajectory and 3D map export
"""
import sys
import math
from pathlib import Path
sys.path.insert(0, ".")

from parsers.betaflight_blackbox import BetaflightBlackboxParser
from export.geospatial import export_3d_html_map
from gui.api import DesktopForensicAPI

p = Path("sample_evidence/betaflight_multi.bbl")
parser = BetaflightBlackboxParser()
events = parser.parse(p)

gps_events = [e for e in events if getattr(e, "latitude", None) is not None]
print(f"Total events: {len(events)}, GPS/Kinematic fixes: {len(gps_events)}")
if gps_events:
    print(f"Start GPS: Lat={gps_events[0].latitude}, Lon={gps_events[0].longitude}, Alt={gps_events[0].altitude_m}m")
    print(f"Mid GPS: Lat={gps_events[len(gps_events)//2].latitude}, Lon={gps_events[len(gps_events)//2].longitude}, Alt={gps_events[len(gps_events)//2].altitude_m}m")
    print(f"End GPS: Lat={gps_events[-1].latitude}, Lon={gps_events[-1].longitude}, Alt={gps_events[-1].altitude_m}m")

# Test 3D map export
out_3d = Path("scratch/test_3d_flight_map.html")
export_3d_html_map(events, output_path=out_3d)
print(f"3D Map generated: {out_3d} ({out_3d.stat().st_size} bytes)")

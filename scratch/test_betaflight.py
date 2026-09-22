"""
Test BetaflightBlackboxParser on sample files
"""
import sys
from pathlib import Path
sys.path.insert(0, ".")

from parsers.betaflight_blackbox import BetaflightBlackboxParser

parser = BetaflightBlackboxParser()

for fname in ["betaflight_sample.bfl", "betaflight_multi.bbl", "betaflight_corrupt.bfl"]:
    p = Path(f"sample_evidence/{fname}")
    if p.exists():
        print(f"\n==========================================")
        print(f"Testing {fname} ({p.stat().st_size} bytes)")
        print(f"Can parse: {parser.can_parse(p)}")
        events = list(parser.parse(p))
        print(f"Total events: {len(events)}")
        types = set(e.event_type for e in events)
        print(f"Event types: {types}")
        gps_events = [e for e in events if getattr(e, "latitude", None) is not None]
        print(f"GPS fixes: {len(gps_events)}")
        if events:
            print(f"First event: {events[0].event_type} - {events[0].payload}")
            print(f"Last event: {events[-1].event_type} - {events[-1].payload}")

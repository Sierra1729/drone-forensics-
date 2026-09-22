"""
Test every file in Drone_Test_Evidence against all registered parsers.
"""
import sys
from pathlib import Path
sys.path.insert(0, ".")

import parsers  # triggers all parser registrations
from parsers.base import _PARSER_REGISTRY, get_parser_for_file

print(f"Registered parsers ({len(_PARSER_REGISTRY)}):")
for p_cls in _PARSER_REGISTRY:
    p = p_cls()
    exts = getattr(p, "supported_extensions", getattr(p, "EXTENSIONS", "N/A"))
    print(f"  • {p.parser_name} ({p_cls.__name__}) - supports: {exts}")

test_evidence_dir = Path(r"C:\Users\pawan\Desktop\Drone_Test_Evidence")
print(f"\nScanning files in {test_evidence_dir}...")

for f in test_evidence_dir.rglob("*"):
    if f.is_file() and not f.name.endswith(".txt") and not f.name.endswith(".MD5") and not f.name.endswith(".SHA1"):
        parser = get_parser_for_file(f)
        p_name = parser.parser_name if parser else "❌ NO PARSER FOUND"
        print(f"\nFile: {f.relative_to(test_evidence_dir)} ({f.stat().st_size} bytes)")
        print(f"  Detected Parser: {p_name}")
        if parser:
            try:
                events = list(parser.parse(f))
                gps_count = sum(1 for e in events if getattr(e, "latitude", None) is not None)
                print(f"  -> Parse SUCCESS: {len(events)} events, {gps_count} GPS fixes")
            except Exception as e:
                print(f"  -> Parse ERROR: {e}")

"""
Inspect contents of betaflight_sample.bfl and betaflight_multi.bbl
"""
from pathlib import Path

for fname in ["betaflight_sample.bfl", "betaflight_multi.bbl"]:
    p = Path(f"sample_evidence/{fname}")
    if p.exists():
        data = p.read_bytes()
        print(f"\n==================== {fname} ({len(data)} bytes) ====================")
        # Find all H header lines
        header_end = 0
        lines = []
        for line in data.split(b"\n")[:30]:
            if line.startswith(b"H "):
                lines.append(line.decode("latin1"))
        print(f"Header lines ({len(lines)}):")
        for l in lines[:10]:
            print(f"  {l}")
        # Check what follows header
        print(f"Byte distribution in remainder: 'I': {data.count(b'I')}, 'P': {data.count(b'P')}, 'G': {data.count(b'G')}, 'S': {data.count(b'S')}, 'E': {data.count(b'E')}")

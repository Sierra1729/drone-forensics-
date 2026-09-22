"""
Test binary decoding for Betaflight bfl/bbl files
"""
import sys
import struct
from pathlib import Path
sys.path.insert(0, ".")

def test_decode_bfl(file_path):
    data = Path(file_path).read_bytes()
    pos = 0
    headers = {}
    
    # 1. Parse H headers
    while pos < len(data):
        line_end = data.find(b"\n", pos)
        if line_end == -1:
            break
        line = data[pos:line_end].strip()
        if line.startswith(b"H "):
            try:
                text = line[2:].decode("latin1")
                if ":" in text:
                    k, v = text.split(":", 1)
                    headers[k.strip()] = v.strip()
            except Exception:
                pass
            pos = line_end + 1
        else:
            break
            
    print(f"Parsed {len(headers)} header keys from {Path(file_path).name}")
    print(f"Craft: {headers.get('Craft name', 'N/A')}, Firmware: {headers.get('Firmware type', 'N/A')} {headers.get('Firmware revision', 'N/A')}")
    print(f"Log start: {headers.get('Log start datetime', 'N/A')}")
    print(f"Frame stream starts at byte offset: {pos}")
    
    # Scan frame types in binary stream
    frame_counts = {}
    i = pos
    while i < len(data):
        byte = bytes([data[i]])
        if byte in [b'I', b'P', b'G', b'S', b'E']:
            frame_counts[byte.decode()] = frame_counts.get(byte.decode(), 0) + 1
        i += 1
    print(f"Frame counts: {frame_counts}")

test_decode_bfl("sample_evidence/betaflight_sample.bfl")
test_decode_bfl("sample_evidence/betaflight_multi.bbl")

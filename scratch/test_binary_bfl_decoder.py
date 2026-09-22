"""
Test decoding binary frames from betaflight_sample.bfl
"""
import sys
from pathlib import Path
from datetime import datetime, timezone, timedelta
sys.path.insert(0, ".")

def read_uval(buf, offset):
    val = 0
    shift = 0
    while offset < len(buf):
        b = buf[offset]
        offset += 1
        val |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            break
        shift += 7
        if shift > 35:
            break
    return val, offset

def read_sval(buf, offset):
    uval, offset = read_uval(buf, offset)
    sval = (uval >> 1) ^ (-(uval & 1))
    return sval, offset

data = Path("sample_evidence/betaflight_sample.bfl").read_bytes()

# Find header end
pos = 0
while pos < len(data):
    line_end = data.find(b"\n", pos)
    if line_end == -1:
        break
    line = data[pos:line_end].strip()
    if line.startswith(b"H "):
        pos = line_end + 1
    else:
        break

print(f"Data stream starts at: {pos}")

# Parse frames
gps_fixes = []
intra_frames = []
events = []

i = pos
while i < len(data) - 8:
    b = data[i]
    if b == ord('G'):
        # Attempt decode G frame
        try:
            cur = i + 1
            # G frame fields in betaflight: time_offset, fixType, numSat, lat, lon, alt, spd, course
            # Try reading VB values
            time_raw, cur = read_uval(data, cur)
            fix_type, cur = read_uval(data, cur)
            num_sat, cur = read_uval(data, cur)
            lat_raw, cur = read_sval(data, cur)
            lon_raw, cur = read_sval(data, cur)
            alt_raw, cur = read_sval(data, cur)
            spd_raw, cur = read_uval(data, cur)
            course_raw, cur = read_uval(data, cur)
            
            lat = lat_raw / 1e7 if abs(lat_raw) > 1000 else lat_raw
            lon = lon_raw / 1e7 if abs(lon_raw) > 1000 else lon_raw
            
            if -90 <= lat <= 90 and -180 <= lon <= 180 and (abs(lat) > 0.1 or abs(lon) > 0.1):
                gps_fixes.append({
                    "time": time_raw,
                    "sats": num_sat,
                    "lat": lat,
                    "lon": lon,
                    "alt": alt_raw / 100.0 if abs(alt_raw) > 1000 else alt_raw,
                    "spd": spd_raw / 100.0 if spd_raw > 100 else spd_raw,
                    "course": course_raw / 10.0 if course_raw > 360 else course_raw,
                })
        except Exception:
            pass
    elif b == ord('I'):
        # Intra frame
        intra_frames.append(i)
    elif b == ord('E'):
        events.append(i)
        
    i += 1

print(f"Decoded GPS fixes: {len(gps_fixes)}")
if gps_fixes:
    print(f"Sample GPS fix 0: {gps_fixes[0]}")
    print(f"Sample GPS fix mid: {gps_fixes[len(gps_fixes)//2]}")
    print(f"Sample GPS fix last: {gps_fixes[-1]}")
print(f"Decoded Intra frames: {len(intra_frames)}")
print(f"Decoded Event frames: {len(events)}")

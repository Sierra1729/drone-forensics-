"""
Inspect header of adsb_log_type0_20180913112320.dat
"""
from pathlib import Path

p = Path(r"C:\Users\pawan\Desktop\Drone_Test_Evidence\01_DJI_Flight_Logs\adsb_log_type0_20180913112320.dat")
if not p.exists():
    p = Path(r"sample_evidence\vto_labs_drone_forensics\DJI_Assistant_export_ADB\DJI_Assistant_Export_ADBS\adsb_log_type0_20180913112320.dat")

data = p.read_bytes()
print(f"File size: {len(data)} bytes")
print(f"Header hex (64 bytes): {data[:64].hex()}")
print(f"Header ascii repr: {data[:128]}")
print(f"Count of 0x55 in first 512 bytes: {data[:512].count(b'\x55')}")
print(f"Contains b'adsb' or b'log' or other text: {[w for w in [b'adsb', b'ADSB', b'DJI', b'BUILD', b'LOG', b'type'] if w in data[:512]]}")

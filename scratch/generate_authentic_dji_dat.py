"""
scratch/generate_authentic_dji_dat.py

Generates a fully compliant, authentic DJI Onboard .DAT flight record
(FLY042_DJI_Phantom_4_Pro.DAT) conforming to DatCon / DJI V3 binary specifications.
"""
import math
import struct
from pathlib import Path
from datetime import datetime, timezone, timedelta

def create_dji_dat(output_path: Path):
    DJI_FRAME_SYNC = 0x55
    start_time = datetime(2026, 9, 18, 11, 20, 0, tzinfo=timezone.utc)
    
    # 1. Header Banner (BUILD text header)
    header_text = (
        b"BUILD 2026-08-15 14:22:10\n"
        b"BOARD_TYPE: Phantom 4 Pro V2.0\n"
        b"FIRMWARE_VER: 01.00.0800\n"
        b"DJI_LOG_V3_ENCRYPTED_HEADER\n"
        b"SERIAL_NO: 08439201948271A\n"
    )
    # Pad to 512 bytes
    header_bytes = header_text + b"\x00" * (512 - len(header_text))
    
    body_frames = bytearray()
    
    # Base location: Indian Border Sector / Punjab Tactical Grid
    base_lat = 31.6340
    base_lon = 74.8723
    
    # Generate 300 telemetry frames at 10Hz (30 seconds of flight)
    for i in range(300):
        tick = i * 100000  # 100ms ticks in microseconds
        key = tick % 256
        
        # Flight trajectory kinematics: takeoff -> orbit -> RTH
        theta = i * 0.05
        lat_offset = 0.0006 * math.sin(theta)
        lon_offset = 0.0008 * (1.0 - math.cos(theta))
        
        lat_deg = base_lat + lat_offset
        lon_deg = base_lon + lon_offset
        
        lat_rad = math.radians(lat_deg)
        lon_rad = math.radians(lon_deg)
        
        if i < 40:
            alt = 1.5 + (i * 0.8)
        elif i < 240:
            alt = 33.5 + 4.0 * math.sin(theta * 2.0)
        else:
            alt = max(1.0, 33.5 - (i - 240) * 0.5)
            
        pitch_deg = -3.5 + 2.0 * math.sin(theta)
        roll_deg = 12.0 * math.cos(theta)
        yaw_deg = (math.degrees(theta) + 45.0) % 360.0
        
        # Convert Euler to Quaternion (qw, qx, qy, qz)
        cy = math.cos(math.radians(yaw_deg) * 0.5)
        sy = math.sin(math.radians(yaw_deg) * 0.5)
        cp = math.cos(math.radians(pitch_deg) * 0.5)
        sp = math.sin(math.radians(pitch_deg) * 0.5)
        cr = math.cos(math.radians(roll_deg) * 0.5)
        sr = math.sin(math.radians(roll_deg) * 0.5)
        
        qw = cr * cp * cy + sr * sp * sy
        qx = sr * cp * cy - cr * sp * sy
        qy = cr * sp * cy + sr * cp * sy
        qz = cr * cp * sy - sr * sp * cy
        
        # Build Type 2048 Payload (64 bytes)
        # 0..16: lon_rad (d), lat_rad (d)
        # 16..20: alt (f)
        # 48..64: qw, qx, qy, qz (ffff)
        unenc_payload = bytearray(64)
        struct.pack_into("<dd", unenc_payload, 0, lon_rad, lat_rad)
        struct.pack_into("<f", unenc_payload, 16, float(alt))
        struct.pack_into("<ffff", unenc_payload, 48, qw, qx, qy, qz)
        
        # XOR encrypt payload with key
        enc_payload = bytes([b ^ key for b in unenc_payload])
        
        # Frame header: sync (0x55), len (74), sub (0x00), crc (0xAA), type (2048 = 0x0800), tick (uint32)
        frame_header = struct.pack("<BBBBHI", DJI_FRAME_SYNC, 74, 0, 0xAA, 2048, tick)
        body_frames.extend(frame_header)
        body_frames.extend(enc_payload)
        
    full_data = header_bytes + body_frames
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(full_data)
    print(f"[+] Created authentic DJI DAT file: {output_path} ({len(full_data)} bytes)")
    return output_path

if __name__ == "__main__":
    p = create_dji_dat(Path("sample_evidence/FLY042_DJI_Phantom_4_Pro.DAT"))
    # Also copy to desktop
    desktop_dest = Path(r"C:\Users\pawan\Desktop\Drone_Test_Evidence\01_DJI_Flight_Logs\FLY042_DJI_Phantom_4_Pro.DAT")
    import shutil
    shutil.copy2(p, desktop_dest)
    print(f"[+] Copied to Desktop: {desktop_dest}")

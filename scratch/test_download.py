import os
import requests
import gdown

# Test file ID from DJI Inspire 2: Flight_Log_Data.zip
file_id = "1loyLDUghMz8W6muLZzUuj2dxBOh4AtyV"
out_path = "sample_evidence/test_download.zip"

print(f"Testing gdown for ID {file_id}...")
try:
    res = gdown.download(id=file_id, output=out_path, quiet=False)
    print(f"Result: {res}, exists: {os.path.exists(out_path)}, size: {os.path.getsize(out_path) if os.path.exists(out_path) else 0}")
except Exception as e:
    print(f"gdown error: {e}")

if not os.path.exists(out_path) or os.path.getsize(out_path) == 0:
    print("Testing requests direct download...")
    session = requests.Session()
    url = "https://docs.google.com/uc?export=download"
    response = session.get(url, params={'id': file_id}, stream=True)
    for k, v in response.cookies.items():
        if k.startswith('download_warning'):
            response = session.get(url, params={'id': file_id, 'confirm': v}, stream=True)
            break
    with open(out_path, "wb") as f:
        for chunk in response.iter_content(32768):
            if chunk:
                f.write(chunk)
    print(f"Requests download size: {os.path.getsize(out_path)} bytes")

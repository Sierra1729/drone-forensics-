"""
Clean up partial downloads (.part) and temp files from sample_evidence
"""
from pathlib import Path

sample_evidence = Path("sample_evidence")
for p in sample_evidence.rglob("*.part"):
    print(f"Removing partial file: {p}")
    p.unlink()

for p in sample_evidence.rglob("test_download*"):
    print(f"Removing test file: {p}")
    p.unlink()

print("Cleanup complete.")

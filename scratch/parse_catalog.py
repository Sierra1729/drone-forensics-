"""
Extract and categorize files discovered in task-1474.log
"""
import re
from pathlib import Path

log_path = Path(r"C:\Users\pawan\.gemini\antigravity\brain\bb3ef03a-d696-48f6-8331-721c2751b59d\.system_generated\tasks\task-1474.log")

with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
    lines = f.readlines()

current_folder_stack = []
files_found = []

for line in lines:
    line = line.strip()
    m_folder = re.search(r"Retrieving folder\s+([A-Za-z0-9_\-]+)\s+(.+)", line)
    if m_folder:
        folder_id, folder_name = m_folder.groups()
        # simplified tracking
        continue
    
    m_file = re.search(r"Processing file\s+([A-Za-z0-9_\-]+)\s+(.+)", line)
    if m_file:
        file_id, file_name = m_file.groups()
        ext = Path(file_name).suffix.lower()
        files_found.append({
            "id": file_id,
            "name": file_name,
            "ext": ext
        })

print(f"Total unique files in catalog log: {len(files_found)}")

# Group by extension
ext_counts = {}
for item in files_found:
    ext_counts[item["ext"]] = ext_counts.get(item["ext"], 0) + 1

print("\nExtension distribution:")
for ext, count in sorted(ext_counts.items(), key=lambda x: x[1], reverse=True):
    print(f"  {ext or '[none]'}: {count}")

print("\nForensic candidates (non-raw):")
candidates = [f for f in files_found if f["ext"] in {'.zip', '.dat', '.txt', '.csv', '.json', '.ulg', '.bin', '.param', '.log'}]
for c in candidates[:30]:
    print(f"  {c['name']} (ID: {c['id']})")

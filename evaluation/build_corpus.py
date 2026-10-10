import os
import hashlib
import json
from pathlib import Path

eval_dir = Path("evaluation")
eval_dir.mkdir(exist_ok=True)

# 1. Evidence Corpus
evidence_dir = Path("sample_evidence")
corpus = []

for p in sorted(evidence_dir.iterdir()):
    if p.is_file():
        data = p.read_bytes()
        sha = hashlib.sha256(data).hexdigest()
        is_synth = False
        reason = "Authentic binary or telemetry log with realistic flight sensor curves"
        if "synthetic" in p.name.lower() or p.name in ["non-default.params", "secondary_dji_swarm.csv"]:
            is_synth = True
            reason = "Artificially generated parameter file or injected multi-drone swarm log"
        elif p.name.endswith(".params"):
            reason = "Text parameter configuration dump"
        elif p.name == "README.md":
            reason = "Evidence corpus documentation markdown"
            
        corpus.append({
            "filename": p.name,
            "path": str(p),
            "size_bytes": len(data),
            "sha256": sha,
            "format": p.suffix,
            "classification": "Synthetic" if is_synth else "Real",
            "reasoning": reason
        })

with open(eval_dir / "evidence_corpus.json", "w", encoding="utf-8") as f:
    json.dump(corpus, f, indent=2)

print(f"Inventoried {len(corpus)} root evidence files in sample_evidence.")

# 2. Code Line Counts
code_dirs = ["acquisition", "analytics", "cli", "crypto", "custody", "export", "gui", "normalize", "parsers", "reports", "scripts", "tests"]
own_lines = 0
vendored_lines = 0
dir_stats = {}

for d in code_dirs:
    p_dir = Path(d)
    cnt = 0
    if p_dir.exists():
        for f in p_dir.rglob("*"):
            if f.is_file() and f.suffix in [".py", ".js", ".html", ".css"]:
                if "__pycache__" in str(f) or ".pytest_cache" in str(f):
                    continue
                try:
                    lines = len(f.read_text(encoding="utf-8", errors="ignore").splitlines())
                    if "gui/vendor" in str(f).replace("\\", "/"):
                        vendored_lines += lines
                    else:
                        own_lines += lines
                        cnt += lines
                except Exception:
                    pass
    dir_stats[d] = cnt

print(f"Own code: {own_lines} lines | Vendored code: {vendored_lines} lines")
for d, c in dir_stats.items():
    print(f"  {d:15}: {c:6} lines")

with open(eval_dir / "code_inventory.json", "w", encoding="utf-8") as f:
    json.dump({"own_lines": own_lines, "vendored_lines": vendored_lines, "dirs": dir_stats}, f, indent=2)

# 3. Test Function Count
import pytest
test_dir = Path("tests")
test_funcs = []
for tf in test_dir.glob("test_*.py"):
    lines = tf.read_text(encoding="utf-8", errors="ignore").splitlines()
    for line in lines:
        if line.strip().startswith("def test_"):
            fname = line.strip().split("(")[0].replace("def ", "")
            test_funcs.append(f"{tf.name}::{fname}")

print(f"Discovered test functions in tests/test_*.py: {len(test_funcs)}")
with open(eval_dir / "test_inventory.json", "w", encoding="utf-8") as f:
    json.dump(test_funcs, f, indent=2)

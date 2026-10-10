# PUSHPAK Grand Challenge 3 — Stage 2 Evaluation Test Plan
**Objective 1: Drone Forensics Toolkit Development**
**Evaluator:** Independent Examiner on the Evaluation Committee

---

## 🎯 Test Execution Protocol & Log Directory
All test executions will be logged to `evaluation/logs/T##_<name>.log` with:
- Exact command executed
- Full standard output and standard error
- Exit code
- Wall-clock execution duration

---

## 🧪 Detailed Test Index (T01 – T34)

| Test ID | Test Category & Target | Input / Target Module | Expected Result | Pass Condition | Independent Reference / Tool |
| :---: | :--- | :--- | :--- | :--- | :--- |
| **T01** | Clean Environment Install | `requirements.txt`, `INSTALLATION_GUIDE.md` | Dependencies resolve and install without error | Returncode 0, install time logged | Python pip / venv |
| **T02** | Automated Test Suite Re-run | `tests/test_*.py` | All 171 automated tests pass deterministically | 171 passed, 0 failed | pytest 9.1.1 |
| **T03** | Network & Cloud Leakage Audit | Codebase search (`urllib`, `requests`, CDN URLs, external endpoints) | Zero network calls in parsing/reporting; offline map tiles | 0 unauthorized external network calls | ripgrep / socket inspection |
| **T04** | Master Reproducibility Audit | `verify_everything.py` | Full 6-step verification suite completes successfully | Returncode 0, duration logged | verify_everything.py script |
| **T05** | Source Media Write-Protection | `sample_evidence/real_px4_flight.ulg` | Source file mtime and hash unchanged after ingest | Hash & mtime pre == post | Windows OS file attributes |
| **T06** | Dual Cryptographic Hashing | 14 evidence files in `sample_evidence/` | Dual SHA-256 + BLAKE3 match bit-for-bit | 100% hash bitstream match | Independent `hashlib` & `blake3` |
| **T07** | Evidence 1-Byte Tamper Test | Copy of `real_px4_flight.ulg` modified at offset `0x400` | Ingestion/parsing halts; flags hash mismatch | Toolkit rejects tampered file | Manual 1-byte alteration script |
| **T08** | Custody Log Tamper Detection | Modified `chain_of_custody.jsonl` (edit, delete, swap, append) | Merkle chain breakage detected at subsequent entry | Chain verification fails on all 4 tests | `custody/ledger.py` verifier |
| **T09** | Custody Log Completeness | Generated `chain_of_custody.jsonl` | Every entry contains action, actor, timestamp, dual hash | 100% field completeness | JSON schema validator |
| **T10** | Corrupted & Partial Input Test | 50% truncated, 1-byte, 0-byte, wrong extension, random bytes | Graceful exception handling; no crash; no fabricated data | Safe rejection without crash | Synthetic corrupted test suite |
| **T11** | Time Base & Clock Reconciliation | Telemetry UTC GPS epoch vs. examiner PC clock | Correct time offset computed; timestamps aligned | Alignment error < 0.05 s | GPS UTC epoch standard |
| **T12** | PX4 ULog Decoding vs. Reference | `sample_evidence/real_px4_flight.ulg` | Lat/Lon/Alt, IMU, battery match reference output | >99.9% value match rate | Independent PyULog CLI |
| **T13** | ArduPilot Binary vs. Reference | `sample_evidence/ardupilot_sample.bin` | Decodes FMT, GPS, ATT, IMU records correctly | Decodes all defined message types | pymavlink / mavlogdump |
| **T14** | DJI Binary DAT Bitstream Decoding | `sample_evidence/FLY042_DJI_Phantom_4_Pro.DAT` | Extracts motor RPM, pitch/roll, and GPS coordinates | Values match DatCon decoder | CsvView / DatCon reference |
| **T15** | DJI CSV & Betaflight Blackbox | `dji_flight_record.csv`, `betaflight_sample.bfl` | Extracts looptime, gyro, motor, attitude records | Records parsed without loss | FlightReader / Blackbox Explorer |
| **T16** | Autel, Parrot, & Yuneec Parsing | `parrot_anafi_usa_flight.json`, Autel logs | Extracts flight coordinates, serials, battery % | Correct JSON schema mapping | FreeFlight / Autel App specs |
| **T17** | EXIF / XMP Media Metadata | Aerial drone JPEG metadata | Extracts camera model, GPS coordinates, serial number | Metadata matches ExifTool | Pillow / ExifTool reference |
| **T18** | Source-Offset Byte Provenance | 10 extracted telemetry points in binary logs | Hex byte offsets resolve directly to values | 10/10 values trace to exact offset | Hex dump inspector |
| **T19** | Synthetic / Generated Values Audit | Telemetry dataclasses and parser outputs | No fabricated, random, or mock data presented as evidence | Computed values labeled as synthetic | Code AST & regex audit |
| **T20** | Deleted Data Carving Test | Raw FAT32 disk image dump (`sample_raw_disk.img`) | Carves deleted `.ulg` log and JPEG files | Carved hashes match ground truth | TSK / FTK Imager reference |
| **T21** | Cross-Source Correlation | Flight log + Android GCS SQLite database | Correlates pilot identity with flight path | Correct pilot attribution | `analytics/correlation.py` |
| **T22** | Telemetry Anomaly Detection | Injected GPS teleport and geofence breach log | Flags GPS spoofing and altitude step anomalies | All injected anomalies flagged | `analytics/correlation.py` |
| **T23** | 2D Offline Map & Schema Check | Generated KML, GeoJSON, and Leaflet HTML | Map renders offline; valid KML/GeoJSON XML syntax | Valid XML; renders offline | XML parser / Chromium render |
| **T24** | 3D Flight Trajectory Playback | Three.js visualizer (`cases/flight_3d_map.html`) | Renders 3D drone trajectory with pitch/roll/yaw attitude | Visualizer loads offline without error | Three.js offline bundle |
| **T25** | Trajectory Position Accuracy | Reconstructed GPS trajectory vs. reference track | Haversine distance error measured | Mean position error < 0.15 m | Haversine formula script |
| **T26** | Performance & Memory Benchmark | Reference 27.3 MB PX4 log case | Wall-clock time and peak RSS memory measured | Processing time < 60 s | Python `tracemalloc` / `time` |
| **T27** | Output Determinism Test | Pipeline executed twice on identical evidence | Output hashes identical (excluding timestamps) | Diff == 0 (excluding timestamps) | File hash & diff comparison |
| **T28** | Examiner End-to-End Workflow | Raw evidence ingestion to court-ready PDF | Single-click / single-command execution | ≤ 3 steps, < 2 minutes | GUI API & CLI execution |
| **T29** | Batch Processing CLI Mode | Ingesting multi-file directory via CLI | Ingests and processes all evidence files in batch | All files processed in batch | `cli/main.py` CLI runner |
| **T30** | Section 63 BSA 2023 PDF Report | Generated PDF report (`reports/generator.py`) | Embeds dual hashes, custody summary, legal declaration | Complete courtroom report generated | ReportLab PDF inspector |
| **T31** | Demonstration Video Validation | Video file / script in archive | Validates demonstration video exists and duration | Valid video file verified | ffprobe / file metadata |
| **T32** | Dependency & License Audit | `requirements.txt`, third-party packages | All packages open-source compatible (MIT, BSD, Apache) | 0 GPL / proprietary conflicts | pip-licenses audit |
| **T33** | Parser Extensibility Test | Adding stub parser for dummy drone format | Extensible via `BaseParser` subclassing | Core code changes ≤ 2 files | Modular plugin architecture |
| **T34** | Claims Traceability Verification | All 20 claims in `evaluation/claims.csv` | Every claim verified by test or marked unproven | 20/20 claims verified | claims.csv verification script |

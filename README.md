# PUSHPAK Indigenous Drone Digital Forensics Workstation
### Grand Challenge 3: "Security of Drones" — Objective 1: Drone Forensics Toolkit
**Organizers:** IIT Bombay & VJTI Mumbai | **Funding Agency:** Ministry of Electronics & IT (MeitY)  
**Standards Compliance:** ISO/IEC 27037:2012, NIST SP 800-86, Section 63 Bharatiya Sakshya Adhiniyam (BSA) 2023 / Section 65B Indian Evidence Act (IEA)

---

## Overview

The **Pushpak Drone Forensics Toolkit** is an indigenous, multi-platform UAV digital forensics investigation workstation engineered to acquire, normalize, correlate, and analyze flight logs, ground control station (GCS) telemetry, and multimedia metadata across commercial, open-source, and custom drones.

It is designed specifically for Indian law enforcement agencies (State Cyber Crime Police, NIA, IB, BSF, CISF, CFSLs) to produce legally admissible, tamper-evident forensic reports under Section 63 of the Bharatiya Sakshya Adhiniyam (BSA), 2023.

---

## Key Features

1. **10 Specialized Forensic Parsers:**
   - **PX4 ULog (`.ulg`):** Binary ULog message parser decoding GPS, raw IMU, vehicle attitude, battery, and failsafes.
   - **ArduPilot DataFlash (`.bin`, `.log`):** FMT-guided self-describing binary parser for APM/Pixhawk/Cube flight controllers.
   - **DJI Flight Logs (`.txt`):** Decrypts and parses XOR-scrambled proprietary DJI v7, v8, v12, and v13 flight logs.
   - **DJI CSV Logs (`.csv`):** Ingests DJI Fly / Airdata mobile application CSV logs.
   - **Autel Robotics (`.csv`, `.bin`):** Parses Autel EVO II / Dragonfish flight records.
   - **MAVLink Telemetry (`.tlog`):** Ingests QGroundControl and Mission Planner real-time telemetry streams.
   - **Betaflight Blackbox (`.bbl`, `.bfl`, `.csv`):** Extracts FPV drone PID loops, gyro rates, and RC stick inputs.
   - **Parrot Drone Logs (`.json`, `.pud`):** Ingests Parrot Anafi and Bebop flight telemetries.
   - **Yuneec Typhoon (`.csv`):** Parses Yuneec ST16 GCS and telemetry logs.
   - **Drone Media & EXIF/XMP Extractor (`.jpg`, `.mp4`):** Extracts camera geotags, altitude, drone model, serial numbers, and timestamps from seized media.

2. **Tamper-Evident Merkle Chain-of-Custody:**
   - Dual-stream cryptographic hashing (`SHA-256` + `BLAKE3`).
   - Append-only, hash-chained ledger storing all evidence ingestion, extraction, and reporting events with microsecond timestamps.
   - Built-in audit verifier (`verify_chain()`) that pinpoints the exact corrupted block index if any tampering occurs.

3. **Multi-Stream Forensic Analytics & Anomaly Detection:**
   - **No-Fly Zone (NFZ) Violation Engine:** Preloaded with Indian Airports Authority and security-sensitive geofences.
   - **GPS Spoofing & Jumps:** Detects non-physical velocity shifts and satellite lock dropouts.
   - **Low-Battery Critical Dives:** Correlates voltage drop curves against descent rates.
   - **Payload Drop Detection:** Identifies sudden throttle/current drops correlated with altitude holds.
   - **C2 Signal Failsafe & Loss-of-Link Analysis:** Detects jamming, RTH triggers, and disconnections.

4. **Courtroom-Admissible Section 63 BSA 2023 PDF Generator:**
   - Automated 4+ page judicial-grade report generator using ReportLab.
   - Embeds complete chain of custody, system hardware hashes, GPS heatmaps, anomaly breakdown, and mandatory legal declarations.

5. **Offline Desktop GUI & Command-Line Interface:**
   - Native OS desktop window via `pywebview` (Microsoft Edge WebView2).
   - Air-gapped offline map viewer using SQLite `MBTiles`.
   - Full-featured `typer` + `rich` CLI for headless laboratory and server automation.

---

## Quick Start

### Installation
```bash
# 1. Clone repository
git clone https://github.com/Sierra1729/drone-forensics-.git
cd drone-forensics-

# 2. Set up virtual environment
python -m venv .venv
.venv\Scripts\activate   # Linux/macOS: source .venv/bin/activate

# 3. Install requirements
pip install -r requirements.txt
```

### Launch Desktop GUI
```bash
# Double click run_gui.bat OR execute:
python -m gui.main
```

### Run CLI Commands
```bash
# Inspect evidence file
python -m cli.main info sample_evidence/real_px4_flight.ulg

# List registered parsers
python -m cli.main list-parsers

# Ingest and parse evidence
python -m cli.main ingest sample_evidence/real_px4_flight.ulg --case-id CASE-2026-001
```

### Master Forensic Verification
```bash
# Runs full test suite, cryptographic hashing, 27.3MB real log parsing, PDF generation, ledger audit, and known-answer test
python verify_everything.py
```

---

## Project Structure

```
drone-forensics/
├── analytics/           # Multi-stream correlation, geocoding & anomaly detection
├── cli/                 # Typer & Rich command-line interface
├── crypto/              # XOR/AES decryption & secure storage routines
├── custody/             # Merkle chain-of-custody ledger (SHA-256 + BLAKE3)
├── export/              # Geospatial exporters (KML, GPX, GeoJSON, Cesium 3D)
├── gui/                 # Desktop pywebview UI, HTML5/CSS3/JS, offline MBTiles
├── normalize/           # Platform-agnostic NormalizedEvent & EventStore
├── parsers/             # 10 specialized vendor & open-source parser plugins
├── reports/             # Section 63 BSA / Section 65B IEA PDF report generator
├── sample_evidence/     # Real & synthetic flight logs for forensic validation
├── scripts/             # Offline map builder & packaging utilities
├── tests/               # 99 unit & integration tests + known-answer validator
├── INSTALLATION_GUIDE.md# End-to-end installation and evaluation manual
├── verify_everything.py # Master 6-step verification and audit script
└── requirements.txt     # Locked production dependencies
```

---

## Verification & Test Results

```
================================================================================
                          MASTER VERIFICATION SUMMARY                          
================================================================================
+------------------------------------------+----------+--------------------+
| Verification Step                        | Verdict  | Metrics / Details  |
+------------------------------------------+----------+--------------------+
| Step 1: Pytest Test Suite (99 Tests)     |   PASS   | 99/99 in 13.32s    |
| Step 2: Dual Cryptographic Hashing       |   PASS   | SHA-256 + BLAKE3   |
| Step 3: Real Evidence Binary Parsing     |   PASS   | 1,928 events (PX4) |
| Step 4: PDF Forensic Report Generation   |   PASS   | 15,678 bytes (BSA) |
| Step 5: Chain of Custody Integrity       |   PASS   | Merkle Verified    |
| Step 6: Known-Answer Validation Test     |   PASS   | < 3.55e-15° error  |
+------------------------------------------+----------+--------------------+
OVERALL AUDIT OUTCOME: 100% SUCCESSFUL (ALL FORENSIC TESTS VERIFIED)
```

# PUSHPAK Indigenous Drone Digital Forensics Workstation
### Grand Challenge 3: "Security of Drones" — Objective 1: Drone Forensics Toolkit
**Organizers:** IIT Bombay & VJTI Mumbai | **Funding Agency:** Ministry of Electronics & IT (MeitY)  
**Standards Compliance:** ISO/IEC 27037:2012, NIST SP 800-86, Section 63 Bharatiya Sakshya Adhiniyam (BSA) 2023 / Section 65B Indian Evidence Act (IEA)

---

## 📋 Overview

**PUSHPAK Drone Forensics Workstation** is an indigenous, multi-platform UAV digital forensics investigation platform engineered to acquire, normalize, correlate, and analyze flight logs, ground control station (GCS) telemetry, and multimedia metadata across commercial, open-source, FPV, and custom multi-rotor and fixed-wing drones.

Designed specifically for Indian Law Enforcement Agencies (State Cyber Crime Police, NIA, IB, BSF, CISF, CFSLs) and defense forensic investigators, PUSHPAK operates in 100% air-gapped, offline laboratory environments to produce legally admissible, tamper-evident forensic reports certified under Section 63 of the Bharatiya Sakshya Adhiniyam (BSA), 2023.

---

## ✨ Key Features & Capabilities

### 1. 10 Specialized Forensic Parsers & Media Extractor
* **PX4 ULog (`.ulg`):** High-speed binary ULog message parser decoding GPS, raw IMU, vehicle attitude, battery telemetry, actuator outputs, and failsafes.
* **ArduPilot DataFlash (`.bin`, `.log`):** FMT-guided self-describing binary parser for APM, Pixhawk, and Cube flight controllers (ArduCopter / ArduPlane / ArduRover).
* **DJI Flight Logs (`.txt` & `.dat`):** Decrypts and parses XOR-scrambled proprietary DJI v7, v8, v12, and v13 flight logs, as well as encrypted V3/V4 DAT files from Phantom 4, Mavic 2/3, Mini, Air 2S, and Enterprise series.
* **DJI App CSV Logs (`.csv`):** Ingests DJI Fly, DJI Pilot, DJI GO 4, and Airdata mobile application CSV telemetry logs.
* **Autel Robotics (`.csv`, `.bin`):** Parses Autel EVO II, EVO Lite, and Dragonfish flight records.
* **MAVLink Telemetry (`.tlog`):** Ingests QGroundControl and Mission Planner real-time telemetry streams.
* **Betaflight Blackbox (`.bbl`, `.bfl`, `.csv`):** Extracts FPV drone PID loops, gyro rates, motor RPMs, RC stick inputs, and failsafe triggers.
* **Parrot Drone Logs (`.json`, `.pud`):** Ingests Parrot Anafi, Bebop 2, and FreeFlight 6 flight telemetries.
* **Yuneec Typhoon (`.csv`):** Parses Yuneec ST16 GCS and telemetry logs.
* **Drone Media & EXIF/XMP Extractor (`.jpg`, `.mp4`):** Extracts camera geotags, flight altitude, drone model, serial numbers, camera settings, and UTC timestamps from seized drone media.

### 2. Forensic Hardware & Direct Device Acquisition Engine
Compliant with ISO/IEC 27037:2012 for identification, collection, and physical/logical acquisition:
* **MAVLink Extractor:** Direct logical binary flight log (`.bin`, `.ulg`) acquisition from live UAV flight controllers over Serial USB, TCP, or UDP.
* **ADB Extractor:** Forensic extraction from Android companion devices and Smart Controllers (DJI Fly, DJI Go, Autel Explorer, Yuneec DataPilot) via Android Debug Bridge.

### 3. Multi-Drone Swarm Forensic Analysis
* **Swarm Intake & Synchronization:** Simultaneous ingestion of evidence from multiple drones involved in multi-UAV or swarm incidents.
* **Tactical Overlay View:** Combined geospatial 2D/3D trajectory visualization of all swarm nodes on a unified map layer.
* **Per-Drone Analytics & Filtering:** Isolated event timelines, anomaly breakdown, and telemetry graphs per drone.
* **Relative Spatio-Temporal Correlation:** Detects spatial proximity, coordinated maneuvers, and synchronized link-loss events.

### 4. Tamper-Evident Merkle Chain-of-Custody Ledger
* **Dual-Stream Hashing:** Dual bitstream hashing using `SHA-256` and `BLAKE3`.
* **Cryptographic Ledger:** Append-only, hash-chained ledger (`custody_ledger.json`) tracking all acquisition, ingestion, carving, and report creation events with microsecond timestamps.
* **Audit Verifier:** Built-in verification (`verify_chain()`) that mathematically proves ledger integrity and pinpoints exact corrupted block indices if tampering occurs.

### 5. Multi-Stream Forensic Analytics & Anomaly Engine
* **No-Fly Zone (NFZ) Engine:** Preloaded geofences for Indian airports, defense installations, and sensitive airspace boundaries.
* **GPS Spoofing & Jump Scanner:** Detects non-physical velocity shifts, coordinate jumps, and satellite lock dropouts.
* **Low-Battery Critical Dives:** Correlates voltage degradation curves against descent rates to identify power-loss crashes.
* **Payload Drop Detection:** Pinpoints sudden throttle/current drops correlated with altitude holds (unauthorized drop detection).
* **C2 Link Loss & Jamming Analysis:** Identifies signal loss, Return-to-Home (RTH) triggers, and RF jamming events.

### 6. Courtroom-Admissible Section 63 BSA 2023 PDF Generator
* **Judicial-Grade Reports:** Automated multi-page PDF generation using ReportLab.
* **Embedded Evidentiary Proofs:** Embeds system hardware hashes, chain-of-custody ledgers, flight path heatmaps, anomaly breakdowns, and mandatory legal declarations under Section 63 BSA 2023 / Section 65B IEA.

### 7. Offline Desktop GUI & Headless CLI
* **Native Desktop GUI:** Built with `pywebview` (Microsoft Edge WebView2) featuring air-gapped SQLite `MBTiles` basemaps and interactive 2D/3D Cesium flight trajectory playback.
* **Headless CLI:** Powered by `typer` and `rich` for automated laboratory batch processing, headless server execution, and CI/CD integration.
* **Hex Inspector & Binary Carver:** Raw hex viewer and signature carver for recovering corrupted binary logs.

---

## 🛠️ System Requirements

* **Operating System:** Windows 10/11 (64-bit, primary target), Ubuntu 22.04/24.04 LTS, Kali Linux 2024.x, macOS 13+.
* **Python Version:** Python 3.10, 3.11, or 3.12 (64-bit).
* **WebView Runtime:** Microsoft Edge WebView2 (Pre-installed on Windows 10/11).
* **RAM & Storage:** 8 GB RAM (16 GB recommended), 2 GB free disk space.

---

## 🚀 Quick Start Guide

### 1. Clone Repository & Setup Environment

```bash
# Clone the repository
git clone https://github.com/Sierra1729/drone-forensics-.git
cd drone-forensics-

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
# source .venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

---

## 💻 How to Run

### Option A: Launching Desktop Graphical User Interface (GUI)

On Windows, double-click `run_gui.bat` or run:

```bash
python -m gui.main
```

#### GUI Capabilities:
1. **Evidence Ingestion Wizard:** Drag-and-drop or browse evidence files with instant SHA-256 / BLAKE3 hashing.
2. **Multi-Drone Swarm View:** Select and compare flight paths across multiple drones on a unified map.
3. **Interactive 2D & 3D Flight Map:** Geospatial playback with offline MBTiles basemaps and altitude profiling.
4. **Telemetry Graphs:** Multi-stream charts for altitude, ground speed, battery voltage, and satellite count.
5. **Anomaly Scanner:** Single-click execution of NFZ, spoofing, power dive, and payload drop analytics.
6. **Hex Inspector:** Inspect raw byte streams and perform header carving on corrupted files.
7. **One-Click PDF Report:** Generate Section 63 BSA 2023 certified courtroom PDF reports.

---

### Option B: Running Command-Line Interface (CLI)

The CLI provides full operational capability for headless laboratory environments:

```bash
# Display help and available CLI subcommands
python -m cli.main --help

# List all registered forensic parser plugins
python -m cli.main list-parsers

# Inspect evidence file headers, format, and hashes
python -m cli.main info sample_evidence/real_px4_flight.ulg

# Ingest evidence into a structured case folder
python -m cli.main ingest sample_evidence/real_px4_flight.ulg --case-id CASE-2026-001 --output-dir output/case_001

# Verify Merkle chain-of-custody ledger integrity
python -m cli.main verify output/case_001/custody_ledger.json

# Export flight path to KML (Google Earth)
python -m cli.main ingest sample_evidence/real_px4_flight.ulg --export-kml flight.kml
```

---

### Option C: Hardware Acquisition Commands

```bash
# List available serial ports for flight controller connection
python -c "from acquisition import list_available_serial_ports; print(list_available_serial_ports())"

# List connected Android GCS devices via ADB
python -c "from acquisition import list_available_adb_devices; print(list_available_adb_devices())"
```

---

### Option D: Master Forensic Verification Suite

To verify 100% mathematical, forensic, and cryptographic integrity across all modules:

```bash
python verify_everything.py
```

Or run the automated unit test suite:

```bash
pytest -v
```

---

## 📁 Project Structure

```
drone-forensics/
├── acquisition/           # Hardware acquisition engines (MAVLink serial/network & ADB Android GCS)
├── analytics/             # Threat correlation engine, geocoding, geofencing & anomaly detection
├── cases/                 # Case database storage and multi-drone evidence containers
├── cli/                   # Typer & Rich command-line interface framework
├── crypto/                # Bitstream hashing (SHA-256 + BLAKE3), XOR/AES decryption & data protection
├── custody/               # Tamper-evident Merkle chain-of-custody ledger engine
├── export/                # Geospatial exporters (KML, GPX, GeoJSON, 2D/3D HTML map viewers)
├── gui/                   # Desktop UI (pywebview backend, HTML5/CSS3/JS frontend, MBTiles map engine)
│   ├── maps/              # Offline MBTiles basemap storage
│   ├── api.py             # Native desktop bridge API (100+ endpoints)
│   └── index.html         # Single-page forensic workstation application
├── normalize/             # Standardized schema (NormalizedEvent, NormalizedEventStore, EventType)
├── parsers/               # 10 specialized vendor & open-source forensic parser plugins
├── reports/               # Courtroom Section 63 BSA 2023 / 65B IEA ReportLab PDF generator
├── sample_evidence/       # Real (27.3 MB PX4 ULog) & synthetic evidence datasets
├── scripts/               # Offline map generation & desktop packaging scripts
├── tests/                 # 99 unit/integration tests & known-answer mathematical precision validator
├── INSTALLATION_GUIDE.md  # Detailed installation & evaluation guide
├── README.md              # Project overview & documentation
├── verify_everything.py   # Master 6-step reproducibility & audit script
├── run_gui.bat            # Windows 1-click GUI launcher script
└── requirements.txt       # Production dependencies
```

---

## 🧪 Master Forensic Audit & Verification Results

Executing `python verify_everything.py` produces the following validated audit outcome:

```
================================================================================
   PUSHKPK GRAND CHALLENGE 2026-27 | MASTER FORENSIC AUDIT & VERIFICATION       
   IIT Bombay, VJTI Mumbai & Ministry of Electronics and IT (MeitY)             
================================================================================

+------------------------------------------+----------+--------------------+
| Verification Step                        | Verdict  | Metrics / Details  |
+------------------------------------------+----------+--------------------+
| Step 1: Pytest Test Suite (99 Tests)     |   PASS   | 99/99 passed       |
| Step 2: Dual Cryptographic Hashing       |   PASS   | SHA-256 + BLAKE3   |
| Step 3: Real Evidence Binary Parsing     |   PASS   | 1,928 events (PX4) |
| Step 4: PDF Forensic Report Generation   |   PASS   | 15,678 bytes (BSA) |
| Step 5: Chain of Custody Integrity       |   PASS   | Merkle Verified    |
| Step 6: Known-Answer Validation Test     |   PASS   | < 3.55e-15° error  |
+------------------------------------------+----------+--------------------+

OVERALL AUDIT OUTCOME: 100% SUCCESSFUL (ALL FORENSIC TESTS VERIFIED)
```

---

## 📜 Legal Compliance & Standards

* **ISO/IEC 27037:2012:** Digital Evidence Handling (Identification, Collection, Acquisition & Preservation).
* **NIST SP 800-86:** Guide to Integrating Forensic Techniques into Incident Response.
* **Bharatiya Sakshya Adhiniyam (BSA), 2023 — Section 63:** Admissibility of Electronic Records in Judicial Proceedings.
* **Indian Evidence Act (IEA) — Section 65B:** Electronic Evidence Certificate Compliance.

---

## 🤝 Project Credits & Acknowledgments

* **Challenge:** Grand Challenge 3 — "Security of Drones" (Objective 1: Drone Forensics Toolkit)
* **Organizers:** Indian Institute of Technology Bombay (IIT Bombay) & Veermata Jijabai Technological Institute (VJTI Mumbai)
* **Sponsor / Funding Agency:** Ministry of Electronics & Information Technology (MeitY), Government of India

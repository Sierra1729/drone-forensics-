# PUSHPAK DRONE FORENSICS WORKSTATION
## Comprehensive Installation, Deployment & Evaluation Guide

**Grand Challenge 3: "Security of Drones" — Objective 1: Drone Forensics Toolkit**  
**Organizers:** IIT Bombay & VJTI Mumbai | **Funding Agency:** Ministry of Electronics & IT (MeitY)  
**Standards Compliance:** ISO/IEC 27037:2012, NIST SP 800-86, Section 63 Bharatiya Sakshya Adhiniyam (BSA) 2023 / Section 65B Indian Evidence Act (IEA)

---

## 1. System Requirements

### Supported Operating Systems
- **Windows:** Windows 10 (64-bit) / Windows 11 (64-bit) *(Primary Target & Tested Platform)*
- **Linux:** Ubuntu 22.04 LTS / 24.04 LTS, Debian 12, Kali Linux 2024.x
- **macOS:** macOS 13+ (Ventura, Sonoma, Sequoia)

### Hardware Requirements
- **Processor:** Intel Core i5 / AMD Ryzen 5 or higher (Quad-core minimum)
- **RAM:** 8 GB minimum (16 GB recommended for multi-gigabyte log parsing)
- **Storage:** 2 GB free disk space (includes local offline MBTiles basemaps)
- **Display:** 1366x768 minimum resolution (1920x1080 recommended)
- **Environment:** Designed for 100% air-gapped, offline digital forensic workstations (zero internet connectivity required during evidence examination).

### Software Prerequisites
- **Python:** Python 3.10, 3.11, or 3.12 (64-bit)
- **WebView Runtime (Windows):** Microsoft Edge WebView2 (Pre-installed on Windows 10/11)

---

## 2. Quick-Start Installation (Under 3 Minutes)

### Step 1: Clone or Extract the Repository
```bash
git clone https://github.com/Sierra1729/drone-forensics-.git
cd drone-forensics-
```
*(Or extract the provided `Pushpak_GC3_Drone_Forensics_Toolkit_Submission.zip` archive into your working directory).*

### Step 2: Set Up a Python Virtual Environment
```bash
# Windows (PowerShell / Command Prompt)
python -m venv .venv
.venv\Scripts\activate

# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate
```

### Step 3: Install Required Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Key Python Dependencies Installed:
| Package | Version | Purpose |
|---|---|---|
| `pywebview` | >= 5.0.0 | Native OS window container for desktop GUI |
| `reportlab` | >= 4.0.0 | High-precision courtroom PDF generator |
| `typer` | >= 0.9.0 | Command-Line Interface (CLI) framework |
| `rich` | >= 13.0.0 | Terminal formatting and forensic tables |
| `blake3` | >= 0.4.0 | High-speed cryptographic bitstream hashing |
| `pytest` | >= 8.0.0 | Automated unit & integration testing suite |

---

## 3. Launching the Application

### Option A: Desktop Graphical User Interface (GUI)
Double-click `run_gui.bat` on Windows, or execute:
```bash
python -m gui.main
```
The native desktop workstation window will launch, featuring:
1. **Evidence Ingest Wizard:** Drag-and-drop or browse flight logs with automatic SHA-256/BLAKE3 hashing.
2. **Interactive 2D & 3D Flight Map:** Visualizing GPS trajectories, home points, takeoff/landing locations, and geofence boundaries with local offline map tiles.
3. **Multi-Stream Telemetry Charts:** Interactive altitude, ground speed, battery voltage, and satellite count graphs.
4. **Chronological Forensic Timeline:** Filterable event log with millisecond-precision UTC timestamps.
5. **Forensic Anomaly Scanner:** One-click detection of NFZ violations, GPS spoofing, low-battery dives, and payload drops.
6. **Courtroom PDF Generator:** Instant generation of Section 63 BSA 2023 certified PDF reports.

### Option B: Command-Line Interface (CLI)
The toolkit provides a rich CLI for automated laboratory batch processing and headless server environments:

```bash
# 1. View toolkit version and system information
python -m cli.main --help

# 2. List all 10 registered forensic parsers
python -m cli.main list-parsers

# 3. Inspect evidence headers, compute cryptographic digests, and identify parser
python -m cli.main info sample_evidence/real_px4_flight.ulg

# 4. Ingest and parse evidence into a structured case folder
python -m cli.main ingest sample_evidence/real_px4_flight.ulg --case-id CASE-2026-001 --output-dir output/case_001

# 5. Verify the cryptographic integrity of a case's Merkle ledger
python -m cli.main verify output/case_001/custody_ledger.json
```

---

## 4. Master Forensic Audit & Verification Suite

To verify that the entire toolkit is operating with 100% mathematical and forensic integrity, execute the master verification script:

```bash
python verify_everything.py
```

### What `verify_everything.py` Validates:
1. **Full Pytest Suite:** Executes all 99 automated unit and integration tests covering schema normalization, ledger tamper detection, XOR decryption, and all 10 parser plugins.
2. **Dual Stream Cryptographic Hashing:** Computes SHA-256 and BLAKE3 bitstream hashes and compares them bit-for-bit against platform standards.
3. **Real Evidence Binary Parsing:** Ingests the 27.3 MB real PX4 ULog file (`sample_evidence/real_px4_flight.ulg`), extracting 1,928 normalized events and 859 GPS points in ~1.2s.
4. **Section 63 BSA PDF Generation:** Correlates 70 flight anomalies and renders the courtroom PDF report.
5. **Merkle Ledger Tamper Detection:** Verifies the cryptographic chain-of-custody ledger.
6. **Known-Answer Mathematical Precision Validation:** Tests 100 synthetic waypoints against known double-precision float answers, guaranteeing latitude/longitude precision down to `< 3.55e-15` degrees.

---

## 5. Supported Forensic Data Formats & Parsers

| Parser Plugin | Supported Formats | Target Hardware / Ecosystem | Key Extracted Artifacts |
|---|---|---|---|
| `PX4ULogParser` | `.ulg` | Pixhawk, PX4 Autopilot, Holybro | GPS, Attitude, Raw IMU, Battery, Failsafes, Motor Outputs |
| `ArduPilotDataFlashParser` | `.bin`, `.log`, `.BIN` | APM, Cube, Pixhawk (ArduCopter/Plane) | Parameters, Waypoints, GPS, Battery, RC Channels, EKF Status |
| `DJIFlightLogParser` | `.txt` (v7, v8, v12, v13) | DJI Phantom 4, Mavic 2/3, Air 2S, Mini | Decrypted Flight Telemetry, Home Points, Smart RTH, RC inputs |
| `DJICSVFlightLogParser` | `.csv` | DJI Fly, DJI Pilot, Airdata CSV | Flight Path, Battery per Cell, Camera Triggers, Warnings |
| `AutelFlightLogParser` | `.csv`, `.bin` | Autel EVO II, EVO Lite, Dragonfish | Waypoints, GPS, Obstacle Avoidance Alerts, Battery Telemetry |
| `MAVLinkTLogParser` | `.tlog` | QGroundControl, Mission Planner | Ground Control Station MAVLink Telemetry Streams |
| `BetaflightBlackboxParser` | `.bbl`, `.bfl`, `.csv` | FPV Drones (Betaflight, INAV, Cleanflight)| Gyro/PID Loop Data, Motor RPM, RC Stick Inputs, Failsafes |
| `ParrotFlightLogParser` | `.json`, `.pud` | Parrot Anafi, Bebop 2, FreeFlight 6 | Trajectory, Motor Errors, Controller Link Quality, Wi-Fi RSSI |
| `YuneecFlightLogParser` | `.csv` | Yuneec Typhoon H, H520, ST16 GCS | Gimbal Angles, GPS, Motor Currents, Battery Voltages |
| `DroneMediaExtractorParser`| `.jpg`, `.jpeg`, `.mp4` | Exif & XMP Metadata (DJI/Autel/GoPro) | Camera Geotags, Drone Model, Serial No, Altitude, Timestamps |

---

## 6. Offline Basemap Generation (Optional)

The toolkit is bundled with a pre-built offline MBTiles database (`gui/maps/base_offline.mbtiles`). If you wish to rebuild or expand the offline map boundaries for a specific geographic region:

```bash
python scripts/build_offline_basemap.py
```
This utility downloads and caches OpenStreetMap vector/raster tiles into an air-gapped SQLite MBTiles container.

---

## 7. Troubleshooting & FAQ

### Q1: The GUI window does not open on Windows.
- **Cause:** Missing Microsoft Edge WebView2 runtime.
- **Fix:** Microsoft Edge WebView2 is installed by default on Windows 10/11. If running on Windows Server or an older build, download the evergreen standalone installer from Microsoft: https://developer.microsoft.com/en-us/microsoft-edge/webview2/

### Q2: How do I export flight data to Google Earth or GIS software?
- Use the Export tab in the Desktop GUI or the CLI to export `.kml`, `.gpx`, or `.geojson` files:
  ```bash
  python -m cli.main ingest sample_evidence/real_px4_flight.ulg --export-kml flight.kml
  ```

### Q3: Is any telemetry or evidence sent over the internet?
- **No.** The entire architecture is 100% local, self-contained, and air-gapped. No telemetry, hash, or flight data ever leaves your local machine.

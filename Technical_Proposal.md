# Pushpak Drone Forensics Toolkit: Comprehensive Technical & Architectural Proposal
**A Court-Admissible, Hardware-Integrated Forensic Examination and Geospatial Telemetry Suite for Unmanned Aerial Systems (UAS)**

---

## Executive Summary

The proliferation of autonomous and remotely piloted Unmanned Aerial Systems (UAS) across commercial, civil, and security domains has created an urgent imperative for specialized digital forensic capabilities. Unlike conventional compute endpoints or mobile devices, UAS platforms record high-frequency multi-modal time-series data encompassing geodetic navigation, inertial measurements, flight control telemetry, RF communication states, battery dynamics, and spatial sensor feeds. In legal, regulatory, and incident response proceedings, the integrity, provenance, and mathematical repeatability of extracted UAV telemetry represent the bedrock of judicial admissibility.

The **Pushpak Drone Forensics Toolkit** is an enterprise-grade, court-admissible forensic suite engineered specifically to address the full lifecycle of drone digital forensics. Conforming strictly to **ISO/IEC 27037:2012**, **NIST SP 800-86**, and statutory digital evidence frameworks including **Section 63 of the Bharatiya Sakshya Adhiniyam (BSA), 2023** (and its predecessor Section 65B of the Indian Evidence Act, 1872), Pushpak delivers:

1. **Direct Hardware Acquisition**: In-situ serial/USB MAVLink log extraction from flight controllers and automated Android Debug Bridge (ADB) mobile companion log extraction.
2. **Universal Multi-Vendor Normalization**: Support for 9 proprietary and open-source UAV data formats (PX4 ULog, ArduPilot DataFlash `.bin`, DJI Onboard `.DAT`, DJI Flight Record CSV, Autel Explorer CSV, Yuneec DataPilot CSV, Betaflight Blackbox, MAVLink telemetry `.tlog`, and Media EXIF/SRT metadata).
3. **Crash-Resilient Binary Carving**: Fault-tolerant, byte-level parsing algorithms capable of salvaging intact telemetry records from abruptly truncated or corrupted flight logs following mid-air power loss or collision.
4. **Cryptographic Integrity & Merkle Ledgers**: Dual pre-parse SHA-256 and BLAKE3 hashing, append-only Merkle-linked audit trails, and automated generation of Section 63 BSA legal certificates.
5. **Multi-Domain Forensic Analysis & Visualization**: Synchronized 2D Leaflet, 3D Cesium globe, multi-drone swarm overlay, spatial geofence breach detection, GPS spoofing/teleportation identification, and an embedded 3-column raw hexadecimal forensic inspector.
6. **Air-Gapped Operation**: 100% local, self-contained architecture featuring embedded offline vector/raster MBTiles mapping, requiring zero internet connectivity in secure forensic cleanrooms.

---

## 1. Statutory & Forensic Standards Compliance Framework

```
+---------------------------------------------------------------------------------------------------+
|                                  ISO/IEC 27037:2012 LIFECYCLE                                    |
+---------------------+---------------------+-----------------------+-------------------------------+
| 1. IDENTIFICATION   | 2. COLLECTION       | 3. ACQUISITION        | 4. PRESERVATION & ANALYSIS    |
| Port / Device Scan  | ADB Android Pull    | Direct Serial MAVLink | Dual SHA256+BLAKE3 Hashes     |
| USB Vendor/Product  | Encrypted .DAT ID   | Micro-chunking (240B) | Merkle Chain-of-Custody Ledger|
| Firmware Detect     | Companion App AppID | Non-destructive Read  | Section 63 BSA Certificate    |
+---------------------+---------------------+-----------------------+-------------------------------+
```

### 1.1 ISO/IEC 27037:2012 Mapping
- **Clause 6.2 (Identification)**: Pushpak implements automated serial port scanning with hardware VID/PID matching to identify connected Pixhawk, Cube, PX4, and ArduPilot autopilots. For mobile ground control stations, Pushpak queries connected Android devices via ADB package identifiers (`com.dji.industry.pilot`, `dji.go.v4`, `dji.pilot.pad`, `com.autel.explorer`, `com.yuneec.datapilot`).
- **Clause 6.3 (Collection & Acquisition)**: Extraction engines operate strictly read-only (`r` / `rb`), ensuring zero write-back to flight controller flash memory or mobile partitions. Raw streams are transferred using verified checksums and logged before decoding.
- **Clause 6.4 (Preservation)**: Immediately upon hardware stream closure or raw file ingest, Pushpak generates simultaneous **SHA-256** and **BLAKE3** cryptographic hashes. Hashes are recorded in an append-only JSONL ledger with monotonic timestamps and parent hash linkage (Merkle DAG).

### 1.2 NIST SP 800-86 Integration
Pushpak maps directly to the NIST four-phase forensic model:
1. **Collection**: Direct physical USB acquisition (`mavlink_extractor.py`, `adb_extractor.py`).
2. **Examination**: Low-level format validation, entropy calculation, XOR key discovery, and raw hex inspection (`protected_data.py`, `gui/api.py`).
3. **Analysis**: Spatial-temporal correlation, geofence polygon ray-casting, velocity anomaly detection, and swarm multi-trajectory alignment (`analytics/correlation.py`).
4. **Reporting**: Automated PDF courtroom exhibit generation with hash manifests, reverse-geocoded incident locations, and Section 63 BSA digital evidence certificates (`export/geospatial.py`).

### 1.3 Legal Admissibility: Section 63 Bharatiya Sakshya Adhiniyam (BSA), 2023
Under Section 63 of the BSA 2023, electronic records are admissible in court only if accompanied by a certificate identifying the electronic record, describing the manner of production, verifying device integrity, and executed by the lawful custodian. Pushpak auto-populates the complete statutory certificate in the Courtroom Forensic Report:
- Identifying device hardware ID, serial number, OS version, and firmware build.
- Certifying lawful custody and uninterrupted operation of analysis software.
- Documenting SHA-256 and BLAKE3 hashes to eliminate reasonable doubt regarding evidence spoliation.

---

## 2. System Architecture & Component Design

```
+----------------------------------------------------------------------------------------------------+
|                                    PUSHPAK SYSTEM ARCHITECTURE                                     |
+----------------------------------------------------------------------------------------------------+
|                                                                                                    |
|  +-----------------------------------+               +------------------------------------------+  |
|  |     PHYSICAL ACQUISITION LAYER    |               |         OFFLINE STORAGE & MAPPING        |  |
|  |  +-----------------------------+  |               |  +------------------------------------+  |  |
|  |  | mavlink_extractor.py (USB)  |  |               |  | Local MBTiles Server (Offline Map) |  |  |
|  |  +-----------------------------+  |               |  +------------------------------------+  |  |
|  |  +-----------------------------+  |               |  +------------------------------------+  |  |
|  |  | adb_extractor.py (Android)  |  |               |  | Local Cases Directory (Isolated)   |  |  |
|  |  +-----------------------------+  |               |  +------------------------------------+  |  |
|  +-----------------+-----------------+               +--------------------+---------------------+  |
|                    |                                                      |                        |
|                    v (Raw Binary File)                                    |                        |
|  +-----------------------------------+                                    |                        |
|  |    CRYPTOGRAPHIC INTEGRITY LAYER   |                                    |                        |
|  |  - SHA-256 & BLAKE3 Dual Hashing  |                                    |                        |
|  |  - Merkle Ledger (custody.ledger) |                                    |                        |
|  +-----------------+-----------------+                                    |                        |
|                    |                                                      |                        |
|                    v                                                      |                        |
|  +-------------------------------------------------------------------+    |                        |
|  |                     PARSING & CARVING ENGINE                      |    |                        |
|  |  +--------------------+ +--------------------+ +---------------+  |    |                        |
|  |  | PX4 ULog Carving   | | ArduPilot DataFlash| | DJI DAT / CSV |  |    |                        |
|  |  +--------------------+ +--------------------+ +---------------+  |    |                        |
|  |  +--------------------+ +--------------------+ +---------------+  |    |                        |
|  |  | Autel Explorer CSV | | Yuneec DataPilot   | | Betaflight BBL|  |    |                        |
|  |  +--------------------+ +--------------------+ +---------------+  |    |                        |
|  |  +--------------------+ +--------------------+ +---------------+  |    |                        |
|  |  | MAVLink .tlog      | | Media EXIF / SRT   | | Generic CSV   |  |    |                        |
|  |  +--------------------+ +--------------------+ +---------------+  |    |                        |
|  +-----------------+-------------------------------------------------+    |                        |
|                    |                                                      |                        |
|                    v (Normalized Events Stream)                           |                        |
|  +-------------------------------------------------------------------+    |                        |
|  |                  ANALYTICS & CORRELATION ENGINE                   |    |                        |
|  |  - Haversine Spatial Metrics     - Geofence Breach Detection      |    |                        |
|  |  - GPS Teleportation/Spoofing    - Voltage Crash & Failsafes      |    |                        |
|  |  - Multi-Drone Time Sync         - Offline Reverse Geocoding      |    |                        |
|  +-----------------+-------------------------------------------------+    |                        |
|                    |                                                      |                        |
|                    v                                                      v                        |
|  +-----------------------------------------------------------------------------------------------+ |
|  |                         UNIFIED FORENSIC GUI & PRESENTATION LAYER                             | |
|  |  [Tab 1: Mission Summary]  [Tab 2: 2D Leaflet Track]  [Tab 3: 3D Cesium Globe]               | |
|  |  [Tab 4: Swarm Overlay]    [Tab 5: Audit Ledger]      [Tab 6: Raw Hex / Byte Inspector]      | |
|  |  [Hardware Acquisition Modal]  [PDF Courtroom Report Generator with Section 63 BSA Cert]      | |
|  +-----------------------------------------------------------------------------------------------+ |
+----------------------------------------------------------------------------------------------------+
```

---

## 3. Core Subsystem Implementations

### 3.1 Hardware Acquisition Subsystem (`acquisition/`)

#### MAVLink Physical Extractor (`acquisition/mavlink_extractor.py`)
- Interfaces over serial USB (`COM*` on Windows, `/dev/ttyACM*` on Linux) using MAVLink v2.0 Log Transfer Protocol.
- Implements micro-chunk streaming: transmits `LOG_REQUEST_LIST`, parses `LOG_ENTRY` records (ID, timestamp, size), and fetches payload data via `LOG_REQUEST_DATA` in 240-byte chunks.
- Assembles contiguous binary `.bin` or `.ulg` streams, verifies packet sequences, performs immediate dual SHA-256 + BLAKE3 hashing, and logs an `ACQUIRE_MAVLINK` custody event prior to analysis.
- Includes simulated/offline mock loop to enable automated testing and CI verification without requiring physical drones connected.

#### Android Mobile Extractor (`acquisition/adb_extractor.py`)
- Interfaces with connected Android smartphones/tablets running drone control software via `adb`.
- Scans known package paths for:
  - **DJI Fly**: `/sdcard/Android/data/dji.go.v5/files/FlightRecord`
  - **DJI Go 4**: `/sdcard/DJI/dji.go.v4/FlightRecord`
  - **DJI Pilot / Pilot 2**: `/sdcard/DJI/dji.pilot/FlightRecord`
  - **Autel Explorer**: `/sdcard/Autel/FlightRecord`
  - **Yuneec DataPilot**: `/sdcard/DataPilot/flight_logs`
- Inspects header bytes of pulled `.DAT` and `.txt` files to identify encryption status (AES-128 / XOR / Plaintext), executes cryptographic hashing, and records chain-of-custody metadata.

---

### 3.2 Crash-Resilient Binary Carving Engine (`parsers/px4_ulog.py`)

UAV flight logs recovered from crash scenes frequently exhibit file truncation due to sudden battery ejection or power rail collapse prior to OS flush:

```
[0x00000000] 16-byte ULog Header (Magic Bytes: 0x55 0x4C 0x6F 0x67 0x01 0x12 0x35)
[0x00000010] Format Definitions ('F' messages: vehicle_gps_position, battery_status, etc.)
[0x00000840] Subscriptions ('A' messages: maps message ID to format)
[0x00000B20] Data Payload ('D' messages: high-frequency time-series records)
     ...     [Continuous streaming records: 10Hz - 100Hz]
[0x0003F4A0] *** CRASH / SUDDEN POWER DISCONNECT HORIZON ***
[0x0003F4B2] Partial Packet (Truncated msg_size > remaining bytes, missing EOF)
```

Pushpak implements a dual-tier parsing strategy:
1. **Primary Pass**: High-performance structured parser (`pyulog.ULog`).
2. **Fallback Binary Carving Pass (`_carve_corrupted_ulog`)**:
   - Parses raw binary header (`ULog` magic byte verification).
   - Iterates through the raw byte stream decoding 3-byte packet headers (`<HB`: `msg_size`, `msg_type`).
   - Dynamically parses format definitions (`'F'`), builds structural unpackers (`struct.unpack`), and maps subscriptions (`'A'`).
   - Decodes all valid telemetry data packets (`'D'`) sequentially.
   - Upon encountering the corruption horizon (truncated length or unrecognized packet), gracefully halts, captures all intact data up to that byte offset, sets `is_corrupted = True`, records `corruption_offset`, and injects a `DATA_TRUNCATION_OR_CORRUPTION` anomaly into the event log.

---

### 3.3 Raw Hexadecimal Forensic Inspector (`gui/api.py` & `gui/index.html`)

To provide court-admissible raw evidence verification without relying on external hex editors:
- **3-Column Forensic Layout**: Standard forensic layout rendering `[Offset (8 Hex)] | [16 Hex Bytes with 8-byte spacer] | [ASCII Representation with non-printable substitution]`.
- **4KB Chunked Streaming**: Files of arbitrary size (from kilobytes to gigabytes) are streamed in 4,096-byte blocks via HTTP API (`/api/file_hex_chunk`), ensuring responsive rendering and zero memory exhaustion.
- **Direct Offset Navigation**: Interactive byte scrubber and jump-to-offset modal supporting decimal (`12345`) and hexadecimal (`0x3039`) offsets.
- **Pattern Search**: Full-file binary pattern matching (`/api/search_file_hex`) supporting UTF-8/ASCII strings and hexadecimal byte sequences (`55 4C 6F 67`).
- **Magic Byte Identification**: Automated inspection of initial file headers with visual badges for recognized UAV signatures (ULog, DataFlash, DJI DAT, JPEG EXIF, MP4/MOV).

---

### 3.4 Cryptographic Custody & Section 63 BSA Verification

```
+---------------------------------------------------------------------------------------------------+
|                                 MERKLE-LINKED CUSTODY LEDGER                                      |
+---------------------------------------------------------------------------------------------------+
|                                                                                                   |
|  +-----------------------+     +-----------------------+     +-----------------------+            |
|  | Record #1 (ACQUIRE)   |     | Record #2 (PARSE)     |     | Record #3 (ANOMALY)   |            |
|  | SHA-256: 3a7f...      | --> | SHA-256: c91b...      | --> | SHA-256: 8d2e...      |            |
|  | BLAKE3:  e142...      |     | BLAKE3:  09fa...      |     | BLAKE3:  44b1...      |            |
|  | PrevHash: GENESIS     |     | PrevHash: 3a7f...     |     | PrevHash: c91b...     |            |
|  +-----------------------+     +-----------------------+     +-----------------------+            |
|                                                                                                   |
+---------------------------------------------------------------------------------------------------+
```

Every operation executed by Pushpak (Ingest, Acquisition, Parse, Anomaly Detection, Report Export) appends a cryptographically signed block to `chain_of_custody.jsonl`:
- **Dual Hash Verification**: Both SHA-256 (FIPS 180-4 standard) and BLAKE3 (high-speed tree hashing) are recorded for raw source artifacts.
- **Tamper Evident**: Modifying even a single character in the raw log file or ledger invalidates the Merkle hash chain, causing instant failure during verification (`verify_ledger_integrity`).
- **Section 63 BSA Court Certificate**: The generated PDF report contains the full certificate with date of acquisition, serial number, investigator name, SHA-256 manifest, and judicial declaration.

---

## 4. Multi-Vendor Format Support Matrix

| Manufacturer / Firmware | Native File Formats | Extraction Mechanism | Parsed Flight Parameters | Cryptographic Handling |
| :--- | :--- | :--- | :--- | :--- |
| **PX4 Autopilot** | `.ulg` (ULog binary) | Serial USB / SD Card | Geodetic (Lat/Lon/Alt), IMU (Acc/Gyro), Battery (V/A/%), Attitude (R/P/Y), Status Flags | SHA-256 + BLAKE3 + Binary Carving |
| **ArduPilot (APM)** | `.bin` (DataFlash), `.log` | Serial USB / SD Card | GPS, POS, ATT, BAT, RCIN/RCOUT, MODE, CMD, EV (Events) | Dual Hashing + Header Sync |
| **DJI Onboard** | `.DAT` (Fly0182, P3/P4/Mavic) | ADB / Direct SD Card | GPS, IMU, Motor Current, Battery Temp, RC Channels, Baro Alt | XOR Entropy / Decryption Pipeline |
| **DJI Flight Record** | `.csv` (App Export) | ADB Mobile Pull / CSV | Time (MM:SS / ISO), Coordinates, Speed, Distance, Satellites, Battery | Timestamp Normalization |
| **Autel Robotics** | `.csv` (Explorer App) | ADB Mobile Pull / CSV | GPS Lat/Lon, MSL/AGL Alt, Speed (H/V), Yaw, Pitch, Roll, Battery | Timestamp Normalization |
| **Yuneec** | `.csv` (DataPilot) | ADB Mobile Pull / CSV | GPS Lat/Lon, Pressure Alt, Compass Heading, Voltage, Satellites | Unit Normalization |
| **Betaflight / Cleanflight** | `.bbl`, `.txt` (Blackbox) | Blackbox Flash Log | High-rate Gyro/Acc (100Hz-1kHz), Motor Throttle, RC Commands | Frame Unpacking |
| **MAVLink Systems** | `.tlog` (Telemetry Log) | Radio Telemetry / Serial | `GLOBAL_POSITION_INT`, `ATTITUDE`, `GPS_RAW_INT`, `SYS_STATUS` | Message Filter & Timestamping |
| **Media Payloads** | `.jpg` (EXIF/XMP), `.srt` / `.mp4` | SD Card / Extracted FS | Frame-level GPS, Altitude, Camera FOV, Timestamp, Shutter Time | Metadata Carving |

---

## 5. Verification, Testing, and Validation Benchmarks

### 5.1 Test Suite Structure

The Pushpak repository maintains a 100% automated test suite spanning unit, integration, and Known-Answer Tests (KAT):

| Test Suite Module | Target Component | Key Verification Scenarios | Test Count |
| :--- | :--- | :--- | :--- |
| `tests/test_acquisition.py` | `acquisition/mavlink_extractor.py`, `adb_extractor.py` | Serial port scanning, MAVLink chunk protocol, ADB extraction, dual hashing, ledger logging | 8 tests |
| `tests/test_corrupted_parsing.py` | `parsers/px4_ulog.py`, `parsers/base.py` | Mid-flight power cutoff carving, salvage count, `DATA_TRUNCATION_OR_CORRUPTION` anomaly | 4 tests |
| `tests/test_hex_viewer.py` | `gui/api.py`, `gui/index.html` | 4KB chunk streaming, jump-to-offset, hex/ASCII search, magic byte detection | 6 tests |
| `tests/test_px4_ulog.py` | `parsers/px4_ulog.py` | ULog format parsing, extended telemetry extraction, Null Island filtering | 5 tests |
| `tests/test_ardupilot.py` | `parsers/ardupilot.py` | DataFlash message framing, FMT definitions, corrupted stream recovery | 4 tests |
| `tests/test_dji.py` & `test_dji_csv.py` | `parsers/dji.py`, `parsers/dji_csv.py` | DAT header detection, Fly0182 parsing, CSV MM:SS parsing, extended dynamics | 9 tests |
| `tests/test_autel.py` & `test_yuneec.py` | `parsers/autel.py`, `parsers/yuneec.py` | CSV header parsing, custody recording, missing serial handling | 8 tests |
| `tests/test_betaflight.py` & `test_mavlink_tlog.py` | `parsers/betaflight.py`, `parsers/mavlink_tlog.py` | Blackbox framing, MAVLink v2.0 message decoding | 8 tests |
| `tests/test_media_extractor.py` | `parsers/media_extractor.py` | JPEG EXIF/XMP coordinate extraction, SRT subtitle telemetry extraction | 4 tests |
| `tests/test_correlation.py` | `analytics/correlation.py` | Haversine distance, polygon ray-casting, GPS spoofing, geofence breaches | 6 tests |
| `tests/test_protected_data.py` | `crypto/protected_data.py` | Shannon entropy calculation, XOR key recovery, encrypted payload decryption | 7 tests |
| `tests/test_ledger.py` | `custody/ledger.py` | Merkle linkage, tamper detection, missing ledger initialization | 4 tests |
| `tests/test_report.py` & `test_pdf_refresh.py` | `export/geospatial.py`, `gui/api.py` | Courtroom PDF report generation, 3D exhibit syncing, Section 63 BSA cert | 9 tests |
| `tests/test_geospatial.py` & `test_mbtiles.py` | `export/geospatial.py`, `export/mbtiles.py` | GeoJSON, KML 3D trajectories, Cesium exports, offline MBTiles serving | 11 tests |
| `tests/test_gui_api.py` & `test_schema.py` | `gui/api.py`, `parsers/base.py` | HTTP Bridge API endpoints, multi-drone analysis, schema serialization | 10 tests |
| **Total Test Suite** | **Entire Pushpak Codebase** | **Comprehensive Regression & Integration Coverage** | **110+ Tests** |

---

## 6. Judicial Report Sample & Section 63 Certificate

The automated Courtroom Forensic Report generated by Pushpak compiles all forensic data into a standardized, tamper-evident PDF document containing:
1. **Case & Investigator Metadata**: Case ID, incident timestamp, investigator credentials, and laboratory identity.
2. **Forensic Acquisition Manifest**: Source device hardware serials, extraction protocol used (MAVLink USB / ADB), SHA-256 and BLAKE3 cryptographic hashes.
3. **Flight Mission Parameters**: Total flight duration, 3D cumulative distance, launch coordinates, terminal/crash coordinates, peak altitude (MSL/AGL), maximum ground speed.
4. **Automated Anomaly Audit Table**: Categorized forensic anomalies (Geofence Breach, GPS Teleportation, Critical Battery Collapse, Data Truncation/Corruption) with UTC timestamps and coordinate tags.
5. **High-Resolution Geospatial Exhibits**: 2D flight path map and 3D altitude profile exhibits with reverse-geocoded landmark references.
6. **Statutory Certificate under Section 63 BSA, 2023**: Formally executed declaration certifying hardware provenance, software non-destructiveness, and hash chain verification.

---

## 7. Conclusion & Operational Readiness

The Pushpak Drone Forensics Toolkit bridges the critical technical and procedural divide between low-level drone telemetry extraction and court-admissible forensic presentation. By incorporating hardware-level MAVLink and ADB extraction, crash-resilient binary carving, tamper-evident cryptographic ledgers, embedded raw hex inspection, and full offline air-gapped mapping, Pushpak establishes a definitive, verifiable standard for Unmanned Aerial Systems digital forensics.

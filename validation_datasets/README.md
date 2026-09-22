# Pushpak Forensic Suite - Validation Datasets & Known-Answer Test (KAT) Specifications

## 1. Scope & Forensic Objectives
In accordance with **ISO/IEC 27037:2012** (*Guidelines for identification, collection, acquisition and preservation of digital evidence*), **NIST SP 800-86** (*Guide to Integrating Forensic Techniques into Incident Response*), and **ASTM E3016-18** (*Standard Guide for Establishing Confidence in Digital and Multimedia Evidence Forensic Results*), forensic analysis software must undergo rigorous verification using standardized, deterministic datasets with known ground truth.

This directory documents the synthetic and reference flight test vectors utilized by the Pushpak Drone Forensics Toolkit to guarantee mathematical repeatability, zero data distortion, and deterministic error margins across multi-vendor UAV platforms.

---

## 2. Ground Truth Flight Test Vectors

### Dataset Overview Table

| Dataset ID | Platform / Ecosystem | Format | Scenario Description | Duration | Telemetry Records | Ground Truth Reference |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`KAT-PX4-001`** | PX4 Autopilot v1.14 | `.ulg` (ULog binary) | Standard urban waypoint mission with GPS lock and barometric altimetry | 120s | 1,200 points @ 10Hz | `tests/test_px4_ulog.py` |
| **`KAT-PX4-002-CORRUPT`** | PX4 Autopilot v1.14 | `.ulg` (Truncated) | Mid-flight power bus disconnect (abrupt crash at T+45s with truncated binary stream) | 45s | 450 carved records | `tests/test_corrupted_parsing.py` |
| **`KAT-ARDU-001`** | ArduPilot Copter 4.3 | `.bin` (DataFlash) | High-speed transit with simulated GPS multipath degradation | 180s | 1,800 points @ 10Hz | `tests/test_ardupilot.py` |
| **`KAT-DJI-DAT-001`** | DJI Mavic 3 / Mini 3 | `.DAT` (Fly0182) | Encrypted payload record with firmware XOR header and IMU/battery streams | 90s | 900 records | `tests/test_dji.py` |
| **`KAT-DJI-CSV-001`** | DJI Flight Record App | `.csv` (App Log) | CSV export with MM:SS time strings and extended motor current telemetry | 60s | 600 records | `tests/test_dji_csv.py` |
| **`KAT-AUTEL-001`** | Autel EVO II Pro | `.csv` (Explorer Log) | Flight corridor crossing with geofence boundary penetration | 75s | 750 records | `tests/test_autel.py` |
| **`KAT-YUNEEC-001`** | Yuneec Typhoon H Plus | `.csv` (DataPilot) | Industrial perimeter inspection with compass yaw oscillation | 110s | 1,100 records | `tests/test_yuneec.py` |
| **`KAT-BETA-001`** | Betaflight 4.4 | `.bbl` / `.txt` | FPV high-G maneuver regime with motor throttle saturation | 40s | 4,000 points @ 100Hz | `tests/test_betaflight.py` |
| **`KAT-MAV-001`** | MAVLink 2.0 Telemetry | `.tlog` (GCS stream) | Dual telemetry stream (`GLOBAL_POSITION_INT`, `ATTITUDE`, `GPS_RAW_INT`) | 150s | 1,500 records | `tests/test_mavlink_tlog.py` |
| **`KAT-EXIF-001`** | Media Forensics (EXIF/SRT) | `.jpg` / `.srt` | Visual payload sync: XMP metadata + video subtitle embedded telemetry | 30s | 30 subtitles + 5 stills | `tests/test_media_extractor.py` |

---

## 3. Mathematical Precision & Error Tolerance Thresholds

Forensic reconstruction engines in the Pushpak Suite are validated against strict error tolerance boundaries to ensure that no numerical drift or coordinate rounding occurs during ingestion and event normalization:

| Metric | Measurement Unit | Allowed Error Margin ($\Delta$) | Rational & Legal Baseline |
| :--- | :--- | :--- | :--- |
| **Geodetic Latitude** | Decimal Degrees (WGS-84) | $\le \pm 0.000001^\circ$ (~0.11 m) | Precision preservation: no floating point rounding below 6 decimal places |
| **Geodetic Longitude** | Decimal Degrees (WGS-84) | $\le \pm 0.000001^\circ$ (~0.11 m) | Section 63 BSA 2023 accuracy mandate |
| **Geometric Altitude** | Meters Above Ellipsoid (MAE/MSL)| $\le \pm 0.05\text{ m}$ | Preserves vertical flight trajectory fidelity |
| **Timestamp Alignment** | ISO 8601 UTC Milliseconds | $\le \pm 1.0\text{ ms}$ | UTC synchronization required for multi-sensor chronological sequencing |
| **Groundspeed Vector** | Meters per second ($m/s$) | $\le \pm 0.02\text{ m/s}$ | Preserves kinetic energy and speed violation assessments |
| **Attitude Angles** | Degrees (Roll, Pitch, Yaw) | $\le \pm 0.1^\circ$ | Preserves aerodynamic loss-of-control reconstruction |
| **Cryptographic Hash** | SHA-256 & BLAKE3 | $0\text{ bit variance}$ (Exact match) | ISO/IEC 27037:2012 Clause 6.3 strict immutability |

---

## 4. Anomaly Injection Scenarios & Expected Outcomes

The Pushpak validation suite tests edge cases and malicious tamper attempts to verify automated anomaly flag emission:

### A. Sudden Mid-Flight Power Cutoff (Crash / Battery Ejection)
- **Vector Pattern**: Log file ends abruptly without proper EOF marker, footer, or index tables.
- **Expected Behavior**:
  1. Low-level binary carving activates (`_carve_corrupted_ulog` / `_resilient_binary_parse`).
  2. All intact packets up to the corruption byte offset are salvaged without crashing.
  3. `is_corrupted: True`, `corruption_offset: <offset>`, and `salvaged_records_count: N` are populated.
  4. An anomaly event `DATA_TRUNCATION_OR_CORRUPTION` is automatically injected into the event timeline.

### B. GPS Spoofing & Instantaneous Teleportation
- **Vector Pattern**: Consecutive GPS fix records jump $> 500\text{ m}$ in $\Delta t < 1.0\text{ s}$ ($> 1,800\text{ km/h}$).
- **Expected Behavior**:
  1. Spatial correlation engine triggers Haversine distance check.
  2. Anomaly event `GPS_SPOOFING_OR_TELEPORTATION` is flagged with starting coordinate, end coordinate, and implied velocity.

### C. Geofence Boundary Breach
- **Vector Pattern**: Flight trajectory points intersect and penetrate an active polygon boundary (e.g., Airport Restricted Zone).
- **Expected Behavior**:
  1. Ray-casting point-in-polygon algorithm identifies transition from outside to inside restricted perimeter.
  2. Anomaly event `GEOFENCE_BREACH` is recorded with UTC entry time and coordinate.

### D. Critical Voltage Collapse & Uncontrolled Descent
- **Vector Pattern**: Battery voltage drops below critical cell threshold ($< 3.3\text{V/cell}$) accompanied by vertical descent rate $> 8\text{ m/s}$.
- **Expected Behavior**:
  1. Correlation engine registers `CRITICAL_BATTERY_FAILSAFE` followed by `UNCONTROLLED_CRASH_DESCENT`.

---

## 5. Reproduction & Continuous Integration Instructions

To execute the complete automated Known-Answer Test (KAT) validation suite:

```bash
# Run all deterministic KAT validation tests
pytest -v -k "test_"

# Run corrupted binary carving verification specifically
pytest -v tests/test_corrupted_parsing.py

# Run hardware acquisition simulation tests
pytest -v tests/test_acquisition.py

# Run hex viewer forensic streaming tests
pytest -v tests/test_hex_viewer.py
```

All test cases assert 100% deterministic hash verification, zero memory leaks, and strict compliance with the error margins defined above.

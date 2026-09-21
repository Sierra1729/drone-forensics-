# PUSHPAK DRONE FORENSICS WORKSTATION
## 5-Minute Video Demonstration Script & Screencast Plan

**Grand Challenge 3: "Security of Drones" — Objective 1: Drone Forensics Toolkit**  
**Evaluation Submission Deliverable**  
**Target Duration:** 4 minutes 45 seconds – 5 minutes 00 seconds

---

### Video Metadata
- **Title:** Indigenous Drone Digital Forensics Workstation — PUSHPAK Grand Challenge 3 (IIT Bombay / VJTI / MeitY)
- **Presenter / Narrator:** Digital Forensics Engineering Team
- **Resolution:** 1080p Full HD (1920x1080), 60 FPS
- **Audio:** Clear voiceover with subtle background ambient music

---

### Timed Scene-by-Scene Script

#### Scene 1: Introduction & Problem Context (0:00 – 0:45)
- **Visual:** Title card with IIT Bombay, VJTI Mumbai, and MeitY logos. Quick montage of drone security incidents (cross-border smuggling, illegal airspace intrusions, rogue UAVs).
- **Narration:**
  > "Welcome. In recent years, uncrewed aerial systems (UAS) have emerged as critical threats to national security, critical infrastructure, and public safety. When a rogue or crashed drone is seized by law enforcement, investigators face proprietary, encrypted, and fragmented flight logs across dozens of commercial and custom manufacturers.
  > 
  > Under the PUSHPAK Grand Challenge 3, funded by MeitY and hosted by IIT Bombay and VJTI Mumbai, we present the **Pushpak Indigenous Drone Forensics Workstation** — a comprehensive, air-gapped, multi-platform digital forensics suite compliant with ISO/IEC 27037 and Section 63 of the Bharatiya Sakshya Adhiniyam, 2023."

---

#### Scene 2: Architecture & Multi-Platform Ingestion (0:45 – 1:30)
- **Visual:** Screen capture opening the Desktop GUI (`run_gui.bat`). Transition to the Ingest Wizard showing the 10 supported parser plugins. Ingesting `real_px4_flight.ulg` (27.3 MB).
- **Narration:**
  > "The toolkit features an extensible plugin architecture equipped with 10 specialized binary and text parsers covering open-source platforms like PX4 and ArduPilot, commercial leaders like DJI, Autel, Parrot, and Yuneec, as well as FPV Betaflight blackboxes and camera media metadata.
  > 
  > Here, we ingest a real-world 27.3 megabyte PX4 binary ULog. The moment the file is selected, the toolkit computes dual-stream cryptographic digests — SHA-256 and high-speed BLAKE3 — and appends an immutable block to our Merkle chain-of-custody ledger."

---

#### Scene 3: High-Performance Normalization & 2D/3D Flight Reconstruction (1:30 – 2:30)
- **Visual:** Progress bar completes in 1.2 seconds. GUI transitions to the 2D Map and 3D Cesium visualization. Show trajectory line, takeoff point, home point, and waypoint pins on the offline MBTiles basemap. Toggle altitude, speed, and battery telemetry graphs.
- **Narration:**
  > "In just 1.2 seconds, over 1,900 telemetry events and 850 GPS coordinates are parsed and normalized into a unified, platform-agnostic schema. 
  > 
  > Investigators can immediately visualize the complete flight path on our fully offline, air-gapped map viewer — no internet connection required. The interface provides interactive 3D attitude playback, synchronized multi-axis sensor telemetry showing battery voltage curves, motor current draw, and ground speed down to microsecond precision."

---

#### Scene 4: Automated Anomaly Detection & Geofence Intelligence (2:30 – 3:30)
- **Visual:** Navigate to the "Anomalies & Intelligence" tab. Run the anomaly correlation engine. Show red warning banners: No-Fly Zone (NFZ) boundary violations, GPS spoofing/loss-of-satellite jumps, and low-battery forced descents.
- **Narration:**
  > "Forensic investigations require rapid identification of malicious or anomalous intent. Our multi-stream correlation engine automatically evaluates the flight against 7 forensic anomaly categories.
  > 
  > Here, the system instantly flags 70 flight anomalies, including unauthorized entry into sensitive geofenced airspace, sudden GPS position discontinuities indicative of spoofing or jamming, and critical battery voltage drops correlated with altitude loss. Each anomaly is linked directly to exact timestamps and sensor readings."

---

#### Scene 5: Cryptographic Integrity Audit & Legal Admissibility Report (3:30 – 4:30)
- **Visual:** Switch to the "Report & Custody" tab. Show the Merkle chain-of-custody table. Click "Generate Courtroom PDF Report". Open the generated 4-page PDF, showcasing the Section 63 BSA 2023 / Section 65B IEA certificate, examiner signature block, SHA-256/BLAKE3 hash tables, and trajectory charts.
- **Narration:**
  > "Digital evidence is only as good as its legal defensibility. The toolkit maintains an append-only Merkle ledger where every operation is cryptographically linked to its parent hash. Any retrospective file tampering is immediately caught.
  > 
  > With a single click, the toolkit compiles a courtroom-ready PDF report adhering to ISO/IEC 27037:2012, NIST SP 800-86, and Section 63 of the Bharatiya Sakshya Adhiniyam, 2023. The report automatically embeds cryptographic digests, examiner credentials, flight telemetry summaries, anomaly evidence, and the statutory legal declaration required by Indian courts."

---

#### Scene 6: Conclusion & Stage 2 Roadmap (4:30 – 5:00)
- **Visual:** Terminal screen running `python verify_everything.py` showing all 99 tests and 6 master verification steps passing. Final closing slide with project summary and GitHub repository link.
- **Narration:**
  > "Backed by 99 automated unit tests and mathematical validation accurate to within fifteen decimal places, the Pushpak Drone Forensics Toolkit delivers an indigenous, sovereign capability for India's digital forensics and national security ecosystem.
  > 
  > In Stage 2, we will integrate direct hardware chip-off acquisition, Android GCS unallocated SQLite carvers, and standalone air-gapped installers. Thank you."

---

### Recording Checklist for Production:
1. **Tool Setup:** Run `run_gui.bat` on a clean 1080p display with Windows dark mode enabled.
2. **Pre-load Evidence:** Have `sample_evidence/real_px4_flight.ulg` and `sample_evidence/DJIFlightRecord_2024-01-15_[14-22-00].csv` ready in the file picker.
3. **Capture Software:** OBS Studio (Record at 1920x1080, 60 FPS, Bitrate 12,000 Kbps, AAC audio).
4. **PDF Viewer:** Use Adobe Acrobat or Microsoft Edge PDF reader in full-page mode to smoothly scroll through `forensic_examination_report.pdf`.

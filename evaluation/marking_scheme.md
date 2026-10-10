# PUSHPAK Grand Challenge 3 — Stage 2 Marking Scheme
**Objective 1: Drone Forensics Toolkit Development**
**Evaluator:** Independent Examiner on the Evaluation Committee
**Evaluation Basis:** `evaluation_inputs/Stage2_Template.pdf` (Total: 100.0 Marks)

---

## ⚖️ Scoring Principles & Fixed Rating Scale

Every sub-check is scored on this pre-registered fixed scale:
- **1.00 (Demonstrated):** Reproduced in clean re-run on real data where required, matching both independent reference and team claim.
- **0.75 (Demonstrated with minor gaps):** Minor edge case fails, partial labeling, or minor undocumented manual step needed.
- **0.50 (Partly demonstrated):** Works only on synthetic data where real data required, partial subset passes, or significant manual intervention needed.
- **0.25 (Minimal):** Runs but output wrong/unverifiable, claim contradicted by tests, or thin documentation.
- **0.00 (Absent / Failing):** Absent, failing, not reproducible, or claimed only.

**Section Marks:** $\sum(\text{Points} \times \text{Rating})$, rounded to nearest 0.5 in code.

### 🚨 Integrity Gate
- **FAILED:** If hash verification fails or a 1-byte alteration to evidence goes undetected.
- **AT RISK:** If any custody-log tamper test (edit, delete, swap, forged append) goes undetected.
- *Status displayed prominently on report cover and executive summary regardless of numerical score.*

---

## 📋 Section-by-Section Sub-Checks & Point Allocations

### Section 1: Executive Toolkit Summary [5.0 Marks]
*Expectation:* Clear final toolkit and key evidence; concise statement of confidence and limits.
- **Sub-check 1.1 (2.0 pts):** Parameter metrics completeness and verification against test results. Full credit requires all 16 template parameters filled with verifiable values.
- **Sub-check 1.2 (1.5 pts):** Defensible statement of field readiness (top 3 reasons) backed by verified test evidence.
- **Sub-check 1.3 (1.5 pts):** Technical disclosure of remaining uncertainties and risks (top 3 risks) reflecting real operational engineering judgement.

### Section 2: Stage 1 Baseline and Design Evolution [8.0 Marks]
*Expectation:* Changes from Stage 1 are justified by testing, not arbitrary; Stage 1 claims are demonstrated or withdrawn.
- **Sub-check 2.1 (3.0 pts):** Stage 1 baseline vs. Stage 2 evolution table and engineering justifications across all 8 rubric rows.
- **Sub-check 2.2 (3.0 pts):** Stage 1 claims revisited table (demonstrated / partly / withdrawn) with concrete supporting test evidence.
- **Sub-check 2.3 (2.0 pts):** Resolution of Stage 1 open questions with documented validation results.

### Section 3: Updated/Implemented Requirements and Architecture [7.0 Marks]
*Expectation:* Architecture is coherent, integrated, and aligned with challenge needs: acquire, preserve, analyse, report.
- **Sub-check 3.1 (3.0 pts):** Challenge targets traceability matrix covering Acquire, Preserve, Custody, Analyse, Reconstruct, Report.
- **Sub-check 3.2 (2.5 pts):** Architectural coherence, modular layering (acquisition, core, parsers, analytics, reports), and clean isolation of third-party code.
- **Sub-check 3.3 (1.5 pts):** Extensibility beyond tested platforms demonstrated via parser abstraction classes (`BaseParser`).

### Section 4: Integrated Methodology and Workflow [8.0 Marks]
*Expectation:* Logical workflow connecting acquisition, integrity, parsing, analysis, reconstruction, and reporting.
- **Sub-check 4.1 (3.0 pts):** End-to-end reproducible logic-flow diagram linking all 7 pipeline stages.
- **Sub-check 4.2 (3.0 pts):** Sub-domain mapping matrix completeness (inputs, outputs, tools, verification methods).
- **Sub-check 4.3 (2.0 pts):** Inter-stage dependency analysis (e.g., how failed hash check halts parsing, how clock drift reconciliation changes reconstructed timeline).

### Section 5: Evidence Acquisition, Preservation and Chain of Custody [18.0 Marks]
*Expectation:* Real acquisition clearly separated from imported files; hash verification and tamper detection demonstrated; custody record is tamper-evident; limits stated.
- **Sub-check 5.1 (3.0 pts):** Acquisition methodology and acquisition matrix separating real hardware paths from imported files/images.
- **Sub-check 5.2 (3.0 pts):** Hardware/software write-blocker enforcement preventing modification of source media.
- **Sub-check 5.3 (3.0 pts):** Dual cryptographic hashing (SHA-256 + BLAKE3) computed at copy and verified on read.
- **Sub-check 5.4 (3.0 pts):** Append-only chained Merkle custody ledger with action, actor, timestamp, and hash chaining.
- **Sub-check 5.5 (3.0 pts):** 1-byte tamper detection demonstration on evidence files and custody log entries.
- **Sub-check 5.6 (2.0 pts):** Robust handling of corrupt, truncated, empty, and unsupported inputs without crashes or data fabrication.
- **Sub-check 5.7 (1.0 pt):** Time source handling, clock reconciliation, and 100% offline air-gapped operation confirmation.

### Section 6: Parsing, Analysis and Data Extraction [12.0 Marks]
*Expectation:* Parsers decode real data with no generated values presented as evidence; results cross-checked against reference; deleted-data and cross-source analysis shown; limits documented.
- **Sub-check 6.1 (3.5 pts):** Parser coverage across multi-vendor platforms and binary log formats on authentic data.
- **Sub-check 6.2 (2.5 pts):** Independent cross-verification of decoded telemetry against reference tools (PyULog, pymavlink, DatCon, ExifTool).
- **Sub-check 6.3 (2.0 pts):** Source-offset byte provenance for extracted values and strict labelling of any computed/estimated metrics.
- **Sub-check 6.4 (1.5 pts):** Deleted-data recovery and binary signature carving from raw disk images.
- **Sub-check 6.5 (1.5 pts):** Telemetry anomaly detection (GPS spoofing, altitude teleportation, geofence breaches).
- **Sub-check 6.6 (1.0 pt):** Media metadata extraction (EXIF/XMP) and mobile companion-app artifact decoding (SharedPrefs, SQLite).

### Section 7: Timeline, Flight Path and Event Reconstruction [8.0 Marks]
*Expectation:* Reconstruction checked against known flight; time base and clock reconciliation explained.
- **Sub-check 7.1 (3.0 pts):** Flight path reconstruction accuracy, sample count, and position error bounds against reference trajectory.
- **Sub-check 7.2 (2.0 pts):** Flight event timeline identification (arming, disarming, failsafes, mode changes).
- **Sub-check 7.3 (1.5 pts):** Cross-source time base alignment error between flight controller and GCS app logs.
- **Sub-check 7.4 (1.5 pts):** Offline visualization outputs (2D map and 3D flight trajectory playback with pitch/roll/yaw attitude).

### Section 8: Validation, Testing and Reproducibility [14.0 Marks]
*Expectation:* Tests and data are in the archive and pass on committee's re-run; real evidence used; negative and tamper tests; synthetic data labelled; every claim traceable.
- **Sub-check 8.1 (3.5 pts):** Test suite comprehensiveness including unit, integration, known-answer, negative, and tamper tests.
- **Sub-check 8.2 (4.0 pts):** Clean-machine test execution and pass rate on committee re-run (171/171 tests).
- **Sub-check 8.3 (2.5 pts):** Genuine real evidence corpus vs. declared synthetic test fixtures distinction.
- **Sub-check 8.4 (2.0 pts):** Performance benchmarking (runtime, peak memory, throughput in min/GB) and output determinism diff.
- **Sub-check 8.5 (2.0 pts):** Claims traceability matrix verifying every quantitative claim in `claims.csv`.

### Section 9: Automation, Usability and Reporting [8.0 Marks]
*Expectation:* Examiner can run toolkit end-to-end offline and produce court-ready report.
- **Sub-check 9.1 (2.5 pts):** Examiner workflow simplicity, step count from raw evidence to final report, and batch processing capability.
- **Sub-check 9.2 (2.5 pts):** Court-ready judicial PDF report generation certified under Section 63 BSA 2023 / Section 65B IEA.
- **Sub-check 9.3 (1.5 pts):** Report completeness (dual hash appendix, certificate of authenticity, chain of custody summary).
- **Sub-check 9.4 (1.5 pts):** Offline air-gapped operation confirmation and demonstration video review.

### Section 10: Final Deployable Package [7.0 Marks]
*Expectation:* Source, guides, tests, evidence, ledgers, video, and risk register are complete and run on clean machine.
- **Sub-check 10.1 (3.0 pts):** Deliverables checklist completeness (source code, tests, guides, evidence, ledgers, pre-generated outputs).
- **Sub-check 10.2 (2.0 pts):** Installation and execution from package on clean machine following documentation only.
- **Sub-check 10.3 (1.0 pt):** Dependency list and open-source license audit.
- **Sub-check 10.4 (1.0 pt):** Risk register, known limitations, and development roadmap.

### Section 11: References, Data Traceability and Integrity [5.0 Marks]
*Expectation:* Sources and third-party code credited and licensed; tools declared and verified; integrity declaration completed.
- **Sub-check 11.1 (1.5 pts):** Academic, forensic, and standard references validity and direct relevance to toolkit architecture.
- **Sub-check 11.2 (1.5 pts):** Disclosure and team verification of software, digital, and AI tools used.
- **Sub-check 11.3 (1.0 pt):** Third-party code and datasets attribution and license compliance.
- **Sub-check 11.4 (1.0 pt):** Design integrity declaration completeness and team leader execution.

---
**Total Marks: 100.0**

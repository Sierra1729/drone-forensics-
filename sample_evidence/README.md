# Sample Evidence Repository

This directory holds authentic UAV flight logs and forensic test exhibits:

1. **PX4 ULog (`.ulg`)**: Native binary blackbox logs from PX4 Flight Review (`https://review.px4.io/`).
2. **ArduPilot DataFlash (`.BIN`)**: Binary logs from Pixhawk/Cube/APM flight controllers.
3. **DJI Flight Records (`.txt`, `.DAT`)**: Downlink logs and onboard blackbox files from DJI Phantom, Mavic, Inspire.
4. **Parrot FreeFlight (`.json`)**: Telemetry JSON files from Parrot ANAFI, ANAFI USA, Bebop.
5. **MAVLink Telemetry (`.tlog`)**: Radio downlink logs from QGroundControl and Mission Planner.

## Ingestion Command

Run the unified one-click forensic pipeline on any evidence file:

```powershell
python -m cli.main ingest sample_evidence/<filename> --output-dir output/<case_name>
```

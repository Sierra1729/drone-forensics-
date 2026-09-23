===============================================================================
       PUSHPAK DRONE FORENSICS SUITE - SECTIONED EVIDENCE TEST DATA
===============================================================================

This test folder is bifurcated into 5 dedicated forensic intake sections:

-------------------------------------------------------------------------------
SECTION FOLDER                             EVIDENCE DESCRIPTION & FORMATS
-------------------------------------------------------------------------------
Section_A_Flight_Controller_Logs          • Raw flight logs (.ulg, .bin, .dat, .bfl, .csv)
                                            • Direct telemetry from PX4, ArduPilot, DJI, FPV.

Section_B_Vehicle_Parameters              • Configuration files (.param, .params)
                                            • Failsafe limits, battery thresholds, geofences.

Section_C_Ground_Station_Tracks           • Exported 3D flight paths (.kmz, .gpx, .tlog)
                                            • GIS waypoint trajectories and satellite tracks.

Section_D_Mobile_and_Controller_Backups   • Acquired evidence zips (iOS, Android, ADB)
                                            • Mobile companion app data & controller dumps.

Section_E_Seized_Media_and_EXIF           • Photos/Videos seized from drone SD card (.jpg, .mp4)
                                            • Embedded camera EXIF & GPS geotags.

===============================================================================
TESTING INSTRUCTION:
Upload files from any 1 or more sections into the Pushpak GUI (python -m gui.main).
The system will cross-correlate all uploaded files and verify whether they belong to 
a SINGLE DRONE or if an ORIGIN MISMATCH is detected!
===============================================================================

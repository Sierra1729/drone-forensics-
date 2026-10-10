"""
analytics/param_diff.py

Parameter Correlation & Security Diff Analytics Engine for Garud FX.

Compares onboard flight log parameters (extracted from .bin / .ulg files)
against external GCS parameter files (.param / .params / vehicle.params).

Identifies:
1. Modified parameters between onboard vehicle state and GCS backup files.
2. Safety & Security Critical Diffs (Geofence disabling, Failsafe overrides, Alt limits).
"""

from __future__ import annotations

from typing import Any


CRITICAL_SECURITY_PARAMS = {
    "FENCE_ENABLE": "Geofence Enforcement Toggle",
    "FENCE_ACTION": "Geofence Breach Failsafe Action",
    "FENCE_ALT_MAX": "Geofence Maximum Altitude Limit",
    "FENCE_RADIUS": "Geofence Maximum Circular Radius",
    "FS_THR_ENABLE": "Throttle Lost-Link Failsafe",
    "FS_BATT_ENABLE": "Battery Low-Voltage Failsafe",
    "FS_GCS_ENABLE": "GCS Telemetry Lost-Link Failsafe",
    "PILOT_ALT_MAX": "Pilot Maximum Altitude Ceiling",
    "ARMING_CHECK": "Pre-Arm Safety Sensor Checks",
    "AVD_ENABLE": "ADS-B Collision Avoidance System",
    "NAV_RTL_ALT": "Return-To-Launch Altitude",
    "COM_OBL_ACT": "Offboard Loss Failsafe Action (PX4)",
    "NAV_DLL_ACT": "Data Link Loss Failsafe Action (PX4)",
}


class ParamDiffEngine:
    """Forensic correlation engine for vehicle configuration parameter diffs."""

    def compare(
        self,
        onboard_params: dict[str, Any],
        gcs_params: dict[str, Any],
    ) -> dict[str, Any]:
        """Compare onboard parameter tree against external GCS parameter file.

        Args:
            onboard_params: Dict of {PARAM_NAME: VALUE} from .bin / .ulg
            gcs_params: Dict of {PARAM_NAME: VALUE} from .param / .params

        Returns:
            Dict containing modified parameters, critical security diffs, and summary statistics.
        """
        # Normalize parameter keys to uppercase
        onboard_norm = {str(k).upper(): v for k, v in onboard_params.items()}
        gcs_norm = {str(k).upper(): v for k, v in gcs_params.items()}

        all_keys = set(onboard_norm.keys()).union(set(gcs_norm.keys()))

        modified: list[dict[str, Any]] = []
        critical_diffs: list[dict[str, Any]] = []
        onboard_only: list[dict[str, Any]] = []
        gcs_only: list[dict[str, Any]] = []

        for key in sorted(all_keys):
            has_onboard = key in onboard_norm
            has_gcs = key in gcs_norm

            if has_onboard and has_gcs:
                val_onboard = onboard_norm[key]
                val_gcs = gcs_norm[key]

                # Check numerical equivalence
                is_equal = False
                try:
                    if float(val_onboard) == float(val_gcs):
                        is_equal = True
                except (ValueError, TypeError):
                    if str(val_onboard) == str(val_gcs):
                        is_equal = True

                if not is_equal:
                    diff_entry = {
                        "parameter": key,
                        "onboard_value": val_onboard,
                        "gcs_value": val_gcs,
                        "is_critical": key in CRITICAL_SECURITY_PARAMS,
                        "description": CRITICAL_SECURITY_PARAMS.get(key, "Vehicle Parameter"),
                    }
                    modified.append(diff_entry)
                    if key in CRITICAL_SECURITY_PARAMS:
                        critical_diffs.append(diff_entry)

            elif has_onboard and not has_gcs:
                onboard_only.append({"parameter": key, "value": onboard_norm[key]})
            elif has_gcs and not has_onboard:
                gcs_only.append({"parameter": key, "value": gcs_norm[key]})

        return {
            "summary": {
                "total_compared": len(all_keys),
                "modified_count": len(modified),
                "critical_diff_count": len(critical_diffs),
                "onboard_only_count": len(onboard_only),
                "gcs_only_count": len(gcs_only),
            },
            "critical_diffs": critical_diffs,
            "modified": modified,
            "onboard_only": onboard_only,
            "gcs_only": gcs_only,
        }

"""
analytics/geocoding.py

Reverse geocoding engine for UAV flight forensics.
Translates GPS coordinates into high-precision, human-readable place names,
landmarks, street addresses, and judicial jurisdictions.
"""

from __future__ import annotations

import json
import logging
import urllib.request
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Local in-memory and disk cache to guarantee fast response and offline re-use
_GEO_CACHE: dict[str, dict[str, Any]] = {}
_CACHE_FILE = Path(__file__).resolve().parent.parent / "cases" / ".geocache.json"


def _load_cache() -> None:
    global _GEO_CACHE
    if _GEO_CACHE:
        return
    try:
        if _CACHE_FILE.exists():
            _GEO_CACHE = json.loads(_CACHE_FILE.read_text(encoding="utf-8"))
    except Exception as e:
        logger.debug(f"Failed to load geocache: {e}")


def _save_cache() -> None:
    try:
        _CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        _CACHE_FILE.write_text(json.dumps(_GEO_CACHE, indent=2), encoding="utf-8")
    except Exception as e:
        logger.debug(f"Failed to save geocache: {e}")


def reverse_geocode(lat: Optional[float], lon: Optional[float]) -> dict[str, Any]:
    """Resolve latitude and longitude into high-resolution place and address details.

    Returns:
        dict with keys:
            - pinpoint_name: Exact road, landmark, or campus
            - full_address: Full administrative address hierarchy
            - city: Town, municipality, or city
            - state: State, province, or canton
            - country: Sovereign nation
            - display_text: Clean one-line location string for UI/PDF
            - source: 'online_osm' | 'cache' | 'offline_coord'
    """
    if lat is None or lon is None or (lat == 0.0 and lon == 0.0):
        return {
            "pinpoint_name": "Unknown Coordinates",
            "full_address": "No GPS Fix Recorded",
            "city": "Unknown",
            "state": "Unknown",
            "country": "Unknown",
            "display_text": "Coordinates Unavailable",
            "source": "offline_coord",
        }

    _load_cache()
    cache_key = f"{lat:.4f},{lon:.4f}"
    if cache_key in _GEO_CACHE:
        cached = dict(_GEO_CACHE[cache_key])
        cached["source"] = "cache"
        return cached

    # Attempt high-resolution online lookup (Zoom 18 for exact road/landmark)
    try:
        url = (
            f"https://nominatim.openstreetmap.org/reverse"
            f"?lat={lat:.6f}&lon={lon:.6f}&format=json&zoom=18&addressdetails=1"
        )
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "PushpakDroneForensics/2.1 (Law Enforcement UAV Analysis)",
                "Accept-Language": "en, fr, de, es",
            },
        )
        with urllib.request.urlopen(req, timeout=3.5) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        addr = data.get("address", {})
        road = addr.get("road") or addr.get("pedestrian") or addr.get("footway") or ""
        quarter = addr.get("quarter") or addr.get("suburb") or addr.get("neighbourhood") or ""
        town = addr.get("town") or addr.get("city") or addr.get("village") or addr.get("municipality") or ""
        state = addr.get("state") or addr.get("county") or ""
        country = addr.get("country") or ""
        postcode = addr.get("postcode") or ""

        pinpoint_parts = [p for p in [road, quarter] if p]
        pinpoint_name = ", ".join(pinpoint_parts) if pinpoint_parts else (town or data.get("name") or "Local Area")

        full_parts = [p for p in [pinpoint_name, town, state, postcode, country] if p]
        full_address = ", ".join(full_parts)

        display_text = f"{pinpoint_name} ({town + ', ' if town else ''}{state}, {country})".strip()
        if not pinpoint_parts and town:
            display_text = f"{town}, {state}, {country}"

        res = {
            "pinpoint_name": pinpoint_name,
            "full_address": full_address,
            "city": town or "Unknown",
            "state": state or "Unknown",
            "country": country or "Unknown",
            "postcode": postcode,
            "display_text": display_text,
            "source": "online_osm",
        }

        _GEO_CACHE[cache_key] = res
        _save_cache()
        return res

    except Exception as e:
        logger.debug(f"Reverse geocode online lookup failed for {lat},{lon}: {e}")

    lat_card = "N" if lat >= 0 else "S"
    lon_card = "E" if lon >= 0 else "W"
    coord_str = f"{abs(lat):.4f}°{lat_card}, {abs(lon):.4f}°{lon_card}"

    fallback = {
        "pinpoint_name": f"Area near {coord_str}",
        "full_address": f"Geographic Coordinates: {coord_str}",
        "city": "Unknown",
        "state": "Unknown",
        "country": "Unknown",
        "postcode": "",
        "display_text": f"Coordinates: {coord_str}",
        "source": "offline_coord",
    }
    return fallback

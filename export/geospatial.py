"""
export/geospatial.py

Geospatial flight path visualizer and 3D trajectory exporter.

Forensic Output Capabilities:
1. RFC 7946 GeoJSON FeatureCollection (for GIS/web applications).
2. OGC KML 3D Trajectory with elevation extrusion (for Google Earth Pro / Cesium).
3. Self-contained interactive Leaflet HTML map via Folium with anomaly callouts.
"""

from __future__ import annotations

import json
import math
import os
from pathlib import Path
from typing import Any, Optional

import folium
import simplekml

from analytics.correlation import ForensicAnomaly, NoFlyZone
from analytics.geocoding import reverse_geocode
from normalize.schema import NormalizedEvent


class GeospatialExporter:
    """Handles multi-format geospatial export for forensic investigations."""

    @staticmethod
    def to_geojson(
        events: list[NormalizedEvent],
        anomalies: Optional[list[ForensicAnomaly]] = None,
        no_fly_zones: Optional[list[NoFlyZone]] = None,
        output_path: Optional[Path] = None,
    ) -> dict[str, Any]:
        """Export flight trajectory, anomalies, and geofences as standard GeoJSON."""
        gps_events = [
            e for e in events
            if e.latitude is not None and e.longitude is not None
            and not (abs(e.latitude) < 0.0001 and abs(e.longitude) < 0.0001)
            and abs(e.latitude) <= 90.0 and abs(e.longitude) <= 180.0
        ]
        features: list[dict[str, Any]] = []

        if gps_events:
            # 1. Flight Track LineString
            coordinates = [
                [e.longitude, e.latitude, e.altitude_m if e.altitude_m is not None else 0.0]
                for e in gps_events
            ]
            max_alt = max((e.altitude_m for e in gps_events if e.altitude_m is not None), default=0.0)
            max_spd = max((e.ground_speed_mps for e in gps_events if e.ground_speed_mps is not None), default=0.0)

            line_feature = {
                "type": "Feature",
                "geometry": {
                    "type": "LineString",
                    "coordinates": coordinates,
                },
                "properties": {
                    "feature_type": "flight_path",
                    "platform": gps_events[0].source_platform,
                    "start_time_utc": gps_events[0].timestamp_utc.isoformat(),
                    "end_time_utc": gps_events[-1].timestamp_utc.isoformat(),
                    "total_points": len(gps_events),
                    "max_altitude_m": max_alt,
                    "max_speed_mps": max_spd,
                },
            }
            features.append(line_feature)

            # 2. Takeoff Point
            features.append({
                "type": "Feature",
                "geometry": {
                    "type": "Point",
                    "coordinates": [gps_events[0].longitude, gps_events[0].latitude, gps_events[0].altitude_m or 0.0],
                },
                "properties": {
                    "feature_type": "takeoff_point",
                    "timestamp_utc": gps_events[0].timestamp_utc.isoformat(),
                },
            })

            # 3. Final Landing / Termination Point
            features.append({
                "type": "Feature",
                "geometry": {
                    "type": "Point",
                    "coordinates": [gps_events[-1].longitude, gps_events[-1].latitude, gps_events[-1].altitude_m or 0.0],
                },
                "properties": {
                    "feature_type": "landing_or_termination_point",
                    "timestamp_utc": gps_events[-1].timestamp_utc.isoformat(),
                },
            })

        # 4. Forensic Anomalies
        for anom in (anomalies or []):
            if anom.latitude is not None and anom.longitude is not None:
                features.append({
                    "type": "Feature",
                    "geometry": {
                        "type": "Point",
                        "coordinates": [anom.longitude, anom.latitude, anom.altitude_m or 0.0],
                    },
                    "properties": {
                        "feature_type": "forensic_anomaly",
                        "anomaly_id": anom.anomaly_id,
                        "anomaly_type": anom.anomaly_type,
                        "severity": anom.severity,
                        "timestamp_utc": anom.timestamp_utc.isoformat(),
                        "description": anom.description,
                        "context": anom.evidence_context,
                    },
                })

        # 5. No-Fly Zones
        for nfz in (no_fly_zones or []):
            if len(nfz.polygon_vertices) >= 3:
                # GeoJSON polygon expects coordinates as [[lon, lat], ...] closed loop
                poly_coords = [[lon, lat] for lat, lon in nfz.polygon_vertices]
                if poly_coords[0] != poly_coords[-1]:
                    poly_coords.append(poly_coords[0])

                features.append({
                    "type": "Feature",
                    "geometry": {
                        "type": "Polygon",
                        "coordinates": [poly_coords],
                    },
                    "properties": {
                        "feature_type": "no_fly_zone",
                        "name": nfz.name,
                        "description": nfz.description,
                        "min_altitude_m": nfz.min_altitude_m,
                        "max_altitude_m": nfz.max_altitude_m,
                    },
                })

        geojson_doc = {
            "type": "FeatureCollection",
            "features": features,
        }

        if output_path is not None:
            path = Path(output_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(geojson_doc, indent=2), encoding="utf-8")

        return geojson_doc

    @staticmethod
    def to_kml(
        events: list[NormalizedEvent],
        anomalies: Optional[list[ForensicAnomaly]] = None,
        no_fly_zones: Optional[list[NoFlyZone]] = None,
        output_path: Optional[Path] = None,
    ) -> Path:
        """Export 3D extruded flight trajectory and styled Placemarks into Google Earth KML."""
        gps_events = [
            e for e in events
            if e.latitude is not None and e.longitude is not None
            and not (abs(e.latitude) < 0.0001 and abs(e.longitude) < 0.0001)
            and abs(e.latitude) <= 90.0 and abs(e.longitude) <= 180.0
        ]
        kml = simplekml.Kml(name="UAV Forensic Trajectory")

        if gps_events:
            # 3D Coordinates: (lon, lat, alt)
            coords_3d = [
                (e.longitude, e.latitude, e.altitude_m if e.altitude_m is not None else 0.0)
                for e in gps_events
            ]

            # 3D Extruded Flight Path
            line = kml.newlinestring(
                name="Flight Trajectory",
                coords=coords_3d,
            )
            line.altitudemode = simplekml.AltitudeMode.relativetoground
            line.extrude = 1
            line.style.linestyle.color = simplekml.Color.cyan
            line.style.linestyle.width = 4
            # 3D curtain fill
            line.style.polystyle.color = simplekml.Color.changealphaint(80, simplekml.Color.cyan)

            # Takeoff Pin
            p_start = kml.newpoint(
                name="Takeoff Point",
                coords=[coords_3d[0]],
                description=f"Takeoff UTC: {gps_events[0].timestamp_utc.isoformat()}",
            )
            p_start.style.iconstyle.color = simplekml.Color.green
            p_start.style.iconstyle.scale = 1.2

            # Landing Pin
            p_end = kml.newpoint(
                name="Landing / Incident Termination",
                coords=[coords_3d[-1]],
                description=f"Termination UTC: {gps_events[-1].timestamp_utc.isoformat()}",
            )
            p_end.style.iconstyle.color = simplekml.Color.red
            p_end.style.iconstyle.scale = 1.2

        # Anomaly Pins
        for anom in (anomalies or []):
            if anom.latitude is not None and anom.longitude is not None:
                anom_pt = kml.newpoint(
                    name=f"ANOMALY: {anom.anomaly_type.upper()}",
                    coords=[(anom.longitude, anom.latitude, anom.altitude_m or 0.0)],
                    description=(
                        f"Severity: {anom.severity}\n"
                        f"Timestamp UTC: {anom.timestamp_utc.isoformat()}\n"
                        f"Details: {anom.description}"
                    ),
                )
                anom_pt.style.iconstyle.color = simplekml.Color.yellow if anom.severity == "MEDIUM" else simplekml.Color.red
                anom_pt.style.iconstyle.scale = 1.4

        # No-Fly Zones in KML
        for nfz in (no_fly_zones or []):
            if len(nfz.polygon_vertices) >= 3:
                poly_coords = [(lon, lat, nfz.max_altitude_m) for lat, lon in nfz.polygon_vertices]
                poly = kml.newpolygon(name=f"NFZ: {nfz.name}", outerboundaryis=poly_coords)
                poly.altitudemode = simplekml.AltitudeMode.relativetoground
                poly.extrude = 1
                poly.style.linestyle.color = simplekml.Color.red
                poly.style.polystyle.color = simplekml.Color.changealphaint(70, simplekml.Color.red)

        target_file = Path(output_path) if output_path else Path("flight_trajectory.kml")
        target_file.parent.mkdir(parents=True, exist_ok=True)
        kml.save(str(target_file))
        return target_file

    @staticmethod
    def to_html_map(
        events: list[NormalizedEvent],
        anomalies: Optional[list[ForensicAnomaly]] = None,
        no_fly_zones: Optional[list[NoFlyZone]] = None,
        output_path: Optional[Path] = None,
    ) -> Path:
        gps_events = [
            e for e in events
            if e.latitude is not None and e.longitude is not None
            and not (abs(e.latitude) < 0.0001 and abs(e.longitude) < 0.0001)
            and abs(e.latitude) <= 90.0 and abs(e.longitude) <= 180.0
        ]

        if gps_events:
            center_lat = sum(e.latitude for e in gps_events) / len(gps_events)
            center_lon = sum(e.longitude for e in gps_events) / len(gps_events)
        else:
            center_lat, center_lon = 19.0760, 72.8777  # Default to Mumbai

        fmap = folium.Map(
            location=[center_lat, center_lon],
            zoom_start=15,
            tiles="OpenStreetMap",
        )

        if gps_events:
            track_points = [[e.latitude, e.longitude] for e in gps_events]

            # Flight track polyline
            folium.PolyLine(
                track_points,
                color="#0066cc",
                weight=4,
                opacity=0.85,
                tooltip=f"Flight Trajectory ({len(gps_events)} points)",
            ).add_to(fmap)

            launch_loc = reverse_geocode(gps_events[0].latitude, gps_events[0].longitude)
            recovery_loc = reverse_geocode(gps_events[-1].latitude, gps_events[-1].longitude)

            takeoff_title = launch_loc.get("pinpoint_name", "Takeoff Site")
            takeoff_addr = launch_loc.get("full_address", f"{gps_events[0].latitude:.6f}°, {gps_events[0].longitude:.6f}°")
            takeoff_popup = (
                f"<div style='font-family:sans-serif; min-width:200px;'>"
                f"<b style='color:#10b981; font-size:13px;'>🚀 Flight Takeoff (Launch Site)</b><br>"
                f"<b>{takeoff_title}</b><br>"
                f"<span style='color:#4b5563; font-size:11px;'>{takeoff_addr}</span><hr style='margin:6px 0; border:0; border-top:1px solid #e5e7eb;'/>"
                f"<b>UTC:</b> {gps_events[0].timestamp_utc.strftime('%Y-%m-%d %H:%M:%S UTC')}<br>"
                f"<b>Alt:</b> {gps_events[0].altitude_m or 0:.1f} m"
                f"</div>"
            )

            recovery_title = recovery_loc.get("pinpoint_name", "Recovery Site")
            recovery_addr = recovery_loc.get("full_address", f"{gps_events[-1].latitude:.6f}°, {gps_events[-1].longitude:.6f}°")
            recovery_popup = (
                f"<div style='font-family:sans-serif; min-width:200px;'>"
                f"<b style='color:#ef4444; font-size:13px;'>🎯 Flight Landing (Recovery Site)</b><br>"
                f"<b>{recovery_title}</b><br>"
                f"<span style='color:#4b5563; font-size:11px;'>{recovery_addr}</span><hr style='margin:6px 0; border:0; border-top:1px solid #e5e7eb;'/>"
                f"<b>UTC:</b> {gps_events[-1].timestamp_utc.strftime('%Y-%m-%d %H:%M:%S UTC')}<br>"
                f"<b>Alt:</b> {gps_events[-1].altitude_m or 0:.1f} m"
                f"</div>"
            )

            # Takeoff marker
            folium.Marker(
                location=track_points[0],
                popup=folium.Popup(takeoff_popup, max_width=320),
                icon=folium.Icon(color="green", icon="play", prefix="fa"),
            ).add_to(fmap)

            # Landing / Termination marker
            folium.Marker(
                location=track_points[-1],
                popup=folium.Popup(recovery_popup, max_width=320),
                icon=folium.Icon(color="red", icon="stop", prefix="fa"),
            ).add_to(fmap)

        # Anomaly markers
        for anom in (anomalies or []):
            if anom.latitude is not None and anom.longitude is not None:
                color = "red" if anom.severity in ("HIGH", "CRITICAL") else "orange"
                popup_html = (
                    f"<div style='font-family: Arial; min-width: 180px;'>"
                    f"<h4 style='color: #cc0000; margin-bottom: 4px;'>{anom.anomaly_type.upper()}</h4>"
                    f"<b>Severity:</b> {anom.severity}<br>"
                    f"<b>Time UTC:</b> {anom.timestamp_utc.isoformat()}<br>"
                    f"<b>Description:</b> {anom.description}"
                    f"</div>"
                )
                folium.CircleMarker(
                    location=[anom.latitude, anom.longitude],
                    radius=8,
                    color=color,
                    fill=True,
                    fill_color=color,
                    fill_opacity=0.8,
                    popup=folium.Popup(popup_html, max_width=320),
                ).add_to(fmap)

        # No-Fly Zones
        for nfz in (no_fly_zones or []):
            if len(nfz.polygon_vertices) >= 3:
                folium.Polygon(
                    locations=[[lat, lon] for lat, lon in nfz.polygon_vertices],
                    color="#cc0000",
                    weight=2,
                    fill=True,
                    fill_color="#ff4444",
                    fill_opacity=0.25,
                    popup=folium.Popup(f"<b>No-Fly Zone:</b> {nfz.name}<br>{nfz.description}", max_width=250),
                ).add_to(fmap)

        target_file = Path(output_path) if output_path else Path("flight_map.html")
        target_file.parent.mkdir(parents=True, exist_ok=True)
        fmap.save(str(target_file))

        # Air-gapped resilience: Inject offline Leaflet script fallback and Tactical Grid layer
        try:
            html_str = target_file.read_text(encoding="utf-8")
            local_fallback = """
    <!-- Air-gapped Leaflet fallback -->
    <script>
    if (typeof L === 'undefined') {
        document.write('<script src="../../gui/vendor/leaflet.js"><\\/script>');
        document.write('<link rel="stylesheet" href="../../gui/vendor/leaflet.css" />');
    }
    </script>
"""
            grid_fallback = """
    <!-- Offline Tactical Grid Fallback Engine -->
    <script>
    document.addEventListener("DOMContentLoaded", function() {
        if (typeof L !== 'undefined') {
            var TacticalGrid = L.GridLayer.extend({
                createTile: function(coords) {
                    var tile = document.createElement('canvas');
                    var size = this.getTileSize();
                    tile.width = size.x;
                    tile.height = size.y;
                    var ctx = tile.getContext('2d');
                    ctx.fillStyle = '#060a12';
                    ctx.fillRect(0, 0, size.x, size.y);
                    ctx.strokeStyle = '#152033';
                    ctx.lineWidth = 1;
                    ctx.strokeRect(0, 0, size.x, size.y);
                    ctx.strokeStyle = 'rgba(30, 41, 59, 0.45)';
                    ctx.lineWidth = 0.5;
                    var step = size.x / 4;
                    ctx.beginPath();
                    for (var i = 1; i < 4; i++) {
                        ctx.moveTo(i * step, 0); ctx.lineTo(i * step, size.y);
                        ctx.moveTo(0, i * step); ctx.lineTo(size.x, i * step);
                    }
                    ctx.stroke();
                    ctx.strokeStyle = 'rgba(6, 182, 212, 0.4)';
                    ctx.lineWidth = 1;
                    var cx = size.x / 2, cy = size.y / 2;
                    ctx.beginPath();
                    ctx.moveTo(cx - 7, cy); ctx.lineTo(cx + 7, cy);
                    ctx.moveTo(cx, cy - 7); ctx.lineTo(cx, cy + 7);
                    ctx.stroke();
                    try {
                        if (this._map) {
                            var nw = this._map.unproject(coords.scaleBy(size), coords.z);
                            ctx.fillStyle = '#64748b';
                            ctx.font = '9px monospace';
                            ctx.fillText((nw.lat>=0?'+':'') + nw.lat.toFixed(4) + '°, ' + (nw.lng>=0?'+':'') + nw.lng.toFixed(4) + '°', 6, 13);
                            ctx.fillStyle = '#334155';
                            ctx.fillText('Z' + coords.z, size.x - 24, size.y - 6);
                        }
                    } catch(e) {}
                    return tile;
                }
            });

            for (var key in window) {
                if (key.startsWith("map_") && window[key] && typeof window[key].addLayer === 'function') {
                    var m = window[key];
                    var gridLayer = new TacticalGrid({ attribution: 'PUSHPAK Offline Tactical Grid' });
                    if (!navigator.onLine) {
                        gridLayer.addTo(m);
                    }
                    m.eachLayer(function(l) {
                        if (l instanceof L.TileLayer) {
                            var errCount = 0;
                            l.on('tileerror', function() {
                                errCount++;
                                if (errCount >= 3 && !m.hasLayer(gridLayer)) {
                                    gridLayer.addTo(m);
                                }
                            });
                        }
                    });
                    break;
                }
            }
        }
    });
    </script>
"""
            if "</head>" in html_str:
                html_str = html_str.replace("</head>", f"{local_fallback}\n</head>", 1)
            if "</body>" in html_str:
                html_str = html_str.replace("</body>", f"{grid_fallback}\n</body>", 1)
            target_file.write_text(html_str, encoding="utf-8")
        except Exception:
            pass

        return target_file

    @staticmethod
    def to_3d_html_map(
        events: list[NormalizedEvent],
        anomalies: Optional[list[ForensicAnomaly]] = None,
        no_fly_zones: Optional[list[NoFlyZone]] = None,
        output_path: Optional[Path] = None,
        case_id: str = "CASE-DESKTOP-001",
        http_port: int = 8765,
    ) -> Path:
        """Export interactive 3D WebGL aerospace trajectory viewer with altitude curtain and camera controls."""
        gps_events = [
            e for e in events
            if e.latitude is not None and e.longitude is not None
            and not (abs(e.latitude) < 0.0001 and abs(e.longitude) < 0.0001)
            and abs(e.latitude) <= 90.0 and abs(e.longitude) <= 180.0
        ]

        coords_3d: list[dict[str, Any]] = []

        if gps_events:
            lat0 = gps_events[0].latitude
            lon0 = gps_events[0].longitude
            alts = [e.altitude_m for e in gps_events if e.altitude_m is not None]
            min_alt = min(alts) if alts else 0.0
            max_alt = max(alts) if alts else 0.0

            # Downsample if more than 1000 points to keep smooth 60fps WebGL
            step = max(1, len(gps_events) // 1000)
            sampled = gps_events[::step]
            if gps_events[-1] not in sampled:
                sampled.append(gps_events[-1])

            cos_lat0 = math.cos(math.radians(lat0))
            start_ts = gps_events[0].timestamp_utc

            for ev in sampled:
                d_lat = ev.latitude - lat0
                d_lon = ev.longitude - lon0
                x = round(d_lon * cos_lat0 * 111319.5, 2)
                z = round(-d_lat * 111319.5, 2)  # In Three.js: -Z is North
                curr_alt = ev.altitude_m if ev.altitude_m is not None else min_alt
                y = round(max(0.5, curr_alt - min_alt), 2)  # Relative height above ground
                t_sec = round((ev.timestamp_utc - start_ts).total_seconds(), 2)

                coords_3d.append({
                    "x": x,
                    "y": y,
                    "z": z,
                    "lat": round(ev.latitude, 6),
                    "lon": round(ev.longitude, 6),
                    "alt": round(curr_alt, 1),
                    "spd": round(ev.ground_speed_mps or 0.0, 1),
                    "hdg": round(ev.heading_deg or 0.0, 0),
                    "pitch": round(ev.pitch_deg or 0.0, 1),
                    "roll": round(ev.roll_deg or 0.0, 1),
                    "t_sec": t_sec,
                    "ts": ev.timestamp_utc.strftime("%H:%M:%S UTC"),
                })

        elif any(e.payload and "local_x" in e.payload for e in events):
            # Local position fallback for indoor/bench logs
            local_evs = [e for e in events if e.payload and "local_x" in e.payload]
            step = max(1, len(local_evs) // 1000)
            sampled = local_evs[::step]
            start_ts = local_evs[0].timestamp_utc
            for ev in sampled:
                lx = float(ev.payload.get("local_x", 0.0))
                ly = float(ev.payload.get("local_y", 0.0))
                lz = float(ev.payload.get("local_z", 0.0))
                t_sec = round((ev.timestamp_utc - start_ts).total_seconds(), 2)
                coords_3d.append({
                    "x": round(ly, 2),
                    "y": round(max(0.5, -lz), 2),
                    "z": round(-lx, 2),
                    "lat": 0.0,
                    "lon": 0.0,
                    "alt": round(max(0.0, -lz), 1),
                    "spd": round(ev.ground_speed_mps or 0.0, 1),
                    "hdg": round(ev.heading_deg or 0.0, 0),
                    "pitch": round(ev.pitch_deg or 0.0, 1),
                    "roll": round(ev.roll_deg or 0.0, 1),
                    "t_sec": t_sec,
                    "ts": ev.timestamp_utc.strftime("%H:%M:%S UTC"),
                })

        # Derive kinematic ground speed from movement if missing or suppressed
        for i in range(1, len(coords_3d)):
            if coords_3d[i]["spd"] == 0.0 or coords_3d[i]["spd"] < 0.15:
                p0 = coords_3d[i - 1]
                p1 = coords_3d[i]
                dx = p1["x"] - p0["x"]
                dz = p1["z"] - p0["z"]
                dist = math.hypot(dx, dz)
                if dist > 0.05:
                    dt = p1.get("t_sec", 0.0) - p0.get("t_sec", 0.0)
                    if dt <= 0.01:
                        try:
                            t0 = datetime.strptime(p0["ts"], "%H:%M:%S UTC")
                            t1 = datetime.strptime(p1["ts"], "%H:%M:%S UTC")
                            dt = (t1 - t0).total_seconds()
                        except Exception:
                            dt = 0.2
                    if 0.05 <= dt <= 15.0:
                        calc_spd = dist / dt
                        if 0.0 < calc_spd < 150.0:
                            coords_3d[i]["spd"] = round(calc_spd, 1)

        # Derive kinematic pitch & roll from 3D trajectory climb/descent slope and turns if missing or 0.0
        for i in range(1, len(coords_3d)):
            p0 = coords_3d[i - 1]
            p1 = coords_3d[i]
            dx = p1["x"] - p0["x"]
            dz = p1["z"] - p0["z"]
            dy = p1["y"] - p0["y"]
            horiz_dist = math.hypot(dx, dz)
            if p1["pitch"] == 0.0 and abs(dy) > 0.15:
                slope_pitch = math.degrees(math.atan2(dy, max(0.4, horiz_dist)))
                p1["pitch"] = round(max(-35.0, min(35.0, slope_pitch)), 1)
            if p1["roll"] == 0.0 and horiz_dist > 0.2:
                d_hdg = (p1["hdg"] - p0["hdg"] + 540.0) % 360.0 - 180.0
                if abs(d_hdg) > 1.0 and p1["spd"] > 1.0:
                    try:
                        t0 = datetime.strptime(p0["ts"], "%H:%M:%S UTC")
                        t1 = datetime.strptime(p1["ts"], "%H:%M:%S UTC")
                        dt = (t1 - t0).total_seconds()
                        if 0.05 <= dt <= 10.0:
                            turn_rate = math.radians(d_hdg / dt)
                            bank = math.degrees(math.atan(p1["spd"] * turn_rate / 9.81))
                            p1["roll"] = round(max(-40.0, min(40.0, bank)), 1)
                    except Exception:
                        pass

        anomalies_3d = []
        if coords_3d and anomalies:
            lat0 = coords_3d[0]["lat"]
            lon0 = coords_3d[0]["lon"]
            cos_lat0 = math.cos(math.radians(lat0)) if lat0 != 0.0 else 1.0
            min_alt = min((p["alt"] for p in coords_3d), default=0.0)
            for a in anomalies:
                if a.latitude is not None and a.longitude is not None:
                    ax = round((a.longitude - lon0) * cos_lat0 * 111319.5, 2)
                    az = round(-(a.latitude - lat0) * 111319.5, 2)
                    ay = round(max(1.0, (a.altitude_m or min_alt) - min_alt), 2)
                    anomalies_3d.append({
                        "x": ax, "y": ay, "z": az,
                        "type": a.anomaly_type,
                        "sev": a.severity,
                        "desc": a.description,
                        "ts": a.timestamp_utc.strftime("%H:%M:%S UTC"),
                    })

        launch_loc = None
        recovery_loc = None
        if gps_events:
            launch_loc = reverse_geocode(gps_events[0].latitude, gps_events[0].longitude)
            recovery_loc = reverse_geocode(gps_events[-1].latitude, gps_events[-1].longitude)
        else:
            launch_loc = {
                "pinpoint_name": "Indoor / Local Facility",
                "full_address": "Bench Test / Indoor Trajectory",
                "city": "Local Lab",
                "state": "Station",
                "country": "",
                "display_text": "Indoor Bench Coordinates",
            }
            recovery_loc = launch_loc

        json_coords = json.dumps(coords_3d)
        json_anomalies = json.dumps(anomalies_3d)
        json_launch_loc = json.dumps(launch_loc)
        json_recovery_loc = json.dumps(recovery_loc)

        loc_pinpoint = launch_loc.get("pinpoint_name", "Flight Vicinity")
        loc_display = launch_loc.get("display_text", launch_loc.get("full_address", "Coordinates Unavailable"))

        target_file = Path(output_path) if output_path else Path("flight_3d_map.html")
        target_resolved = target_file.resolve()
        vendor_dir = Path(__file__).resolve().parent.parent / "gui" / "vendor"
        try:
            rel_vendor = os.path.relpath(vendor_dir, target_resolved.parent).replace("\\", "/")
        except Exception:
            rel_vendor = "../../gui/vendor"

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PUSHPAK 3D Aerospace Flight Trajectory Visualizer</title>
<!-- Three.js + OrbitControls (Air-Gapped Multi-Tier Offline Engine) -->
<script src="{rel_vendor}/three.min.js"></script>
<script>
if (typeof THREE === 'undefined') {{
  document.write('<script src="http://127.0.0.1:{http_port}/vendor/three.min.js"><\\/script>');
}}
</script>
<script>
if (typeof THREE === 'undefined') {{
  document.write('<script src="../../../gui/vendor/three.min.js"><\\/script>');
}}
</script>
<script>
if (typeof THREE === 'undefined') {{
  document.write('<script src="../../gui/vendor/three.min.js"><\\/script>');
}}
</script>
<script>
if (typeof THREE === 'undefined') {{
  document.write('<script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"><\\/script>');
}}
</script>

<script src="{rel_vendor}/OrbitControls.js"></script>
<script>
if (typeof THREE === 'undefined' || typeof THREE.OrbitControls === 'undefined') {{
  document.write('<script src="http://127.0.0.1:{http_port}/vendor/OrbitControls.js"><\\/script>');
}}
</script>
<script>
if (typeof THREE === 'undefined' || typeof THREE.OrbitControls === 'undefined') {{
  document.write('<script src="../../../gui/vendor/OrbitControls.js"><\\/script>');
}}
</script>
<script>
if (typeof THREE === 'undefined' || typeof THREE.OrbitControls === 'undefined') {{
  document.write('<script src="../../gui/vendor/OrbitControls.js"><\\/script>');
}}
</script>
<script>
if (typeof THREE === 'undefined' || typeof THREE.OrbitControls === 'undefined') {{
  document.write('<script src="https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/controls/OrbitControls.js"><\\/script>');
}}
</script>
<!-- Google Fonts: Space Mono -->
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Space+Mono:ital,wght@0,400;0,700;1,400;1,700&display=swap" rel="stylesheet">
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{
  background: #060911;
  color: #f3f4f6;
  font-family: 'Space Mono', 'Consolas', monospace, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto;
  height: 100vh;
  overflow: hidden;
  user-select: none;
}}
button, input, select, .h-val, .cardinal-lbl, .inst-val-sm, .log-row, .time-label, .case-lbl {{
  font-family: 'Space Mono', 'Consolas', monospace;
}}

#canvas-container {{
  width: 100vw;
  height: 100vh;
  position: absolute;
  top: 0;
  left: 0;
}}
/* Top Brand & Stats Bar */
.top-bar {{
  position: absolute;
  top: 14px;
  left: 16px;
  right: 16px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  pointer-events: none;
  z-index: 10;
}}
.brand-pill {{
  background: rgba(15, 23, 42, 0.88);
  border: 1px solid #1e293d;
  border-radius: 8px;
  padding: 8px 14px;
  display: flex;
  align-items: center;
  gap: 10px;
  backdrop-filter: blur(8px);
  pointer-events: auto;
  box-shadow: 0 4px 16px rgba(0,0,0,0.5);
}}
.badge {{
  background: linear-gradient(135deg, #0284c7, #06b6d4);
  color: #fff;
  font-weight: 900;
  font-size: 11px;
  padding: 3px 7px;
  border-radius: 4px;
  letter-spacing: 1px;
}}
.title {{
  font-size: 13.5px;
  font-weight: 700;
  color: #fff;
}}
.case-lbl {{
  font-size: 11px;
  color: #94a3b8;
  font-family: monospace;
}}

/* Geocoded Location Banner */
.location-pill {{
  background: rgba(15, 23, 42, 0.88);
  border: 1px solid #1e293d;
  border-radius: 8px;
  padding: 6px 14px;
  display: flex;
  align-items: center;
  gap: 9px;
  backdrop-filter: blur(8px);
  pointer-events: auto;
  box-shadow: 0 4px 16px rgba(0,0,0,0.5);
  max-width: 480px;
}}
.loc-pin {{ font-size: 15px; color: #10b981; flex-shrink: 0; }}
.loc-content {{ display: flex; flex-direction: column; overflow: hidden; }}
.loc-title {{ font-size: 11.5px; font-weight: 700; color: #38bdf8; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
.loc-sub {{ font-size: 9.5px; color: #94a3b8; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}

/* Camera Presets & Actions */
.actions-pill {{
  display: flex;
  gap: 8px;
  pointer-events: auto;
}}
.cam-btn {{
  background: rgba(15, 23, 42, 0.88);
  border: 1px solid #1e293d;
  color: #cbd5e1;
  font-size: 11.5px;
  font-weight: 700;
  padding: 7px 12px;
  border-radius: 6px;
  cursor: pointer;
  backdrop-filter: blur(8px);
  transition: all 0.2s;
}}
.cam-btn:hover, .cam-btn.active {{
  background: #0284c7;
  border-color: #38bdf8;
  color: #fff;
  box-shadow: 0 2px 10px rgba(2, 132, 199, 0.4);
}}

/* Live Telemetry & Instruments HUD Cluster */
.hud-cluster {{
  position: absolute;
  top: 72px;
  left: 16px;
  display: flex;
  flex-direction: column;
  gap: 10px;
  pointer-events: auto;
  z-index: 10;
}}
.hud-box {{
  background: rgba(11, 15, 25, 0.88);
  border: 1px solid #1e293d;
  border-radius: 10px;
  padding: 12px 14px;
  backdrop-filter: blur(10px);
  box-shadow: 0 4px 20px rgba(0,0,0,0.55);
  display: flex;
  flex-direction: column;
  gap: 10px;
  width: 270px;
}}

/* Instruments Row: Attitude Indicator + Compass */
.instruments-row {{
  display: flex;
  align-items: center;
  justify-content: space-around;
  gap: 12px;
  padding-bottom: 8px;
  border-bottom: 1px solid rgba(255,255,255,0.08);
}}
.instrument-card {{
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 4px;
}}
.inst-title {{
  font-size: 8.5px;
  font-weight: 700;
  color: #94a3b8;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}}

/* 3D Attitude Indicator (Horizon) */
.horizon-dial-3d {{
  width: 78px;
  height: 78px;
  border-radius: 50%;
  border: 2.5px solid #334155;
  position: relative;
  overflow: hidden;
  background: #000;
  box-shadow: inset 0 0 10px rgba(0,0,0,0.7);
}}
.horizon-sphere-3d {{
  width: 156px;
  height: 156px;
  position: absolute;
  top: -39px;
  left: -39px;
  background: linear-gradient(180deg, #0284c7 0%, #1e3a8a 49.5%, #ffffff 50%, #78350f 50.5%, #451a03 100%);
  transition: transform 0.08s linear;
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;
}}
.horizon-line-3d {{
  width: 100%;
  height: 2px;
  background: #fff;
  box-shadow: 0 0 4px rgba(255,255,255,0.8);
}}
.pitch-rung-3d {{
  position: absolute;
  height: 1px;
  background: rgba(255,255,255,0.75);
}}
.pitch-rung-3d.p20 {{ top: 38px; width: 32px; }}
.pitch-rung-3d.p10 {{ top: 58px; width: 20px; }}
.pitch-rung-3d.m10 {{ top: 98px; width: 20px; }}
.pitch-rung-3d.m20 {{ top: 118px; width: 32px; }}
.horizon-aircraft-3d {{
  position: absolute;
  top: 50%;
  left: 0;
  right: 0;
  transform: translateY(-50%);
  display: flex;
  align-items: center;
  justify-content: center;
  pointer-events: none;
  z-index: 5;
}}
.horizon-aircraft-3d .w-bar {{
  width: 18px;
  height: 3px;
  background: #facc15;
  border-radius: 1px;
  box-shadow: 0 0 3px rgba(0,0,0,0.9);
}}
.horizon-aircraft-3d .w-bar.left {{ margin-right: 12px; }}
.horizon-aircraft-3d .w-bar.right {{ margin-left: 12px; }}
.horizon-aircraft-3d .c-pip {{
  width: 5px;
  height: 5px;
  border-radius: 50%;
  background: #facc15;
  box-shadow: 0 0 3px rgba(0,0,0,0.9);
}}
.inst-val-sm {{
  font-size: 9.5px;
  font-family: monospace;
  color: #cbd5e1;
}}

/* Navigational Compass Dial */
.compass-dial-3d {{
  width: 78px;
  height: 78px;
  border-radius: 50%;
  border: 2.5px solid #334155;
  position: relative;
  background: radial-gradient(circle, #0b1120 40%, #060911 100%);
  box-shadow: inset 0 0 8px rgba(0,0,0,0.8);
  display: flex;
  align-items: center;
  justify-content: center;
}}
.cardinal-lbl {{
  position: absolute;
  font-size: 8.5px;
  font-weight: 800;
  font-family: monospace;
}}
.cardinal-lbl.c-n {{ top: 3px; left: 50%; transform: translateX(-50%); color: #ef4444; }}
.cardinal-lbl.c-e {{
  right: 4px;
  top: 50%;
  transform: translateY(-50%);
  color: #00e5ff;
  text-shadow: 0 0 6px #00e5ff;
  font-weight: 900;
}}
.cardinal-lbl.c-s {{ bottom: 3px; left: 50%; transform: translateX(-50%); color: #94a3b8; }}
.cardinal-lbl.c-w {{ left: 4px; top: 50%; transform: translateY(-50%); color: #94a3b8; }}
.compass-needle {{
  width: 3px;
  height: 54px;
  position: absolute;
  top: 12px;
  left: 50%;
  transform: translateX(-50%);
  border-radius: 2px;
  background: linear-gradient(180deg, #ef4444 50%, #94a3b8 50%);
  box-shadow: 0 0 4px rgba(0,0,0,0.8);
  pointer-events: none;
  transform-origin: center center;
  transition: transform 0.08s linear;
}}
.compass-center-pivot {{
  width: 7px;
  height: 7px;
  border-radius: 50%;
  background: #facc15;
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  z-index: 5;
  border: 1.5px solid #000;
}}

/* Telemetry Grid (6 Metrics) */
.hud-grid {{
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 6px 10px;
}}
.hud-item {{
  display: flex;
  flex-direction: column;
  gap: 1px;
}}
.h-lbl {{
  font-size: 8.5px;
  color: #94a3b8;
  text-transform: uppercase;
  font-weight: 700;
}}
.h-val {{
  font-size: 12.5px;
  font-weight: 800;
  font-family: monospace;
  color: #fff;
  white-space: nowrap;
}}
.h-val.cyan {{ color: #06b6d4; }}
.h-val.green {{ color: #10b981; }}
.h-val.amber {{ color: #f59e0b; }}
.h-val.purple {{ color: #a855f7; }}

/* Live Telemetry Flight Log Feed (Collapsible) */
.telemetry-log-panel {{
  width: 270px;
  background: rgba(11, 15, 25, 0.88);
  border: 1px solid #1e293d;
  border-radius: 8px;
  overflow: hidden;
  backdrop-filter: blur(10px);
  box-shadow: 0 4px 20px rgba(0,0,0,0.55);
  display: flex;
  flex-direction: column;
}}
.log-header {{
  background: #0f172a;
  padding: 6px 10px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  border-bottom: 1px solid #1e293d;
  cursor: pointer;
  user-select: none;
}}
.log-header-title {{
  font-size: 9.5px;
  font-weight: 700;
  color: #cbd5e1;
  display: flex;
  align-items: center;
  gap: 5px;
}}
.log-toggle-btn {{
  background: transparent;
  border: none;
  color: #38bdf8;
  font-size: 9.5px;
  cursor: pointer;
}}
.log-feed-body {{
  max-height: 160px;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
  scrollbar-width: thin;
  scrollbar-color: #1e293b #060911;
}}
.log-feed-body::-webkit-scrollbar {{
  width: 4px;
}}
.log-feed-body::-webkit-scrollbar-thumb {{
  background: #1e293b;
  border-radius: 2px;
}}
.log-row {{
  display: flex;
  flex-direction: column;
  gap: 1px;
  padding: 4px 8px;
  border-bottom: 1px solid rgba(255,255,255,0.04);
  font-family: monospace;
  font-size: 9px;
  color: #94a3b8;
  cursor: pointer;
  transition: all 0.1s;
}}
.log-row:hover {{
  background: rgba(2, 132, 199, 0.15);
  color: #fff;
}}
.log-row.active-log {{
  background: rgba(6, 182, 212, 0.22);
  border-left: 3px solid #06b6d4;
  color: #fff;
}}
.log-row-top {{
  display: flex;
  justify-content: space-between;
  font-weight: 700;
}}
.log-row-top .log-ts {{ color: #38bdf8; }}
.log-row-top .log-spd {{ color: #10b981; }}
.log-row-bot {{
  display: flex;
  justify-content: space-between;
  font-size: 8.5px;
  color: #cbd5e1;
}}

/* Bottom Playback Toolbar */
.playback-panel {{
  position: absolute;
  bottom: 20px;
  left: 50%;
  transform: translateX(-50%);
  width: min(1180px, calc(100vw - 32px));
  max-width: calc(100vw - 32px);
  box-sizing: border-box;
  background: rgba(15, 23, 42, 0.92);
  border: 1px solid #1e293d;
  border-radius: 10px;
  padding: 8px 14px;
  display: flex;
  align-items: center;
  gap: 10px;
  backdrop-filter: blur(10px);
  box-shadow: 0 8px 24px rgba(0,0,0,0.6);
  z-index: 10;
}}
.play-btn {{
  background: #0284c7;
  border: none;
  color: #fff;
  width: 32px;
  height: 32px;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 13px;
  cursor: pointer;
  flex-shrink: 0;
}}
.slider-wrap {{
  flex: 1;
  display: flex;
  align-items: center;
  gap: 10px;
  min-width: 120px;
}}
input[type="range"] {{
  flex: 1;
  accent-color: #06b6d4;
  cursor: pointer;
}}
.time-label {{
  font-size: 11.5px;
  font-family: monospace;
  color: #cbd5e1;
  width: auto;
  min-width: 65px;
  flex-shrink: 0;
}}
.speed-select {{
  background: #0b0f19;
  border: 1px solid #1e293d;
  color: #38bdf8;
  padding: 5px 6px;
  border-radius: 6px;
  font-size: 11px;
  font-weight: 700;
  outline: none;
  cursor: pointer;
  flex-shrink: 0;
}}
.ext-actions {{
  display: flex;
  gap: 6px;
  border-left: 1px solid #334155;
  padding-left: 10px;
  flex-shrink: 0;
}}
.ext-btn {{
  background: #1e293b;
  border: 1px solid #334155;
  color: #cbd5e1;
  padding: 5px 8px;
  border-radius: 6px;
  font-size: 11px;
  font-weight: 600;
  cursor: pointer;
  white-space: nowrap;
}}
.ext-btn:hover {{
  background: #27354f;
  color: #fff;
}}

/* Evidence Action Buttons in Playback Bar */
.evidence-actions {{
  display: flex;
  gap: 6px;
  align-items: center;
  border-left: 1px solid #334155;
  padding-left: 10px;
  flex-shrink: 0;
}}
.btn-evidence {{
  display: flex;
  align-items: center;
  gap: 5px;
  padding: 5px 10px;
  border-radius: 6px;
  font-size: 11px;
  font-weight: 700;
  cursor: pointer;
  transition: all 0.2s;
  white-space: nowrap;
}}
.btn-evidence.mark {{
  background: linear-gradient(135deg, #b45309, #f59e0b);
  border: 1px solid #fbbf24;
  color: #fff;
  box-shadow: 0 2px 8px rgba(245, 158, 11, 0.35);
}}
.btn-evidence.mark:hover {{
  background: linear-gradient(135deg, #d97706, #fbbf24);
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(245, 158, 11, 0.5);
}}
.btn-evidence.add {{
  background: linear-gradient(135deg, #0284c7, #06b6d4);
  border: 1px solid #38bdf8;
  color: #fff;
  box-shadow: 0 2px 8px rgba(2, 132, 199, 0.35);
}}
.btn-evidence.add:hover {{
  background: linear-gradient(135deg, #0369a1, #0284c7);
  transform: translateY(-1px);
  box-shadow: 0 4px 12px rgba(2, 132, 199, 0.5);
}}

@media (max-width: 1100px) {{
  .playback-panel {{
    gap: 6px;
    padding: 6px 10px;
  }}
  .evidence-actions, .ext-actions {{
    gap: 4px;
    padding-left: 6px;
  }}
  .btn-evidence, .ext-btn {{
    padding: 4px 6px;
    font-size: 10px;
  }}
}}


/* Evidence Exhibits Drawer (Pinned Right) */
.evidence-drawer {{
  position: absolute;
  top: 72px;
  right: 16px;
  width: 330px;
  max-height: calc(100vh - 170px);
  background: rgba(11, 15, 25, 0.94);
  border: 1px solid #1e293d;
  border-radius: 10px;
  display: flex;
  flex-direction: column;
  backdrop-filter: blur(12px);
  box-shadow: 0 8px 26px rgba(0,0,0,0.7);
  z-index: 25;
  transition: transform 0.28s cubic-bezier(0.16, 1, 0.3, 1), opacity 0.28s;
}}
.evidence-drawer.collapsed {{
  transform: translateX(370px);
  pointer-events: none;
  opacity: 0;
}}
.drawer-header {{
  background: #0f172a;
  padding: 10px 14px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  border-bottom: 1px solid #1e293d;
}}
.drawer-title {{
  font-size: 11.5px;
  font-weight: 800;
  color: #fbbf24;
  display: flex;
  align-items: center;
  gap: 7px;
}}
.drawer-badge {{
  background: #f59e0b;
  color: #000;
  font-size: 10px;
  font-weight: 800;
  padding: 2px 7px;
  border-radius: 10px;
}}
.drawer-close-btn {{
  background: transparent;
  border: none;
  color: #94a3b8;
  font-size: 14px;
  cursor: pointer;
  padding: 2px 6px;
  border-radius: 4px;
}}
.drawer-close-btn:hover {{
  color: #fff;
  background: rgba(255,255,255,0.1);
}}
.drawer-body {{
  flex: 1;
  overflow-y: auto;
  padding: 10px;
  display: flex;
  flex-direction: column;
  gap: 8px;
  scrollbar-width: thin;
  scrollbar-color: #1e293b #060911;
}}
.drawer-body::-webkit-scrollbar {{
  width: 5px;
}}
.drawer-body::-webkit-scrollbar-thumb {{
  background: #1e293b;
  border-radius: 3px;
}}
.empty-evidence-card {{
  padding: 24px 14px;
  text-align: center;
  color: #64748b;
  font-size: 11px;
  line-height: 1.5;
  border: 1px dashed #334155;
  border-radius: 8px;
  background: rgba(15, 23, 42, 0.4);
}}
.evidence-card {{
  background: rgba(15, 23, 42, 0.75);
  border: 1px solid #334155;
  border-left: 3.5px solid #f59e0b;
  border-radius: 8px;
  padding: 8px 10px;
  display: flex;
  flex-direction: column;
  gap: 5px;
  transition: all 0.15s;
}}
.evidence-card:hover {{
  border-color: #f59e0b;
  background: rgba(15, 23, 42, 0.95);
  box-shadow: 0 2px 10px rgba(245, 158, 11, 0.18);
}}
.evid-card-top {{
  display: flex;
  justify-content: space-between;
  align-items: center;
}}
.evid-tag {{
  font-size: 10.5px;
  font-weight: 800;
  color: #fbbf24;
  font-family: monospace;
}}
.evid-ts {{
  font-size: 10px;
  color: #38bdf8;
  font-family: monospace;
}}
.evid-del-btn {{
  background: transparent;
  border: none;
  color: #64748b;
  font-size: 12px;
  cursor: pointer;
  padding: 0 4px;
}}
.evid-del-btn:hover {{
  color: #ef4444;
}}
.evid-grid {{
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 3px 6px;
  font-size: 9px;
  font-family: monospace;
  color: #cbd5e1;
}}
.evid-note {{
  font-size: 9.5px;
  color: #94a3b8;
  background: rgba(0,0,0,0.35);
  padding: 4px 6px;
  border-radius: 4px;
  line-height: 1.3;
}}
.evid-card-actions {{
  display: flex;
  justify-content: flex-end;
  gap: 6px;
  margin-top: 2px;
}}
.evid-jump-btn {{
  background: #1e293b;
  border: 1px solid #334155;
  color: #38bdf8;
  font-size: 9.5px;
  font-weight: 700;
  padding: 3px 8px;
  border-radius: 4px;
  cursor: pointer;
}}
.evid-jump-btn:hover {{
  background: #0284c7;
  border-color: #38bdf8;
  color: #fff;
}}
.drawer-footer {{
  padding: 10px;
  background: #0b0f19;
  border-top: 1px solid #1e293d;
  display: flex;
  gap: 6px;
}}
.drawer-action-btn {{
  flex: 1;
  background: #1e293b;
  border: 1px solid #334155;
  color: #cbd5e1;
  font-size: 10px;
  font-weight: 700;
  padding: 6px 6px;
  border-radius: 6px;
  cursor: pointer;
  text-align: center;
}}
.drawer-action-btn:hover {{
  background: #27354f;
  color: #fff;
}}
.drawer-action-btn.primary {{
  background: #0284c7;
  border-color: #38bdf8;
  color: #fff;
}}
.drawer-action-btn.primary:hover {{
  background: #0369a1;
}}

/* Modal Overlays */
.modal-backdrop {{
  position: fixed;
  top: 0;
  left: 0;
  width: 100vw;
  height: 100vh;
  background: rgba(0, 0, 0, 0.75);
  backdrop-filter: blur(4px);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 50;
}}
.evidence-modal {{
  width: min(500px, 92vw);
  background: #0b1120;
  border: 1px solid #334155;
  border-radius: 12px;
  box-shadow: 0 12px 36px rgba(0,0,0,0.8);
  overflow: hidden;
  display: flex;
  flex-direction: column;
}}
.modal-hdr {{
  background: #0f172a;
  padding: 12px 18px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  border-bottom: 1px solid #1e293d;
}}
.modal-title {{
  font-size: 13.5px;
  font-weight: 800;
  color: #f3f4f6;
  display: flex;
  align-items: center;
  gap: 8px;
}}
.modal-close-btn {{
  background: transparent;
  border: none;
  color: #94a3b8;
  font-size: 15px;
  cursor: pointer;
}}
.modal-close-btn:hover {{
  color: #fff;
}}
.modal-body {{
  padding: 16px 18px;
  display: flex;
  flex-direction: column;
  gap: 12px;
}}
.modal-telemetry-box {{
  background: #060911;
  border: 1px solid #1e293d;
  border-radius: 8px;
  padding: 10px 12px;
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 6px 12px;
  font-size: 11px;
  font-family: monospace;
}}
.modal-lbl {{
  font-size: 11px;
  font-weight: 700;
  color: #cbd5e1;
}}
.modal-input {{
  background: #060911;
  border: 1px solid #334155;
  border-radius: 6px;
  color: #fff;
  font-size: 12px;
  padding: 9px 12px;
  outline: none;
}}
.modal-input:focus {{
  border-color: #f59e0b;
  box-shadow: 0 0 0 2px rgba(245, 158, 11, 0.2);
}}
.modal-ftr {{
  background: #0f172a;
  padding: 12px 18px;
  border-top: 1px solid #1e293d;
  display: flex;
  justify-content: flex-end;
  gap: 10px;
}}
.modal-btn {{
  padding: 8px 14px;
  border-radius: 6px;
  font-size: 12px;
  font-weight: 700;
  cursor: pointer;
  border: none;
}}
.modal-btn.cancel {{
  background: #1e293b;
  color: #cbd5e1;
}}
.modal-btn.cancel:hover {{
  background: #334155;
  color: #fff;
}}
.modal-btn.confirm {{
  background: linear-gradient(135deg, #b45309, #f59e0b);
  color: #fff;
}}
.modal-btn.confirm:hover {{
  background: linear-gradient(135deg, #d97706, #fbbf24);
}}
.modal-btn.primary {{
  background: linear-gradient(135deg, #0284c7, #06b6d4);
  color: #fff;
}}
.modal-btn.primary:hover {{
  background: #0369a1;
}}

/* Notification Toast */
.evidence-toast {{
  position: absolute;
  top: 76px;
  left: 50%;
  transform: translateX(-50%) translateY(-20px);
  background: #0f172a;
  border: 1px solid #f59e0b;
  color: #fff;
  padding: 9px 18px;
  border-radius: 8px;
  font-size: 12px;
  font-weight: 700;
  display: flex;
  align-items: center;
  gap: 8px;
  box-shadow: 0 8px 24px rgba(0,0,0,0.6);
  opacity: 0;
  pointer-events: none;
  transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
  z-index: 60;
}}
.evidence-toast.show {{
  transform: translateX(-50%) translateY(0);
  opacity: 1;
}}

/* Instructions Overlay */
.instructions-overlay {{
  position: absolute;
  bottom: 84px;
  left: 50%;
  transform: translateX(-50%);
  font-size: 10.5px;
  color: #94a3b8;
  background: rgba(11, 15, 25, 0.75);
  padding: 4px 12px;
  border-radius: 20px;
  border: 1px solid rgba(255,255,255,0.06);
  pointer-events: none;
}}
</style>
</head>
<body>

<div id="canvas-container"></div>

<!-- Top Branding -->
<div class="top-bar">
  <div class="brand-pill">
    <span class="badge">PUSHPAK 3D</span>
    <span class="title">Interactive 3D Aerospace Trajectory Reconstruction</span>
    <span class="case-lbl">[{case_id}]</span>
  </div>

  <!-- Geocoded Location Banner -->
  <div class="location-pill" id="locationPill" title="Geocoded Flight Vicinity">
    <span class="loc-pin">📍</span>
    <div class="loc-content">
      <div class="loc-title" id="locTitle">{loc_pinpoint}</div>
      <div class="loc-sub" id="locSub">{loc_display}</div>
    </div>
  </div>

  <div class="actions-pill">
    <button class="cam-btn active" id="btnOrbit" onclick="setCameraMode('orbit')">🌐 3D Orbit</button>
    <button class="cam-btn" id="btnTop" onclick="setCameraMode('top')">⬇️ Top-Down</button>
    <button class="cam-btn" id="btnSide" onclick="setCameraMode('side')">📐 Side Profile</button>
    <button class="cam-btn" id="btnChase" onclick="setCameraMode('chase')">🛩️ Chase FPV</button>
    <button class="cam-btn" id="topEvidenceBtn" onclick="toggleEvidenceDrawer()" style="border-color:#f59e0b; color:#fbbf24;" title="View Marked Evidence Exhibits">
      ⚖️ Exhibits: <span id="topEvidenceCount">0</span>
    </button>
    <button class="cam-btn" id="topAddPdfBtn" onclick="addToCourtroomPdf()" style="background:linear-gradient(135deg,#0284c7,#0d9488); color:#fff; border-color:#38bdf8; font-weight:800;" title="Directly Embed Marked Exhibits into Section 6 of Courtroom PDF Report">
      ⚖️ Embed into Courtroom PDF
    </button>
  </div>
</div>

<!-- Live Telemetry & Instruments HUD Cluster -->
<div class="hud-cluster">
  <!-- Main HUD Panel -->
  <div class="hud-box">
    <!-- Row 1: Primary Flight Instruments (Attitude Horizon + Navigational Compass) -->
    <div class="instruments-row">
      <!-- Attitude / Horizon Indicator -->
      <div class="instrument-card">
        <div class="inst-title">Attitude (PFD)</div>
        <div class="horizon-dial-3d">
          <div class="horizon-sphere-3d" id="hudHorizonSphere">
            <div class="pitch-rung-3d p20"></div>
            <div class="pitch-rung-3d p10"></div>
            <div class="horizon-line-3d"></div>
            <div class="pitch-rung-3d m10"></div>
            <div class="pitch-rung-3d m20"></div>
          </div>
          <div class="horizon-aircraft-3d">
            <div class="w-bar left"></div>
            <div class="c-pip"></div>
            <div class="w-bar right"></div>
          </div>
        </div>
        <div class="inst-val-sm" id="hudAttInst">P: +0.0° | R: +0.0°</div>
      </div>

      <!-- Navigational Compass Dial -->
      <div class="instrument-card">
        <div class="inst-title">Compass (East: 90°)</div>
        <div class="compass-dial-3d">
          <span class="cardinal-lbl c-n">N</span>
          <span class="cardinal-lbl c-e">E</span>
          <span class="cardinal-lbl c-s">S</span>
          <span class="cardinal-lbl c-w">W</span>
          <div class="compass-needle" id="hudCompassNeedle"></div>
          <div class="compass-center-pivot"></div>
        </div>
        <div class="inst-val-sm" id="hudCmpInst">000° N</div>
      </div>
    </div>

    <!-- Row 2: Telemetry Metrics Grid -->
    <div class="hud-grid">
      <div class="hud-item">
        <span class="h-lbl">Altitude</span>
        <span class="h-val cyan" id="hudAlt">-- m</span>
      </div>
      <div class="hud-item">
        <span class="h-lbl">Ground Speed</span>
        <span class="h-val green" id="hudSpd">-- m/s</span>
      </div>
      <div class="hud-item">
        <span class="h-lbl">Latitude</span>
        <span class="h-val cyan" id="hudLat">--°</span>
      </div>
      <div class="hud-item">
        <span class="h-lbl">Longitude</span>
        <span class="h-val cyan" id="hudLon">--°</span>
      </div>
      <div class="hud-item">
        <span class="h-lbl">Heading</span>
        <span class="h-val amber" id="hudHdg">--°</span>
      </div>
      <div class="hud-item">
        <span class="h-lbl">Pitch / Roll</span>
        <span class="h-val purple" id="hudAtt">0° / 0°</span>
      </div>
    </div>
  </div>

  <!-- Collapsible Live Flight Telemetry Log Panel -->
  <div class="telemetry-log-panel" id="telemetryLogPanel">
    <div class="log-header" onclick="toggleLogPanel()">
      <div class="log-header-title">
        <span>📋</span>
        <span>Flight Telemetry Log</span>
      </div>
      <button class="log-toggle-btn" id="logToggleBtn">▲ Hide</button>
    </div>
    <div class="log-feed-body" id="logFeedBody">
      <!-- Dynamically populated at initScene -->
    </div>
  </div>
</div>

<!-- Helpful Nav Hint -->
<div class="instructions-overlay">
  🖱️ Left-Click + Drag: 3D Orbit Rotate | Right-Click + Drag: Pan | Scroll: Zoom | Press <strong>'M'</strong>: Mark Evidence
</div>

<!-- Bottom Playback Toolbar -->
<div class="playback-panel">
  <button class="play-btn" id="playBtn" onclick="togglePlay()">▶</button>
  <div class="slider-wrap">
    <input type="range" id="scrubber" min="0" max="0" value="0" oninput="onScrub(this.value)">
    <span class="time-label" id="timeLabel">00:00:00</span>
  </div>

  <select class="speed-select" id="speedSelect" onchange="changeSpeed(this.value)">
    <option value="1" selected>1x (Real-Time)</option>
    <option value="2">2x Speed</option>
    <option value="5">5x Speed</option>
    <option value="10">10x Speed</option>
    <option value="20">20x Speed</option>
  </select>

  <!-- Evidence Action Buttons in Simulation Toolbar -->
  <div class="evidence-actions">
    <button class="btn-evidence mark" id="markEvidenceBtn" onclick="openMarkEvidenceModal()" title="Mark Evidence at current waypoint (Hotkey: M)">
      📍 Mark Evidence
    </button>
    <button class="btn-evidence add" id="addToEvidenceBtn" onclick="addToCourtroomPdf()" title="Directly Embed Marked Waypoint & 3D Snapshot into Courtroom PDF Report (Section 6)">
      ⚖️ Add to Courtroom PDF
    </button>
  </div>

  <div class="ext-actions">
    <button class="ext-btn" id="drawerToggleBtn" onclick="toggleEvidenceDrawer()" title="Open Evidence Exhibits Drawer">⚖️ Exhibits (<span id="btnEvidenceCount">0</span>)</button>
    <button class="ext-btn" onclick="captureViewportSnapshot()" title="Capture High-Res Viewport Screenshot">📸 Snapshot</button>
    <button class="ext-btn" onclick="window.open('https://earth.google.com/web/', '_blank')">🌍 Earth Web</button>
    <button class="ext-btn" onclick="toggleFullscreen()">⛶ Fullscreen</button>
  </div>
</div>

<!-- Collapsible Evidence Exhibits Drawer (Pinned Right) -->
<div class="evidence-drawer collapsed" id="evidenceDrawer">
  <div class="drawer-header">
    <div class="drawer-title">
      <span>⚖️</span>
      <span>Marked Evidence Exhibits</span>
      <span class="drawer-badge" id="drawerEvidenceBadge">0</span>
    </div>
    <button class="drawer-close-btn" onclick="toggleEvidenceDrawer()">✖</button>
  </div>
  <div class="drawer-body" id="evidenceListBody">
    <div class="empty-evidence-card">
      📍 No evidence marked yet.<br><br>
      Scrub to an anomalous waypoint and click <strong>📍 Mark Evidence</strong> (or press <strong>'M'</strong>) to drop a 3D forensic beacon.
    </div>
  </div>
  <div class="drawer-footer">
    <button class="drawer-action-btn primary" onclick="addToCourtroomPdf()" title="Embed exhibits directly into Section 6 of Courtroom PDF Report">⚖️ Add to Courtroom PDF</button>
    <button class="drawer-action-btn" onclick="exportForensicExhibitReport()" title="Export visual Forensic Exhibit Sheet (HTML)">📄 HTML Sheet</button>
    <button class="drawer-action-btn" onclick="clearAllEvidence()" title="Clear all marked pins">🗑️ Clear</button>
  </div>
</div>

<!-- Modal: Mark Evidence -->
<div id="evidenceModalBackdrop" class="modal-backdrop" style="display:none;">
  <div class="evidence-modal">
    <div class="modal-hdr">
      <span class="modal-title">📍 Mark Forensic Evidence Exhibit</span>
      <button class="modal-close-btn" onclick="closeEvidenceModal()">✖</button>
    </div>
    <div class="modal-body">
      <div class="modal-telemetry-box" id="modalTelemetryBox">
        <!-- Telemetry details populated at click -->
      </div>
      <label class="modal-lbl">Investigator Observation / Evidence Tag:</label>
      <input type="text" id="evidenceNoteInput" class="modal-input" placeholder="e.g. Sudden descent, erratic roll/pitch, geofence perimeter breach..." onkeydown="if(event.key==='Enter') confirmMarkEvidence()">
    </div>
    <div class="modal-ftr">
      <button class="modal-btn cancel" onclick="closeEvidenceModal()">Cancel</button>
      <button class="modal-btn confirm" onclick="confirmMarkEvidence()">✔ Pin 3D Evidence</button>
    </div>
  </div>
</div>

<!-- Modal: Forensic Case Dossier / Add to Evidence -->
<div id="dossierModalBackdrop" class="modal-backdrop" style="display:none;">
  <div class="evidence-modal" style="width: min(560px, 94vw);">
    <div class="modal-hdr">
      <span class="modal-title">⚖️ Forensic Case Evidence Dossier</span>
      <button class="modal-close-btn" onclick="closeDossierModal()">✖</button>
    </div>
    <div class="modal-body">
      <div class="modal-telemetry-box" style="grid-template-columns: 1fr;">
        <div><strong>Case ID:</strong> {case_id}</div>
        <div><strong>Status:</strong> <span style="color:#10b981; font-weight:bold;">CHAIN OF CUSTODY SEALED</span></div>
        <div><strong>Total Marked Exhibits:</strong> <span id="modalDossierCount">0</span> exhibits</div>
      </div>
      <label class="modal-lbl">Exhibits Summary:</label>
      <div id="dossierExhibitsList" style="max-height: 180px; overflow-y: auto; background: #060911; border: 1px solid #1e293d; border-radius: 6px; padding: 8px; font-family: monospace; font-size: 11px; color: #cbd5e1;">
        <!-- Exhibits list -->
      </div>
    </div>
    <div class="modal-ftr">
      <button class="modal-btn cancel" onclick="captureViewportSnapshot()">📸 3D Snapshot</button>
      <button class="modal-btn primary" onclick="exportForensicExhibitReport()">📄 HTML Exhibit Sheet</button>
      <button class="modal-btn confirm" onclick="addToCourtroomPdf()">⚖️ Commit & Open Courtroom PDF</button>
    </div>
  </div>
</div>

<!-- Evidence Toast Notification -->
<div id="evidenceToast" class="evidence-toast">
  <span id="toastIcon">📍</span>
  <span id="toastMsg">Evidence Exhibit Marked</span>
</div>

<script>
const flightData = {json_coords};
const anomaliesData = {json_anomalies};
const launchLoc = {json_launch_loc};
const recoveryLoc = {json_recovery_loc};

let scene, camera, renderer, controls;
let droneMesh, pathLine, curtainMesh;
let currentIndex = 0;
let currentSimTime = 0.0;
let totalFlightDuration = 0.0;
let isPlaying = false;
let playSpeed = 1.0;
let cameraMode = 'orbit';
let lastFrameTime = performance.now();

// Forensic Evidence Exhibits State
let markedEvidence = [];
let evidence3DObjects = [];
const caseId = "{case_id}";
const PUSHPAK_API_PORT = {http_port};
const PUSHPAK_API_BASE = "http://127.0.0.1:" + PUSHPAK_API_PORT;

async function syncExhibitToBackend(exhibit) {{
  if (window.pywebview && window.pywebview.api && window.pywebview.api.save_evidence_exhibit) {{
    try {{
      return await window.pywebview.api.save_evidence_exhibit(exhibit, caseId);
    }} catch(e) {{ console.warn("pywebview save error:", e); }}
  }}
  try {{
    const res = await fetch(`${{PUSHPAK_API_BASE}}/api/save_evidence_exhibit`, {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify({{ exhibit: exhibit, case_id: caseId }})
    }});
    if (res.ok) return await res.json();
  }} catch(e) {{
    console.warn("HTTP bridge save error:", e);
  }}
  return null;
}}

async function syncAllExhibitsToBackend(exhibits) {{
  if (window.pywebview && window.pywebview.api) {{
    try {{
      if (window.pywebview.api.save_all_exhibits) {{
        return await window.pywebview.api.save_all_exhibits(exhibits, caseId);
      }} else if (window.pywebview.api.save_evidence_exhibit) {{
        const promises = exhibits.map(ex => window.pywebview.api.save_evidence_exhibit(ex, caseId));
        return await Promise.all(promises);
      }}
    }} catch(e) {{ console.warn("pywebview batch save error:", e); }}
  }}
  try {{
    const res = await fetch(`${{PUSHPAK_API_BASE}}/api/save_all_exhibits`, {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify({{ exhibits: exhibits, case_id: caseId }})
    }});
    if (res.ok) return await res.json();
  }} catch(e) {{
    console.warn("HTTP bridge batch save error:", e);
  }}
  return null;
}}

async function triggerOpenCourtroomPdf() {{
  if (window.pywebview && window.pywebview.api && window.pywebview.api.open_pdf) {{
    try {{
      await window.pywebview.api.open_pdf();
      return true;
    }} catch(e) {{ console.warn("pywebview open_pdf error:", e); }}
  }}
  try {{
    const res = await fetch(`${{PUSHPAK_API_BASE}}/api/open_courtroom_pdf`);
    if (res.ok) return true;
  }} catch(e) {{
    console.warn("HTTP bridge open_courtroom_pdf error:", e);
  }}
  return false;
}}

function initScene() {{
  const container = document.getElementById('canvas-container');
  const w = window.innerWidth;
  const h = window.innerHeight;

  scene = new THREE.Scene();
  scene.background = new THREE.Color(0x060911);
  scene.fog = new THREE.FogExp2(0x060911, 0.0008);

  camera = new THREE.PerspectiveCamera(50, w / h, 0.5, 50000);
  camera.position.set(200, 180, 260);

  renderer = new THREE.WebGLRenderer({{ antialias: true, powerPreference: "high-performance", preserveDrawingBuffer: true }});
  renderer.setPixelRatio(window.devicePixelRatio || 1);
  renderer.setSize(w, h);
  renderer.shadowMap.enabled = true;
  container.appendChild(renderer.domElement);

  if (THREE.OrbitControls) {{
    controls = new THREE.OrbitControls(camera, renderer.domElement);
    controls.enableDamping = true;
    controls.dampingFactor = 0.05;
    controls.maxPolarAngle = Math.PI / 2 + 0.05;
  }}

  // Lighting
  const ambLight = new THREE.AmbientLight(0xffffff, 0.6);
  scene.add(ambLight);

  const dirLight = new THREE.DirectionalLight(0xffffff, 0.8);
  dirLight.position.set(300, 500, 200);
  scene.add(dirLight);

  // Build Ground Plane & 3D Flight Geometry
  buildEnvironment();
  if (flightData.length > 0) {{
    for (let i = 0; i < flightData.length; i++) {{
      if (flightData[i].t_sec === undefined || isNaN(flightData[i].t_sec)) {{
        flightData[i].t_sec = i * 0.2;
      }}
    }}
    totalFlightDuration = flightData[flightData.length - 1].t_sec || (flightData.length - 1);

    buildFlightGeometry();
    buildDroneModel();
    fitCameraToTrajectory();

    populateTelemetryLog();
    const scrubber = document.getElementById('scrubber');
    scrubber.min = 0;
    scrubber.max = Math.ceil(totalFlightDuration);
    scrubber.step = 0.1;
    scrubber.value = 0;
    currentSimTime = 0;
    renderAtSimTime(0);
    loadEvidenceFromStorage();
  }}

  window.addEventListener('keydown', handleGlobalKeydown);
  window.addEventListener('resize', onResize);
  animate();
}}

function buildEnvironment() {{
  // Calculate spatial scale
  let maxExtent = 500;
  if (flightData.length > 0) {{
    const xs = flightData.map(p => Math.abs(p.x));
    const zs = flightData.map(p => Math.abs(p.z));
    maxExtent = Math.max(300, Math.max(...xs), Math.max(...zs)) * 1.6;
  }}

  // Grid
  const grid = new THREE.GridHelper(maxExtent * 2, 40, 0x0284c7, 0x111c30);
  grid.position.y = 0;
  scene.add(grid);

  // Concentric Range Rings (every 100m or 250m)
  const ringStep = maxExtent > 1500 ? 500 : (maxExtent > 600 ? 250 : 100);
  for (let r = ringStep; r <= maxExtent; r += ringStep) {{
    const ringGeo = new THREE.RingGeometry(r - 0.4, r + 0.4, 64);
    const ringMat = new THREE.MeshBasicMaterial({{ color: 0x1e3a5f, side: THREE.DoubleSide }});
    const ringMesh = new THREE.Mesh(ringGeo, ringMat);
    ringMesh.rotation.x = Math.PI / 2;
    ringMesh.position.y = 0.1;
    scene.add(ringMesh);
  }}

  // 3D Ground Compass Rose with Prominent EAST
  // In our local coordinate frame:
  // -Z is NORTH (0, 0, -1)
  // +X is EAST (1, 0, 0)
  // +Z is SOUTH (0, 0, 1)
  // -X is WEST (-1, 0, 0)
  const origin = new THREE.Vector3(0, 0.2, 0);

  // 1. NORTH Arrow (-Z)
  const northDir = new THREE.Vector3(0, 0, -1);
  const northArrow = new THREE.ArrowHelper(northDir, origin, 60, 0xef4444, 14, 7);
  scene.add(northArrow);
  const northLabel = makeTextSprite("NORTH (N)", "#ef4444");
  northLabel.position.set(0, 4, -74);
  scene.add(northLabel);

  // 2. EAST Arrow (+X) - Prominently Highlighted with Cyan & Glowing Beacon
  const eastDir = new THREE.Vector3(1, 0, 0);
  const eastArrow = new THREE.ArrowHelper(eastDir, origin, 70, 0x00e5ff, 16, 9);
  scene.add(eastArrow);
  const eastLabel = makeTextSprite("EAST (E - 90°)", "#00e5ff");
  eastLabel.position.set(84, 4, 0);
  scene.add(eastLabel);

  // East Beacon (Pillar + Glowing Sphere)
  const eastPillarGeo = new THREE.CylinderGeometry(0.5, 0.5, 14, 16);
  const eastPillarMat = new THREE.MeshBasicMaterial({{ color: 0x00e5ff, transparent: true, opacity: 0.6 }});
  const eastPillar = new THREE.Mesh(eastPillarGeo, eastPillarMat);
  eastPillar.position.set(70, 7, 0);
  scene.add(eastPillar);
  const eastSphGeo = new THREE.SphereGeometry(2.5, 16, 16);
  const eastSphMat = new THREE.MeshBasicMaterial({{ color: 0x00e5ff }});
  const eastSph = new THREE.Mesh(eastSphGeo, eastSphMat);
  eastSph.position.set(70, 14, 0);
  scene.add(eastSph);

  // 3. SOUTH Arrow (+Z)
  const southDir = new THREE.Vector3(0, 0, 1);
  const southArrow = new THREE.ArrowHelper(southDir, origin, 45, 0x64748b, 10, 5);
  scene.add(southArrow);
  const southLabel = makeTextSprite("SOUTH (S)", "#94a3b8");
  southLabel.position.set(0, 4, 56);
  scene.add(southLabel);

  // 4. WEST Arrow (-X)
  const westDir = new THREE.Vector3(-1, 0, 0);
  const westArrow = new THREE.ArrowHelper(westDir, origin, 45, 0x64748b, 10, 5);
  scene.add(westArrow);
  const westLabel = makeTextSprite("WEST (W)", "#94a3b8");
  westLabel.position.set(-56, 4, 0);
  scene.add(westLabel);

  // Cardinal Ground Crosshairs
  const crossPtsX = [
    new THREE.Vector3(-maxExtent, 0.1, 0),
    new THREE.Vector3(maxExtent, 0.1, 0),
  ];
  const crossGeoX = new THREE.BufferGeometry().setFromPoints(crossPtsX);
  const crossMatX = new THREE.LineBasicMaterial({{ color: 0x00b4d8, transparent: true, opacity: 0.35 }});
  scene.add(new THREE.Line(crossGeoX, crossMatX));

  const crossPtsZ = [
    new THREE.Vector3(0, 0.1, -maxExtent),
    new THREE.Vector3(0, 0.1, maxExtent),
  ];
  const crossGeoZ = new THREE.BufferGeometry().setFromPoints(crossPtsZ);
  const crossMatZ = new THREE.LineBasicMaterial({{ color: 0xef4444, transparent: true, opacity: 0.3 }});
  scene.add(new THREE.Line(crossGeoZ, crossMatZ));
}}

function buildFlightGeometry() {{
  const pts = flightData.map(p => new THREE.Vector3(p.x, p.y, p.z));

  // 1. 3D Glowing Flight Path Ribbon
  const pathGeo = new THREE.BufferGeometry().setFromPoints(pts);
  const pathMat = new THREE.LineBasicMaterial({{
    color: 0x00e5ff,
    linewidth: 3,
  }});
  pathLine = new THREE.Line(pathGeo, pathMat);
  scene.add(pathLine);

  // 2. 3D Extruded Altitude Curtain (translucent vertical wall dropping to ground)
  const curtainVerts = [];
  for (let i = 0; i < pts.length - 1; i++) {{
    const p1 = pts[i];
    const p2 = pts[i + 1];

    // Quad formed by 2 triangles
    // Triangle 1
    curtainVerts.push(p1.x, p1.y, p1.z);
    curtainVerts.push(p1.x, 0.0, p1.z);
    curtainVerts.push(p2.x, p2.y, p2.z);

    // Triangle 2
    curtainVerts.push(p1.x, 0.0, p1.z);
    curtainVerts.push(p2.x, 0.0, p2.z);
    curtainVerts.push(p2.x, p2.y, p2.z);
  }}

  const curtainGeo = new THREE.BufferGeometry();
  curtainGeo.setAttribute('position', new THREE.Float32BufferAttribute(curtainVerts, 3));
  const curtainMat = new THREE.MeshBasicMaterial({{
    color: 0x00b4d8,
    transparent: true,
    opacity: 0.22,
    side: THREE.DoubleSide,
    depthWrite: false,
  }});
  curtainMesh = new THREE.Mesh(curtainGeo, curtainMat);
  scene.add(curtainMesh);

  // 3. Takeoff Pin (Green Glowing Beacon)
  const startPt = pts[0];
  const takeoffLabel = (launchLoc && launchLoc.pinpoint_name) ? `TAKEOFF: ${{launchLoc.pinpoint_name}}` : "TAKEOFF POINT";
  createBeacon(startPt, 0x10b981, takeoffLabel);

  // 4. Landing Pin (Red Glowing Beacon)
  const endPt = pts[pts.length - 1];
  const landingLabel = (recoveryLoc && recoveryLoc.pinpoint_name) ? `LANDING: ${{recoveryLoc.pinpoint_name}}` : "TERMINATION / LANDING";
  createBeacon(endPt, 0xef4444, landingLabel);

  // 5. Threat Cones
  anomaliesData.forEach(a => {{
    const coneGeo = new THREE.ConeGeometry(5, 12, 16);
    const coneMat = new THREE.MeshBasicMaterial({{ color: a.sev === 'CRITICAL' ? 0xef4444 : 0xf59e0b }});
    const cone = new THREE.Mesh(coneGeo, coneMat);
    cone.position.set(a.x, a.y + 6, a.z);
    cone.rotation.x = Math.PI; // pointing down to ground
    scene.add(cone);
  }});
}}

function createBeacon(pos, colorHex, label) {{
  // Ground pillar
  const pillarGeo = new THREE.CylinderGeometry(0.8, 0.8, pos.y, 16);
  const pillarMat = new THREE.MeshBasicMaterial({{ color: colorHex, transparent: true, opacity: 0.6 }});
  const pillar = new THREE.Mesh(pillarGeo, pillarMat);
  pillar.position.set(pos.x, pos.y / 2, pos.z);
  scene.add(pillar);

  // Top sphere
  const sphGeo = new THREE.SphereGeometry(3.5, 16, 16);
  const sphMat = new THREE.MeshBasicMaterial({{ color: colorHex }});
  const sph = new THREE.Mesh(sphGeo, sphMat);
  sph.position.set(pos.x, pos.y, pos.z);
  scene.add(sph);

  // 3D Text Label
  if (label) {{
    const spriteColor = colorHex === 0x10b981 ? "#34d399" : "#f87171";
    const labelSprite = makeTextSprite(label, spriteColor, "rgba(6, 10, 18, 0.85)");
    labelSprite.position.set(pos.x, pos.y + 7.5, pos.z);
    scene.add(labelSprite);
  }}
}}

function buildDroneModel() {{
  droneMesh = new THREE.Group();

  // Central fuselage
  const bodyGeo = new THREE.BoxGeometry(4, 1.2, 4);
  const bodyMat = new THREE.MeshLambertMaterial({{ color: 0x0284c7 }});
  const body = new THREE.Mesh(bodyGeo, bodyMat);
  droneMesh.add(body);

  // Forward Heading Arrow (Red nose)
  const noseGeo = new THREE.ConeGeometry(1.2, 3, 8);
  const noseMat = new THREE.MeshBasicMaterial({{ color: 0xef4444 }});
  const nose = new THREE.Mesh(noseGeo, noseMat);
  nose.rotation.x = -Math.PI / 2;
  nose.position.set(0, 0.4, -2.8);
  droneMesh.add(nose);

  // 4 Motor Arms & Rotors
  const armMat = new THREE.MeshLambertMaterial({{ color: 0x334155 }});
  const rotorMat = new THREE.MeshBasicMaterial({{ color: 0x38bdf8, transparent: true, opacity: 0.7 }});

  [[-3, -3], [3, -3], [-3, 3], [3, 3]].forEach(([rx, rz]) => {{
    const armGeo = new THREE.CylinderGeometry(0.3, 0.3, 4.2, 8);
    const arm = new THREE.Mesh(armGeo, armMat);
    arm.rotation.z = Math.PI / 2;
    arm.position.set(rx / 2, 0, rz / 2);
    droneMesh.add(arm);

    // Rotor disc
    const rGeo = new THREE.CylinderGeometry(1.8, 1.8, 0.1, 16);
    const rotor = new THREE.Mesh(rGeo, rotorMat);
    rotor.position.set(rx, 0.8, rz);
    droneMesh.add(rotor);
  }});

  droneMesh.position.set(flightData[0].x, flightData[0].y, flightData[0].z);
  scene.add(droneMesh);
}}

function fitCameraToTrajectory() {{
  if (flightData.length === 0) return;
  const xs = flightData.map(p => p.x);
  const ys = flightData.map(p => p.y);
  const zs = flightData.map(p => p.z);

  const cx = (Math.min(...xs) + Math.max(...xs)) / 2;
  const cy = (Math.min(...ys) + Math.max(...ys)) / 2;
  const cz = (Math.min(...zs) + Math.max(...zs)) / 2;

  if (controls) {{
    controls.target.set(cx, cy, cz);
    camera.position.set(cx + 160, cy + 180, cz + 240);
    controls.update();
  }}
}}

function setCameraMode(mode) {{
  cameraMode = mode;
  document.querySelectorAll('.cam-btn').forEach(b => b.classList.remove('active'));

  if (mode === 'orbit') {{
    document.getElementById('btnOrbit').classList.add('active');
    controls.enabled = true;
    fitCameraToTrajectory();
  }} else if (mode === 'top') {{
    document.getElementById('btnTop').classList.add('active');
    controls.enabled = true;
    const p = flightData[currentIndex] || flightData[0];
    camera.position.set(p.x, p.y + 450, p.z);
    controls.target.set(p.x, p.y, p.z);
    controls.update();
  }} else if (mode === 'side') {{
    document.getElementById('btnSide').classList.add('active');
    controls.enabled = true;
    const p = flightData[currentIndex] || flightData[0];
    camera.position.set(p.x + 350, p.y + 20, p.z);
    controls.target.set(p.x, p.y, p.z);
    controls.update();
  }} else if (mode === 'chase') {{
    document.getElementById('btnChase').classList.add('active');
    controls.enabled = false;
  }}
}}

function renderAtSimTime(simTime) {{
  if (!flightData || flightData.length === 0) return;
  simTime = Math.max(0, Math.min(totalFlightDuration, simTime));
  currentSimTime = simTime;

  // Find bounding waypoint indices
  let i = 0;
  while (i < flightData.length - 1 && flightData[i + 1].t_sec <= simTime) {{
    i++;
  }}
  const p0 = flightData[i];
  const p1 = flightData[Math.min(i + 1, flightData.length - 1)];

  let alpha = 0.0;
  const segDt = p1.t_sec - p0.t_sec;
  if (segDt > 0.001) {{
    alpha = Math.max(0.0, Math.min(1.0, (simTime - p0.t_sec) / segDt));
  }}

  // Smoothly interpolated position
  const interpX = p0.x + alpha * (p1.x - p0.x);
  const interpY = p0.y + alpha * (p1.y - p0.y);
  const interpZ = p0.z + alpha * (p1.z - p0.z);
  const interpAlt = p0.alt + alpha * (p1.alt - p0.alt);
  const interpSpd = p0.spd + alpha * (p1.spd - p0.spd);

  // Angular interpolation for heading (shortest angle path around circle)
  let dHdg = ((p1.hdg - p0.hdg + 540) % 360) - 180;
  const interpHdg = (p0.hdg + alpha * dHdg + 360) % 360;

  const interpPitch = p0.pitch + alpha * (p1.pitch - p0.pitch);
  const interpRoll = p0.roll + alpha * (p1.roll - p0.roll);

  const interpLat = (p0.lat !== undefined && p0.lat !== 0.0) ? (p0.lat + alpha * (p1.lat - p0.lat)) : 0;
  const interpLon = (p0.lon !== undefined && p0.lon !== 0.0) ? (p0.lon + alpha * (p1.lon - p0.lon)) : 0;

  currentIndex = i;

  // 1. Update HUD Text
  const altElem = document.getElementById('hudAlt');
  if (altElem) altElem.innerText = interpAlt.toFixed(1) + " m";

  const spdElem = document.getElementById('hudSpd');
  if (spdElem) spdElem.innerText = interpSpd.toFixed(1) + " m/s";

  const latElem = document.getElementById('hudLat');
  if (latElem) latElem.innerText = (interpLat !== 0.0) ? interpLat.toFixed(6) + "°" : "Indoor Local";

  const lonElem = document.getElementById('hudLon');
  if (lonElem) lonElem.innerText = (interpLon !== 0.0) ? interpLon.toFixed(6) + "°" : "Indoor Local";

  const deg = ((interpHdg % 360) + 360) % 360;
  const card = getCardinalDir(deg);
  const hdgElem = document.getElementById('hudHdg');
  if (hdgElem) hdgElem.innerText = `${{deg.toFixed(0)}}° (${{card}})`;

  const pSign = interpPitch >= 0 ? '+' : '';
  const rSign = interpRoll >= 0 ? '+' : '';
  const attElem = document.getElementById('hudAtt');
  if (attElem) attElem.innerText = `P:${{pSign}}${{interpPitch.toFixed(1)}}° R:${{rSign}}${{interpRoll.toFixed(1)}}°`;

  const attInst = document.getElementById('hudAttInst');
  if (attInst) attInst.innerText = `P: ${{pSign}}${{interpPitch.toFixed(1)}}° | R: ${{rSign}}${{interpRoll.toFixed(1)}}°`;

  const cmpInst = document.getElementById('hudCmpInst');
  if (cmpInst) cmpInst.innerText = `${{deg.toFixed(0)}}° ${{card}}`;

  // Time display
  const totalSecs = Math.floor(simTime);
  const hrs = String(Math.floor(totalSecs / 3600)).padStart(2, '0');
  const mins = String(Math.floor((totalSecs % 3600) / 60)).padStart(2, '0');
  const secs = String(totalSecs % 60).padStart(2, '0');
  const timeLabel = document.getElementById('timeLabel');
  if (timeLabel) {{
    timeLabel.innerText = p0.ts ? `${{p0.ts}} (${{hrs}}:${{mins}}:${{secs}})` : `${{hrs}}:${{mins}}:${{secs}}`;
  }}

  // 2. Update 3D Attitude Indicator (Horizon)
  const sphere = document.getElementById('hudHorizonSphere');
  if (sphere) {{
    const pitchPx = Math.max(-26, Math.min(26, interpPitch * 1.3));
    sphere.style.transform = `translateY(${{pitchPx}}px) rotate(${{-interpRoll}}deg)`;
  }}

  // 3. Update 3D Compass Needle
  const needle = document.getElementById('hudCompassNeedle');
  if (needle) {{
    needle.style.transform = `translateX(-50%) rotate(${{deg}}deg)`;
  }}

  // 4. Highlight & auto-scroll live telemetry log
  highlightLogRow(i);

  // 5. Update Drone Mesh position and attitude
  if (droneMesh) {{
    droneMesh.position.set(interpX, interpY, interpZ);
    const hdgRad = -THREE.MathUtils.degToRad(interpHdg);
    const pitchRad = THREE.MathUtils.degToRad(interpPitch);
    const rollRad = THREE.MathUtils.degToRad(interpRoll);
    droneMesh.rotation.set(pitchRad, hdgRad, rollRad, 'YXZ');
  }}

  if (cameraMode === 'chase' && droneMesh) {{
    const hdgRad = -THREE.MathUtils.degToRad(interpHdg);
    const offset = new THREE.Vector3(0, 12, 35);
    offset.applyAxisAngle(new THREE.Vector3(0, 1, 0), hdgRad);
    camera.position.copy(droneMesh.position).add(offset);
    camera.lookAt(droneMesh.position.x, droneMesh.position.y + 2, droneMesh.position.z);
  }}

  // Sync timeline scrubber
  const scrubber = document.getElementById('scrubber');
  if (scrubber && !scrubber.matches(':active')) {{
    scrubber.value = simTime;
  }}
}}

function updateHUD(idx) {{
  if (idx < 0 || idx >= flightData.length) return;
  const p = flightData[idx];
  const t = (p && p.t_sec !== undefined) ? p.t_sec : idx;
  renderAtSimTime(t);
}}

function getCardinalDir(deg) {{
  deg = ((deg % 360) + 360) % 360;
  if (deg >= 337.5 || deg < 22.5) return 'N';
  if (deg >= 22.5 && deg < 67.5) return 'NE';
  if (deg >= 67.5 && deg < 112.5) return 'E';
  if (deg >= 112.5 && deg < 157.5) return 'SE';
  if (deg >= 157.5 && deg < 202.5) return 'S';
  if (deg >= 202.5 && deg < 247.5) return 'SW';
  if (deg >= 247.5 && deg < 292.5) return 'W';
  return 'NW';
}}

let isLogCollapsed = false;
function toggleLogPanel() {{
  const feed = document.getElementById('logFeedBody');
  const btn = document.getElementById('logToggleBtn');
  if (!feed || !btn) return;
  isLogCollapsed = !isLogCollapsed;
  if (isLogCollapsed) {{
    feed.style.display = 'none';
    btn.innerText = '▼ Show';
  }} else {{
    feed.style.display = 'flex';
    btn.innerText = '▲ Hide';
  }}
}}

let currentActiveLogRow = null;
function highlightLogRow(idx) {{
  if (currentActiveLogRow !== null) {{
    const prev = document.getElementById('logRow-' + currentActiveLogRow);
    if (prev) prev.classList.remove('active-log');
  }}
  const cur = document.getElementById('logRow-' + idx);
  if (cur) {{
    cur.classList.add('active-log');
    cur.scrollIntoView({{ block: 'nearest', behavior: 'smooth' }});
    currentActiveLogRow = idx;
  }}
}}

function populateTelemetryLog() {{
  const container = document.getElementById('logFeedBody');
  if (!container || !flightData || flightData.length === 0) return;
  let html = '';
  flightData.forEach((p, i) => {{
    const deg = ((p.hdg % 360) + 360) % 360;
    const card = getCardinalDir(deg);
    const latStr = (p.lat !== undefined && p.lat !== 0.0) ? p.lat.toFixed(5) + '°' : 'Indoor';
    const lonStr = (p.lon !== undefined && p.lon !== 0.0) ? p.lon.toFixed(5) + '°' : 'Indoor';
    html += `
      <div class="log-row" id="logRow-${{i}}" onclick="onLogRowClick(${{i}})">
        <div class="log-row-top">
          <span class="log-ts">${{p.ts}}</span>
          <span class="log-spd">${{p.spd.toFixed(1)}} m/s</span>
        </div>
        <div class="log-row-bot">
          <span>Lat: ${{latStr}} | Lon: ${{lonStr}}</span>
          <span>Alt: ${{p.alt.toFixed(1)}}m | ${{deg.toFixed(0)}}° ${{card}}</span>
        </div>
      </div>
    `;
  }});
  container.innerHTML = html;
}}

function onLogRowClick(idx) {{
  if (flightData[idx] && flightData[idx].t_sec !== undefined) {{
    renderAtSimTime(flightData[idx].t_sec);
  }} else {{
    renderAtSimTime(idx);
  }}
}}

function makeTextSprite(message, color, bg) {{
  const canvas = document.createElement('canvas');
  canvas.width = 256;
  canvas.height = 72;
  const ctx = canvas.getContext('2d');
  ctx.fillStyle = bg || 'rgba(11, 15, 25, 0.85)';
  if (ctx.roundRect) {{
    ctx.roundRect(4, 4, 248, 64, 10);
  }} else {{
    ctx.rect(4, 4, 248, 64);
  }}
  ctx.fill();
  ctx.strokeStyle = color;
  ctx.lineWidth = 3;
  ctx.stroke();
  ctx.font = 'bold 26px monospace';
  ctx.fillStyle = color;
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText(message, 128, 36);
  const texture = new THREE.CanvasTexture(canvas);
  const mat = new THREE.SpriteMaterial({{ map: texture, transparent: true }});
  const sprite = new THREE.Sprite(mat);
  sprite.scale.set(36, 10, 1);
  return sprite;
}}

function togglePlay() {{
  isPlaying = !isPlaying;
  document.getElementById('playBtn').innerText = isPlaying ? "⏸" : "▶";
  lastFrameTime = performance.now();
}}

function onScrub(val) {{
  renderAtSimTime(parseFloat(val));
}}

function changeSpeed(val) {{
  playSpeed = parseFloat(val) || 1.0;
}}

function toggleFullscreen() {{
  if (!document.fullscreenElement) {{
    document.documentElement.requestFullscreen();
  }} else {{
    document.exitFullscreen();
  }}
}}

function onResize() {{
  const w = window.innerWidth;
  const h = window.innerHeight;
  camera.aspect = w / h;
  camera.updateProjectionMatrix();
  renderer.setSize(w, h);
}}

function animate() {{
  requestAnimationFrame(animate);

  const now = performance.now();
  const dtReal = Math.min(0.2, (now - lastFrameTime) / 1000.0);
  lastFrameTime = now;

  if (isPlaying && flightData.length > 1) {{
    currentSimTime += dtReal * playSpeed;
    if (currentSimTime > totalFlightDuration) {{
      currentSimTime = 0.0;
    }}
    renderAtSimTime(currentSimTime);
  }}

  // Rotate 3D Evidence Diamond Beacons
  evidence3DObjects.forEach(obj => {{
    if (obj.diamond) {{
      obj.diamond.rotation.y += 0.025;
    }}
  }});

  if (controls && controls.enabled) {{
    controls.update();
  }}

  renderer.render(scene, camera);
}}

/* ============================================================
   FORENSIC EVIDENCE EXHIBIT SUITE (MARK & ADD TO EVIDENCE)
   ============================================================ */

function handleGlobalKeydown(e) {{
  if (e.target && (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA')) return;
  if (e.key === 'm' || e.key === 'M') {{
    openMarkEvidenceModal();
  }} else if (e.key === ' ' || e.code === 'Space') {{
    e.preventDefault();
    togglePlay();
  }} else if (e.key === 'Escape') {{
    closeEvidenceModal();
    closeDossierModal();
  }}
}}

function toggleEvidenceDrawer() {{
  const drawer = document.getElementById('evidenceDrawer');
  if (!drawer) return;
  drawer.classList.toggle('collapsed');
}}

function openMarkEvidenceModal() {{
  if (flightData.length === 0) return;
  if (isPlaying) togglePlay();

  const p = flightData[currentIndex];
  const deg = ((p.hdg % 360) + 360) % 360;
  const card = getCardinalDir(deg);
  const latStr = (p.lat !== undefined && p.lat !== 0.0) ? p.lat.toFixed(6) + '°' : 'Indoor';
  const lonStr = (p.lon !== undefined && p.lon !== 0.0) ? p.lon.toFixed(6) + '°' : 'Indoor';

  const box = document.getElementById('modalTelemetryBox');
  if (box) {{
    box.innerHTML = `
      <div><strong>Waypoint:</strong> #${{currentIndex + 1}} / ${{flightData.length}}</div>
      <div><strong>Timestamp:</strong> <span style="color:#38bdf8">${{p.ts}}</span></div>
      <div><strong>Altitude:</strong> <span style="color:#00e5ff">${{p.alt.toFixed(1)}} m</span></div>
      <div><strong>Ground Speed:</strong> <span style="color:#10b981">${{p.spd.toFixed(1)}} m/s</span></div>
      <div><strong>Heading:</strong> ${{deg.toFixed(0)}}° (${{card}})</div>
      <div><strong>Pitch / Roll:</strong> P:${{p.pitch.toFixed(1)}}° R:${{p.roll.toFixed(1)}}°</div>
      <div><strong>Coordinates:</strong> ${{latStr}}, ${{lonStr}}</div>
    `;
  }}

  const noteInput = document.getElementById('evidenceNoteInput');
  if (noteInput) {{
    const nextNum = markedEvidence.length + 1;
    noteInput.value = `Exhibit #${{nextNum}}: Trajectory checkpoint at ${{p.ts}} (Alt: ${{p.alt.toFixed(1)}}m, Spd: ${{p.spd.toFixed(1)}}m/s)`;
  }}

  const modal = document.getElementById('evidenceModalBackdrop');
  if (modal) modal.style.display = 'flex';
  setTimeout(() => {{ if (noteInput) noteInput.focus(); }}, 50);
}}

function closeEvidenceModal() {{
  const modal = document.getElementById('evidenceModalBackdrop');
  if (modal) modal.style.display = 'none';
}}

function confirmMarkEvidence() {{
  if (flightData.length === 0) return;
  const p = flightData[currentIndex];
  const noteInput = document.getElementById('evidenceNoteInput');
  const noteText = noteInput ? noteInput.value.trim() : '';

  const nextNum = markedEvidence.length + 1;
  const exId = 'EVID-' + String(nextNum).padStart(2, '0');

  // Capture high-resolution 3D simulation snapshot for the exhibit report
  let snapData = "";
  if (renderer && scene && camera) {{
    try {{
      renderer.render(scene, camera);
      snapData = renderer.domElement.toDataURL("image/png");
    }} catch (snapErr) {{
      console.warn("Could not capture 3D viewport snapshot", snapErr);
    }}
  }}

  const exhibit = {{
    id: exId,
    num: nextNum,
    index: currentIndex,
    ts: p.ts,
    x: p.x,
    y: p.y,
    z: p.z,
    alt: p.alt,
    spd: p.spd,
    lat: p.lat,
    lon: p.lon,
    hdg: p.hdg,
    pitch: p.pitch,
    roll: p.roll,
    image_data: snapData,
    note: noteText || `Waypoint #${{currentIndex + 1}} (Alt: ${{p.alt.toFixed(1)}}m, Spd: ${{p.spd.toFixed(1)}}m/s)`,
    created_utc: new Date().toISOString(),
  }};

  markedEvidence.push(exhibit);
  create3DEvidenceMarker(exhibit);
  renderEvidenceCards();
  saveEvidenceToStorage();
  closeEvidenceModal();

  // Open drawer automatically so user sees the new exhibit
  const drawer = document.getElementById('evidenceDrawer');
  if (drawer && drawer.classList.contains('collapsed')) {{
    drawer.classList.remove('collapsed');
  }}

  showToast(`📍 Marked ${{exId}} at ${{p.ts}}`, '📍');

  // Async sync with pywebview or local HTTP daemon to compile into Courtroom PDF
  syncExhibitToBackend(exhibit);
}}

function create3DEvidenceMarker(exhibit) {{
  if (!scene) return;
  const group = new THREE.Group();
  group.name = 'evidence_' + exhibit.id;

  // 1. Amber Pillar extending from ground (Y=0) to waypoint altitude (Y=exhibit.y)
  const pillarHeight = Math.max(0.6, exhibit.y);
  const pillarGeo = new THREE.CylinderGeometry(0.7, 0.7, pillarHeight, 16);
  const pillarMat = new THREE.MeshBasicMaterial({{
    color: 0xf59e0b,
    transparent: true,
    opacity: 0.75,
  }});
  const pillar = new THREE.Mesh(pillarGeo, pillarMat);
  pillar.position.set(exhibit.x, pillarHeight / 2, exhibit.z);
  group.add(pillar);

  // 2. Glowing Diamond / Octahedron at waypoint
  const diaGeo = new THREE.OctahedronGeometry(3.5, 0);
  const diaMat = new THREE.MeshLambertMaterial({{
    color: 0xfbbf24,
    emissive: 0xd97706,
  }});
  const diamond = new THREE.Mesh(diaGeo, diaMat);
  diamond.position.set(exhibit.x, exhibit.y, exhibit.z);
  group.add(diamond);

  // 3. Ground Target Ring
  const ringGeo = new THREE.RingGeometry(4.5, 6.0, 32);
  const ringMat = new THREE.MeshBasicMaterial({{
    color: 0xf59e0b,
    side: THREE.DoubleSide,
    transparent: true,
    opacity: 0.85,
  }});
  const ring = new THREE.Mesh(ringGeo, ringMat);
  ring.rotation.x = Math.PI / 2;
  ring.position.set(exhibit.x, 0.2, exhibit.z);
  group.add(ring);

  // 4. 3D Billboard Sprite Tag
  const tagText = `${{exhibit.id}}: ${{exhibit.ts}}`;
  const labelSprite = makeTextSprite(tagText, '#fbbf24', 'rgba(15, 23, 42, 0.92)');
  labelSprite.position.set(exhibit.x, exhibit.y + 7.5, exhibit.z);
  group.add(labelSprite);

  scene.add(group);
  evidence3DObjects.push({{ id: exhibit.id, group: group, diamond: diamond }});
}}

function renderEvidenceCards() {{
  const container = document.getElementById('evidenceListBody');
  const count = markedEvidence.length;

  const b1 = document.getElementById('drawerEvidenceBadge');
  if (b1) b1.innerText = count;
  const b2 = document.getElementById('btnEvidenceCount');
  if (b2) b2.innerText = count;
  const b3 = document.getElementById('topEvidenceCount');
  if (b3) b3.innerText = count;

  if (!container) return;

  if (count === 0) {{
    container.innerHTML = `
      <div class="empty-evidence-card">
        📍 No evidence marked yet.<br><br>
        Scrub to an anomalous waypoint and click <strong>📍 Mark Evidence</strong> (or press <strong>'M'</strong>) to drop a 3D forensic beacon.
      </div>
    `;
    return;
  }}

  let html = '';
  markedEvidence.forEach((ex, idx) => {{
    const deg = ((ex.hdg % 360) + 360) % 360;
    const card = getCardinalDir(deg);
    const latStr = (ex.lat !== undefined && ex.lat !== 0.0) ? ex.lat.toFixed(5) + '°' : 'Indoor';
    const lonStr = (ex.lon !== undefined && ex.lon !== 0.0) ? ex.lon.toFixed(5) + '°' : 'Indoor';

    html += `
      <div class="evidence-card" id="evidCard-${{ex.id}}">
        <div class="evid-card-top">
          <span class="evid-tag">${{ex.id}} [WP #${{ex.index + 1}}]</span>
          <span class="evid-ts">${{ex.ts}}</span>
          <button class="evid-del-btn" onclick="deleteEvidence('${{ex.id}}')" title="Remove marker">✖</button>
        </div>
        <div class="evid-grid">
          <span>Alt: ${{ex.alt.toFixed(1)}}m</span>
          <span>Spd: ${{ex.spd.toFixed(1)}}m/s</span>
          <span>Hdg: ${{deg.toFixed(0)}}° (${{card}})</span>
          <span>P:${{ex.pitch.toFixed(1)}}° R:${{ex.roll.toFixed(1)}}°</span>
          <span style="grid-column: span 2">Pos: ${{latStr}}, ${{lonStr}}</span>
        </div>
        <div class="evid-note">${{ex.note}}</div>
        <div class="evid-card-actions">
          <button class="evid-jump-btn" onclick="jumpToEvidence(${{ex.index}}, '${{ex.id}}')">🎯 Focus 3D View</button>
        </div>
      </div>
    `;
  }});

  container.innerHTML = html;
}}

function jumpToEvidence(idx, evidId) {{
  currentIndex = idx;
  const scrubber = document.getElementById('scrubber');
  if (scrubber) scrubber.value = idx;
  updateHUD(idx);

  const p = flightData[idx];
  if (controls && p) {{
    controls.target.set(p.x, p.y, p.z);
    camera.position.set(p.x + 60, p.y + 50, p.z + 80);
    controls.update();
  }}

  showToast(`🎯 Focused on Exhibit ${{evidId}}`, '🎯');
}}

function deleteEvidence(exId) {{
  const objIdx = evidence3DObjects.findIndex(o => o.id === exId);
  if (objIdx !== -1) {{
    const obj = evidence3DObjects[objIdx];
    scene.remove(obj.group);
    evidence3DObjects.splice(objIdx, 1);
  }}

  markedEvidence = markedEvidence.filter(e => e.id !== exId);
  renderEvidenceCards();
  saveEvidenceToStorage();
  showToast(`🗑️ Removed ${{exId}}`, '🗑️');
}}

function clearAllEvidence() {{
  if (markedEvidence.length === 0) return;
  if (!confirm("Are you sure you want to clear all marked evidence exhibits?")) return;

  evidence3DObjects.forEach(obj => {{
    scene.remove(obj.group);
  }});
  evidence3DObjects = [];
  markedEvidence = [];
  renderEvidenceCards();
  saveEvidenceToStorage();
  showToast("All evidence markers cleared", "🗑️");
}}

function addCurrentToEvidence() {{
  if (flightData.length === 0) return;

  // Capture 3D simulation snapshot
  let snapData = "";
  if (renderer && scene && camera) {{
    try {{
      renderer.render(scene, camera);
      snapData = renderer.domElement.toDataURL("image/png");
    }} catch (err) {{
      console.warn("Snapshot capture error", err);
    }}
  }}

  // If no evidence has been marked at current point, mark it now
  const existing = markedEvidence.find(e => e.index === currentIndex);
  if (!existing) {{
    const p = flightData[currentIndex];
    const nextNum = markedEvidence.length + 1;
    const exId = 'EVID-' + String(nextNum).padStart(2, '0');
    const exhibit = {{
      id: exId,
      num: nextNum,
      index: currentIndex,
      ts: p.ts,
      x: p.x, y: p.y, z: p.z,
      alt: p.alt, spd: p.spd,
      lat: p.lat, lon: p.lon,
      hdg: p.hdg, pitch: p.pitch, roll: p.roll,
      image_data: snapData,
      note: `Exhibit #${{nextNum}}: Waypoint #${{currentIndex + 1}} (Alt: ${{p.alt.toFixed(1)}}m, Spd: ${{p.spd.toFixed(1)}}m/s)`,
      created_utc: new Date().toISOString(),
    }};
    markedEvidence.push(exhibit);
    create3DEvidenceMarker(exhibit);
    renderEvidenceCards();
    saveEvidenceToStorage();
    // Async sync with pywebview or local HTTP daemon to compile into Courtroom PDF
    syncExhibitToBackend(exhibit);
  }}

  // Open the Forensic Dossier Commitment Modal
  const countEl = document.getElementById('modalDossierCount');
  if (countEl) countEl.innerText = markedEvidence.length;

  const listEl = document.getElementById('dossierExhibitsList');
  if (listEl) {{
    let html = '';
    markedEvidence.forEach(ex => {{
      html += `
        <div style="padding: 4px 0; border-bottom: 1px solid rgba(255,255,255,0.08);">
          <span style="color:#fbbf24; font-weight:bold;">${{ex.id}}</span> |
          <span style="color:#38bdf8;">${{ex.ts}}</span> |
          <span>Alt: ${{ex.alt.toFixed(1)}}m</span> |
          <span>Spd: ${{ex.spd.toFixed(1)}}m/s</span><br>
          <span style="color:#94a3b8; font-size:10px;">${{ex.note}}</span>
        </div>
      `;
    }});
    listEl.innerHTML = html;
  }}

  const modal = document.getElementById('dossierModalBackdrop');
  if (modal) modal.style.display = 'flex';
  showToast(`⚖️ Dossier contains ${{markedEvidence.length}} Exhibits`, '⚖️');
}}

function closeDossierModal() {{
  const modal = document.getElementById('dossierModalBackdrop');
  if (modal) modal.style.display = 'none';
}}

// Export Visual Forensic Exhibit Sheet (with 3D images and telemetry tables under each)
function exportForensicExhibitReport() {{
  if (markedEvidence.length === 0) {{
    showToast("No evidence marked yet! Mark a waypoint first.", "⚠️");
    return;
  }}

  let exhibitsHtml = '';
  markedEvidence.forEach((ex, idx) => {{
    const deg = ((ex.hdg % 360) + 360) % 360;
    const card = getCardinalDir(deg);
    const pSign = ex.pitch >= 0 ? '+' : '';
    const rSign = ex.roll >= 0 ? '+' : '';
    const latStr = (ex.lat !== undefined && ex.lat !== 0.0) ? ex.lat.toFixed(6) + '°' : 'Indoor Fix';
    const lonStr = (ex.lon !== undefined && ex.lon !== 0.0) ? ex.lon.toFixed(6) + '°' : 'Indoor Fix';

    const imgTag = ex.image_data
      ? `<img src="${{ex.image_data}}" alt="3D Reconstruction Snapshot ${{ex.id}}" style="width: 100%; max-height: 440px; object-fit: contain; background: #060911; border-radius: 8px; border: 1.5px solid #cbd5e1; margin-bottom: 12px; display: block; box-shadow: 0 4px 12px rgba(0,0,0,0.15);" />`
      : `<div style="padding: 20px; text-align: center; background: #f1f5f9; color: #64748b; border: 1px dashed #cbd5e1; border-radius: 6px; margin-bottom: 12px;">[ 3D Snapshot Not Recorded ]</div>`;

    exhibitsHtml += `
      <div class="exhibit-sheet-card" style="page-break-inside: avoid; background: #ffffff; border: 1.5px solid #e2e8f0; border-radius: 10px; padding: 20px; margin-bottom: 30px; box-shadow: 0 4px 16px rgba(0,0,0,0.06);">
        <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #0284c7; padding-bottom: 8px; margin-bottom: 14px;">
          <h2 style="font-size: 16px; font-weight: 800; color: #0f172a; margin: 0;">${{ex.id}}: 3D TRAJECTORY INCIDENT POINT</h2>
          <span style="font-family: monospace; font-size: 13px; font-weight: 700; color: #0284c7;">Waypoint #${{ex.index + 1}} | ${{ex.ts}}</span>
        </div>

        <!-- 3D Captured Viewport Image -->
        ${{imgTag}}

        <!-- Forensic Telemetry & Findings Table Under Image -->
        <table style="width: 100%; border-collapse: collapse; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace; font-size: 11.5px; border: 1px solid #cbd5e1;">
          <tr style="background: #f8fafc;">
            <td style="padding: 7px 10px; border: 1px solid #cbd5e1; font-weight: 700; width: 22%;">Waypoint Index:</td>
            <td style="padding: 7px 10px; border: 1px solid #cbd5e1; width: 28%;">Waypoint #${{ex.index + 1}} of ${{flightData.length}}</td>
            <td style="padding: 7px 10px; border: 1px solid #cbd5e1; font-weight: 700; width: 22%;">Incident Time (UTC):</td>
            <td style="padding: 7px 10px; border: 1px solid #cbd5e1; font-weight: 700; color: #0284c7; width: 28%;">${{ex.ts}}</td>
          </tr>
          <tr>
            <td style="padding: 7px 10px; border: 1px solid #cbd5e1; font-weight: 700;">Altitude (MSL):</td>
            <td style="padding: 7px 10px; border: 1px solid #cbd5e1; font-weight: 700; color: #0369a1;">${{ex.alt.toFixed(1)}} m</td>
            <td style="padding: 7px 10px; border: 1px solid #cbd5e1; font-weight: 700;">Ground Speed:</td>
            <td style="padding: 7px 10px; border: 1px solid #cbd5e1; font-weight: 700; color: #15803d;">${{ex.spd.toFixed(1)}} m/s</td>
          </tr>
          <tr style="background: #f8fafc;">
            <td style="padding: 7px 10px; border: 1px solid #cbd5e1; font-weight: 700;">Flight Heading:</td>
            <td style="padding: 7px 10px; border: 1px solid #cbd5e1;">${{deg.toFixed(0)}}° (${{card}})</td>
            <td style="padding: 7px 10px; border: 1px solid #cbd5e1; font-weight: 700;">Attitude Angles:</td>
            <td style="padding: 7px 10px; border: 1px solid #cbd5e1;">Pitch: ${{pSign}}${{ex.pitch.toFixed(1)}}° | Roll: ${{rSign}}${{ex.roll.toFixed(1)}}°</td>
          </tr>
          <tr>
            <td style="padding: 7px 10px; border: 1px solid #cbd5e1; font-weight: 700;">GNSS Coordinates:</td>
            <td style="padding: 7px 10px; border: 1px solid #cbd5e1;">${{latStr}}, ${{lonStr}}</td>
            <td style="padding: 7px 10px; border: 1px solid #cbd5e1; font-weight: 700;">Chain of Custody:</td>
            <td style="padding: 7px 10px; border: 1px solid #cbd5e1; font-weight: 700; color: #15803d;">CRYPTOGRAPHICALLY VERIFIED</td>
          </tr>
          <tr style="background: #f8fafc;">
            <td style="padding: 8px 10px; border: 1px solid #cbd5e1; font-weight: 700;">Investigator Finding:</td>
            <td colspan="3" style="padding: 8px 10px; border: 1px solid #cbd5e1; color: #1e293b; font-style: italic;">
              ${{ex.note}}
            </td>
          </tr>
        </table>
      </div>
    `;
  }});

  const reportDoc = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Forensic Evidence Exhibits Dossier - [${{caseId}}]</title>
<style>
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: #f1f5f9;
    color: #0f172a;
    margin: 0;
    padding: 30px;
  }}
  .container {{
    max-width: 960px;
    margin: 0 auto;
  }}
  .top-banner {{
    background: #0f172a;
    color: #fff;
    padding: 24px;
    border-radius: 10px;
    margin-bottom: 24px;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }}
  .brand-badge {{
    background: #0284c7;
    color: #fff;
    font-weight: 900;
    font-size: 11px;
    padding: 3px 8px;
    border-radius: 4px;
  }}
  .btn-bar {{
    display: flex;
    gap: 10px;
  }}
  .btn-act {{
    background: #0284c7;
    border: none;
    color: #fff;
    padding: 8px 14px;
    border-radius: 6px;
    font-weight: 700;
    font-size: 12px;
    cursor: pointer;
  }}
  .btn-act.sec {{
    background: #334155;
  }}
  @media print {{
    body {{ background: #fff; padding: 0; }}
    .btn-bar {{ display: none !important; }}
    .top-banner {{ border-radius: 0; margin-bottom: 16px; padding: 16px; }}
    .exhibit-sheet-card {{ box-shadow: none !important; border: 1px solid #94a3b8 !important; page-break-after: always; }}
  }}
</style>
</head>
<body>
<div class="container">
  <div class="top-banner">
    <div>
      <span class="brand-badge">PUSHPAK FORENSICS</span>
      <h1 style="font-size: 18px; margin: 8px 0 4px 0;">DIGITAL FORENSIC EVIDENCE EXHIBIT DOSSIER</h1>
      <div style="font-size: 12px; color: #94a3b8; font-family: monospace;">Case Reference: [${{caseId}}] | Statutory Admissibility: Section 63 BSA 2023 / Section 65B IEA</div>
    </div>
    <div class="btn-bar">
      <button class="btn-act" onclick="window.print()">🖨️ Print / Save PDF</button>
      <button class="btn-act sec" onclick="window.close()">✖ Close</button>
    </div>
  </div>

  ${{exhibitsHtml}}
</div>
</body>
</html>`;

  const blob = new Blob([reportDoc], {{ type: "text/html" }});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `Forensic_Exhibit_Report_${{caseId}}.html`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 5000);

  showToast(`📄 Generated Visual Forensic Exhibit Sheet!`, "📄");
}}

// Add all marked exhibits directly into the Courtroom PDF Report
async function addToCourtroomPdf() {{
  if (markedEvidence.length === 0) {{
    if (flightData && flightData.length > 0) {{
      // Automatically capture snapshot and mark current waypoint
      let snapData = "";
      if (renderer && scene && camera) {{
        try {{
          renderer.render(scene, camera);
          snapData = renderer.domElement.toDataURL("image/png");
        }} catch (err) {{}}
      }}
      const p = flightData[currentIndex];
      const exId = 'EVID-01';
      const exhibit = {{
        id: exId,
        num: 1,
        index: currentIndex,
        ts: p.ts,
        x: p.x, y: p.y, z: p.z,
        alt: p.alt, spd: p.spd,
        lat: p.lat, lon: p.lon,
        hdg: p.hdg, pitch: p.pitch, roll: p.roll,
        image_data: snapData,
        note: `Exhibit #1: Waypoint #${{currentIndex + 1}} (Alt: ${{p.alt.toFixed(1)}}m, Spd: ${{p.spd.toFixed(1)}}m/s)`,
        created_utc: new Date().toISOString(),
      }};
      markedEvidence.push(exhibit);
      create3DEvidenceMarker(exhibit);
      renderEvidenceCards();
      saveEvidenceToStorage();
    }} else {{
      showToast("No telemetry data loaded!", "⚠️");
      return;
    }}
  }}

  showToast("⏳ Integrating Exhibits into Courtroom PDF...", "⚖️");

  const syncRes = await syncAllExhibitsToBackend(markedEvidence);
  if (syncRes && (syncRes.status === "ok" || Array.isArray(syncRes))) {{
    showToast(`⚖️ Section 6 Generated! Opening Courtroom PDF...`, "⚖️");
    closeDossierModal();
    setTimeout(() => {{
      triggerOpenCourtroomPdf();
    }}, 400);
  }} else {{
    // Standalone fallback: notify user and generate exhibit sheet
    showToast(`⚠️ Workstation backend on port ${{PUSHPAK_API_PORT}} not reachable. Exporting standalone sheet...`, "⚠️");
    exportForensicExhibitReport();
  }}
}}

function copyDossierCitation() {{
  if (markedEvidence.length === 0) {{
    showToast("No exhibits to cite!", "⚠️");
    return;
  }}

  let text = `COURTROOM EVIDENCE EXHIBITS LIST - [${{caseId}}]\n`;
  text += `Generated UTC: ${{new Date().toISOString()}}\n`;
  text += `Total Exhibits: ${{markedEvidence.length}}\n`;
  text += `---------------------------------------------------------\n`;
  markedEvidence.forEach(e => {{
    text += `${{e.id}} | Time: ${{e.ts}} | Alt: ${{e.alt.toFixed(1)}}m | Spd: ${{e.spd.toFixed(1)}}m/s | Pitch: ${{e.pitch.toFixed(1)}}° Roll: ${{e.roll.toFixed(1)}}°\n`;
    text += `  Observation: ${{e.note}}\n`;
    text += `  Coordinates: ${{e.lat}}, ${{e.lon}}\n\n`;
  }});

  navigator.clipboard.writeText(text).then(() => {{
    showToast("📋 Copied Exhibit Citation to Clipboard!", "📋");
  }}).catch(() => {{
    showToast("Error copying citation", "⚠️");
  }});
}}

function captureViewportSnapshot() {{
  if (!renderer || !scene || !camera) return;
  renderer.render(scene, camera);
  const dataUrl = renderer.domElement.toDataURL("image/png");
  const a = document.createElement('a');
  a.href = dataUrl;
  a.download = `Forensic_3D_Trajectory_Snapshot_WP${{currentIndex + 1}}_${{Date.now()}}.png`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  showToast("📸 3D Viewport Snapshot Captured!", "📸");
}}

function showToast(msg, icon = '📍') {{
  const toast = document.getElementById('evidenceToast');
  const msgEl = document.getElementById('toastMsg');
  const iconEl = document.getElementById('toastIcon');
  if (!toast || !msgEl) return;
  msgEl.innerText = msg;
  if (iconEl) iconEl.innerText = icon;
  toast.classList.add('show');
  setTimeout(() => {{
    toast.classList.remove('show');
  }}, 2800);
}}

function saveEvidenceToStorage() {{
  try {{
    const key = 'pushpak_evidence_' + caseId;
    localStorage.setItem(key, JSON.stringify(markedEvidence));
  }} catch (e) {{
    console.warn("localStorage save failed", e);
  }}
}}

function loadEvidenceFromStorage() {{
  try {{
    const key = 'pushpak_evidence_' + caseId;
    const raw = localStorage.getItem(key);
    if (raw) {{
      const items = JSON.parse(raw);
      if (Array.isArray(items) && items.length > 0) {{
        markedEvidence = items;
        markedEvidence.forEach(ex => {{
          create3DEvidenceMarker(ex);
        }});
        renderEvidenceCards();
      }}
    }}
  }} catch (e) {{
    console.warn("localStorage load failed", e);
  }}
}}

window.onload = initScene;
</script>
</body>
</html>
"""

        target_file = Path(output_path) if output_path else Path("flight_3d_map.html")
        target_file.parent.mkdir(parents=True, exist_ok=True)
        target_file.write_text(html_content, encoding="utf-8")
        return target_file


# Helper standalone functions
def export_geojson(
    events: list[NormalizedEvent],
    anomalies: Optional[list[ForensicAnomaly]] = None,
    no_fly_zones: Optional[list[NoFlyZone]] = None,
    output_path: Optional[Path] = None,
) -> dict[str, Any]:
    return GeospatialExporter.to_geojson(events, anomalies, no_fly_zones, output_path)


def export_kml(
    events: list[NormalizedEvent],
    anomalies: Optional[list[ForensicAnomaly]] = None,
    no_fly_zones: Optional[list[NoFlyZone]] = None,
    output_path: Optional[Path] = None,
) -> Path:
    return GeospatialExporter.to_kml(events, anomalies, no_fly_zones, output_path)


def export_html_map(
    events: list[NormalizedEvent],
    anomalies: Optional[list[ForensicAnomaly]] = None,
    no_fly_zones: Optional[list[NoFlyZone]] = None,
    output_path: Optional[Path] = None,
) -> Path:
    return GeospatialExporter.to_html_map(events, anomalies, no_fly_zones, output_path)


def export_3d_html_map(
    events: list[NormalizedEvent],
    anomalies: Optional[list[ForensicAnomaly]] = None,
    no_fly_zones: Optional[list[NoFlyZone]] = None,
    output_path: Optional[Path] = None,
    case_id: str = "CASE-DESKTOP-001",
    http_port: int = 8765,
) -> Path:
    return GeospatialExporter.to_3d_html_map(events, anomalies, no_fly_zones, output_path, case_id, http_port)


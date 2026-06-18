"""Journey (multi-trip travel) routes (FIXES 6.1).

Moved verbatim out of app.py. Handler bodies unchanged except
``@app.route`` → ``@journeys_bp.route`` and the one internal
``url_for("journeys_list")`` → ``url_for("journeys.journeys_list")`` (endpoint
names gain the blueprint prefix; templates use hardcoded paths, so unaffected).
Shared helpers come from app at blueprint-import time (bottom of app.py).
"""

from datetime import datetime, timedelta, timezone

import config
import detector
from flask import (Blueprint, Response, jsonify, redirect, render_template,
                   request, url_for)
from flask_login import login_required

from app import (_operator_icon_map, _to_rfc3339, _to_rfc3339_padded,
                 _translations, active_device, get_db, get_language, log)

journeys_bp = Blueprint("journeys", __name__)


@journeys_bp.route("/journeys")
@login_required
def journeys_list():
    device = active_device()
    db = get_db()
    rows = db.execute(
        """SELECT j.*, COUNT(jt.trip_id) AS trip_count,
                  COALESCE(SUM(t.distance_km), 0) AS total_km
           FROM journeys j
           LEFT JOIN journey_trips jt ON jt.journey_id = j.id
           LEFT JOIN trips t ON t.id = jt.trip_id
           WHERE j.device = ?
           GROUP BY j.id ORDER BY j.date_from DESC""",
        (device,),
    ).fetchall()
    db.close()
    return render_template("journeys.html", journeys=[dict(r) for r in rows])


@journeys_bp.route("/journeys/<int:journey_id>")
@login_required
def journey_detail(journey_id):
    db = get_db()
    journey = db.execute("SELECT * FROM journeys WHERE id = ?", (journey_id,)).fetchone()
    if not journey:
        db.close()
        return redirect(url_for("journeys.journeys_list"))
    trips = db.execute(
        """SELECT t.* FROM trips t
           JOIN journey_trips jt ON jt.trip_id = t.id
           WHERE jt.journey_id = ?
           ORDER BY t.start_time""",
        (journey_id,),
    ).fetchall()
    # Filter charge sessions: link vehicle via device -> plate
    veh = db.execute("SELECT * FROM vehicles WHERE device = ?",
                     (journey["device"],)).fetchone()
    if veh:
        charges = db.execute(
            """SELECT * FROM charge_sessions
               WHERE vehicle_plate = ? AND date(start_time) >= ? AND date(start_time) <= ?
               ORDER BY start_time""",
            (veh["plate"], journey["date_from"], journey["date_to"]),
        ).fetchall()
    else:
        charges = db.execute(
            """SELECT * FROM charge_sessions
               WHERE date(start_time) >= ? AND date(start_time) <= ?
               ORDER BY start_time""",
            (journey["date_from"], journey["date_to"]),
        ).fetchall()
    vehicles = db.execute("SELECT plate, name FROM vehicles").fetchall()
    vehicle_names = {v["plate"]: v["name"] or v["plate"] for v in vehicles}
    op_icon_map = _operator_icon_map(db)
    # loc_operators for charge icons (like charges.html)
    loc_operators = {}
    for cl in db.execute("""SELECT cl.name, cl.operator, cl.type, cl.color, cl.icon_filename,
                                   op.icon_filename AS op_icon_filename, op.color AS op_color
                            FROM charge_locations cl
                            LEFT JOIN operators op ON cl.operator_id = op.id""").fetchall():
        if cl['icon_filename']:
            icon_url = f"/media/charge-icons/{cl['icon_filename']}"
        elif cl['op_icon_filename']:
            icon_url = f"/media/operator-icons/{cl['op_icon_filename']}"
        else:
            icon_url = None
        loc_operators[cl['name']] = {
            'color': cl['op_color'] or cl['color'] or '#8b949e',
            'icon_url': icon_url,
        }
    # Calculate drive time, charge time, average speed
    drive_minutes = 0
    for t in trips:
        if t["start_time"] and t["end_time"]:
            try:
                t0 = datetime.fromisoformat(t["start_time"])
                t1 = datetime.fromisoformat(t["end_time"])
                drive_minutes += (t1 - t0).total_seconds() / 60
            except Exception:
                log.debug("drive-time: bad timestamps on trip %s — skipped", t["id"] if "id" in t.keys() else "?", exc_info=True)
    # Split charge times by AC/DC
    loc_types = {}
    for cl in db.execute("SELECT name, type FROM charge_locations").fetchall():
        loc_types[cl["name"]] = (cl["type"] or "ac").lower()
    ac_minutes = 0
    dc_minutes = 0
    for c in charges:
        dur = c["duration_minutes"] or 0
        if loc_types.get(c["location_name"]) == "dc":
            dc_minutes += dur
        else:
            ac_minutes += dur
    total_km = sum(t["distance_km"] or 0 for t in trips)
    avg_speed = round(total_km / (drive_minutes / 60), 1) if drive_minutes > 0 else None

    db.close()
    return render_template("journey_detail.html",
                           journey=dict(journey),
                           trips=[dict(t) for t in trips],
                           charges=[dict(c) for c in charges],
                           vehicle_names=vehicle_names,
                           op_icon_map=op_icon_map,
                           loc_operators=loc_operators,
                           drive_minutes=round(drive_minutes),
                           ac_minutes=round(ac_minutes),
                           dc_minutes=round(dc_minutes),
                           avg_speed=avg_speed)


@journeys_bp.route("/api/journeys", methods=["POST"])
@login_required
def create_journey():
    data = request.get_json(force=True)
    title = (data.get("title") or "").strip()
    date_from = (data.get("date_from") or "").strip()
    date_to = (data.get("date_to") or "").strip()
    notes = (data.get("notes") or "").strip()
    trip_ids = data.get("trip_ids", [])
    if not title or not date_from or not date_to:
        lang = get_language()
        _t = _translations.get(lang, _translations["DE"])
        return jsonify({"error": _t["journeys_required_fields"]}), 400
    device = active_device()
    db = get_db()
    cur = db.execute(
        "INSERT INTO journeys (device, title, date_from, date_to, notes) VALUES (?,?,?,?,?)",
        (device, title, date_from, date_to, notes),
    )
    jid = cur.lastrowid
    for tid in trip_ids:
        db.execute("INSERT OR IGNORE INTO journey_trips (journey_id, trip_id) VALUES (?,?)",
                    (jid, int(tid)))
    db.commit()
    db.close()
    return jsonify({"ok": True, "id": jid})


@journeys_bp.route("/api/journeys/<int:journey_id>", methods=["POST"])
@login_required
def update_journey(journey_id):
    data = request.get_json(force=True)
    db = get_db()
    sets, vals = [], []
    for col in ("title", "date_from", "date_to", "notes"):
        if col in data:
            sets.append(f"{col} = ?")
            vals.append(data[col])
    if sets:
        vals.append(journey_id)
        db.execute(f"UPDATE journeys SET {', '.join(sets)} WHERE id = ?", vals)
    if "trip_ids" in data:
        db.execute("DELETE FROM journey_trips WHERE journey_id = ?", (journey_id,))
        for tid in data["trip_ids"]:
            db.execute("INSERT OR IGNORE INTO journey_trips (journey_id, trip_id) VALUES (?,?)",
                        (journey_id, int(tid)))
    db.commit()
    db.close()
    return jsonify({"ok": True})


@journeys_bp.route("/api/journeys/<int:journey_id>", methods=["DELETE"])
@login_required
def delete_journey(journey_id):
    db = get_db()
    db.execute("DELETE FROM journeys WHERE id = ?", (journey_id,))
    db.commit()
    db.close()
    return jsonify({"ok": True})


@journeys_bp.route("/api/journeys/<int:journey_id>/trips")
@login_required
def journey_trips_list(journey_id):
    """All trips of a journey with GPS data."""
    db = get_db()
    trips = db.execute(
        """SELECT t.* FROM trips t
           JOIN journey_trips jt ON jt.trip_id = t.id
           WHERE jt.journey_id = ?
           ORDER BY t.start_time""",
        (journey_id,),
    ).fetchall()
    db.close()
    return jsonify([dict(t) for t in trips])


@journeys_bp.route("/api/journeys/<int:journey_id>/route")
@login_required
def journey_route(journey_id):
    """GPS points of all trips in a journey.
    Priority: 1) InfluxDB time series  2) GPX waypoints  3) start/end coordinates of the trip
    """
    db = get_db()
    if not db.execute("SELECT id FROM journeys WHERE id = ?", (journey_id,)).fetchone():
        db.close()
        return jsonify({"segments": []})

    trips = db.execute(
        """SELECT t.id, t.device, t.start_time, t.end_time,
                  t.start_lat, t.start_lon, t.end_lat, t.end_lon, t.is_gpx
           FROM trips t
           JOIN journey_trips jt ON jt.trip_id = t.id
           WHERE jt.journey_id = ?
           ORDER BY t.start_time""",
        (journey_id,),
    ).fetchall()

    # Pre-load GPX waypoints (trip_id → [[lat,lon], ...])
    gpx_tracks = {}
    gpx_trip_ids = [t["id"] for t in trips if t["is_gpx"]]
    if gpx_trip_ids:
        placeholders = ",".join("?" * len(gpx_trip_ids))
        wpts = db.execute(
            f"SELECT trip_id, lat, lon FROM gpx_waypoints WHERE trip_id IN ({placeholders}) ORDER BY trip_id, timestamp",
            gpx_trip_ids,
        ).fetchall()
        for w in wpts:
            gpx_tracks.setdefault(w["trip_id"], []).append([round(w["lat"], 6), round(w["lon"], 6)])

    db.close()

    segments = []

    # 1) InfluxDB: query grouped by trip device
    client = detector.get_influx()
    if client:
        try:
            from collections import defaultdict
            by_device = defaultdict(list)
            for trip in trips:
                if trip["device"]:
                    by_device[trip["device"]].append(trip)

            for device, dev_trips in by_device.items():
                for trip in dev_trips:
                    query = f'''
                    from(bucket: "{config.INFLUX_BUCKET}")
                      |> range(start: {_to_rfc3339(trip["start_time"])}, stop: {_to_rfc3339_padded(trip["end_time"])})
                      |> filter(fn: (r) => r._measurement == "v" and r.d == "{device}")
                      |> filter(fn: (r) => r._field == "la" or r._field == "lo")
                      |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
                      |> sort(columns: ["_time"])
                    '''
                    tables = client.query_api().query(query, org=config.INFLUX_ORG)
                    raw = []
                    for table in tables:
                        for rec in table.records:
                            raw.append(rec.values)
                    raw.sort(key=lambda r: r.get("_time") or datetime.min.replace(tzinfo=timezone.utc))
                    raw = detector._merge_rows(raw)
                    raw = detector._filter_gps_jumps(raw)
                    pts = []
                    for rec in raw:
                        lat = rec.get("la")
                        lon = rec.get("lo")
                        if lat and lon and lat != 0 and lon != 0:
                            pts.append([round(lat, 6), round(lon, 6)])
                    if pts:
                        segments.append(pts)
        except Exception:
            log.exception("Error loading journey route %d", journey_id)
        finally:
            client.close()

    # 2) Fallback: GPX waypoints for trips without InfluxDB data
    if not segments:
        for trip in trips:
            if trip["id"] in gpx_tracks:
                pts = gpx_tracks[trip["id"]]
                if pts:
                    segments.append(pts)

    # 3) Fallback: start/end coordinates of trips
    if not segments:
        for trip in trips:
            pts = []
            if trip["start_lat"] and trip["start_lon"]:
                pts.append([round(trip["start_lat"], 6), round(trip["start_lon"], 6)])
            if trip["end_lat"] and trip["end_lon"]:
                pts.append([round(trip["end_lat"], 6), round(trip["end_lon"], 6)])
            if pts:
                segments.append(pts)

    return jsonify({"segments": segments, "source": "influx" if segments and client else ("gpx" if gpx_tracks else "coords")})


@journeys_bp.route("/api/journeys/<int:journey_id>/chart-data")
@login_required
def journey_chart_data(journey_id):
    """Daily kilometers of the journey trips. Rest days within the journey's
    date_from..date_to span are filled with 0 so the bar chart doesn't squash
    two non-adjacent travel days next to each other and fake a daily routine."""
    db = get_db()
    journey = db.execute(
        "SELECT date_from, date_to FROM journeys WHERE id = ?",
        (journey_id,),
    ).fetchone()
    if not journey:
        db.close()
        return jsonify({"labels": [], "values": []})
    rows = db.execute(
        """SELECT date(t.start_time) AS day, SUM(t.distance_km) AS km
           FROM trips t
           JOIN journey_trips jt ON jt.trip_id = t.id
           WHERE jt.journey_id = ?
           GROUP BY day ORDER BY day""",
        (journey_id,),
    ).fetchall()
    db.close()
    km_by_day = {
        r["day"]: round(r["km"], 1) if r["km"] is not None else 0
        for r in rows
    }
    try:
        start = datetime.fromisoformat(journey["date_from"]).date()
        end = datetime.fromisoformat(journey["date_to"]).date()
    except (TypeError, ValueError):
        # Malformed journey dates — fall back to just the days the SQL returned.
        return jsonify({"labels": list(km_by_day), "values": list(km_by_day.values())})
    labels, values = [], []
    day = start
    while day <= end:
        key = day.isoformat()
        labels.append(key)
        values.append(km_by_day.get(key, 0))
        day += timedelta(days=1)
    return jsonify({"labels": labels, "values": values})


@journeys_bp.route("/api/journeys/<int:journey_id>/gpx")
@login_required
def journey_gpx(journey_id):
    """GPX export of all trips in a journey."""
    db = get_db()
    journey = db.execute("SELECT * FROM journeys WHERE id = ?", (journey_id,)).fetchone()
    if not journey:
        db.close()
        lang = get_language()
        _t = _translations.get(lang, _translations["DE"])
        return jsonify({"error": _t["journey_not_found"]}), 404
    trips = db.execute(
        """SELECT t.start_time, t.end_time FROM trips t
           JOIN journey_trips jt ON jt.trip_id = t.id
           WHERE jt.journey_id = ?
           ORDER BY t.start_time""",
        (journey_id,),
    ).fetchall()
    db.close()

    lang = get_language()
    _t = _translations.get(lang, _translations["DE"])
    device = journey["device"]
    gpx_lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<gpx version="1.1" creator="IDmate"',
        '     xmlns="http://www.topografix.com/GPX/1/1">',
        f'  <metadata><name>{journey["title"]}</name></metadata>',
    ]

    client = detector.get_influx()
    if client:
        try:
            for i, trip in enumerate(trips):
                query = f'''
                from(bucket: "{config.INFLUX_BUCKET}")
                  |> range(start: {_to_rfc3339(trip["start_time"])}, stop: {_to_rfc3339_padded(trip["end_time"])})
                  |> filter(fn: (r) => r._measurement == "v" and r.d == "{device}")
                  |> filter(fn: (r) => r._field == "la" or r._field == "lo" or r._field == "v" or r._field == "s")
                  |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
                  |> filter(fn: (r) => exists r.la and exists r.lo)
                  |> sort(columns: ["_time"])
                '''
                tables = client.query_api().query(query, org=config.INFLUX_ORG)
                gpx_lines.append(f'  <trk>')
                gpx_lines.append(f'    <name>{_t["journey_gpx_track_name"].format(i+1)} ({trip["start_time"][:10]})</name>')
                gpx_lines.append(f'    <trkseg>')
                for table in tables:
                    for rec in table.records:
                        la = rec.values.get("la")
                        lo = rec.values.get("lo")
                        t = rec.values.get("_time")
                        if la and lo:
                            time_str = t.isoformat() if t else ""
                            line = f'      <trkpt lat="{la}" lon="{lo}">'
                            if time_str:
                                line += f'<time>{time_str}</time>'
                            speed = rec.values.get("v")
                            if speed is not None:
                                line += f'<speed>{speed / 3.6:.1f}</speed>'
                            line += '</trkpt>'
                            gpx_lines.append(line)
                gpx_lines += ['    </trkseg>', '  </trk>']
        except Exception:
            log.exception("Error in GPX export of journey %d", journey_id)
        finally:
            client.close()

    gpx_lines.append('</gpx>')
    safe_title = journey["title"].replace(" ", "_")
    filename = f"journey_{safe_title}_{journey['date_from']}_{journey['date_to']}.gpx"
    return Response(
        "\n".join(gpx_lines),
        mimetype="application/gpx+xml",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@journeys_bp.route("/api/journeys/available-trips")
@login_required
def journey_available_trips():
    """Trips in date range for journey assignment."""
    date_from = request.args.get("from", "")
    date_to = request.args.get("to", "")
    device = active_device()
    db = get_db()
    trips = db.execute(
        """SELECT id, start_time, end_time, start_address, end_address, distance_km
           FROM trips
           WHERE device = ? AND date(start_time) >= ? AND date(start_time) <= ?
           ORDER BY start_time""",
        (device, date_from, date_to),
    ).fetchall()
    db.close()
    return jsonify([dict(t) for t in trips])


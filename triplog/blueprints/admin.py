"""Admin & management routes: settings, value rename/merge, gaps, TeslaMate
import, users, DB stats, geocode, hardware stats (FIXES 6.1).

Moved verbatim out of app.py (``@app.route`` → ``@admin_bp.route``). These views
have no internal ``url_for`` to admin endpoints and templates use hardcoded
paths, so endpoint renaming has no ripple. ``import_job`` and ``_trend_cache``
are module objects mutated in place (safe across ``from app import``). The MQTT
monitor and ``debug_page`` routes stay in app.py — they read MQTT background
globals that get rebound there.
"""

import sqlite3
from datetime import datetime, timedelta, timezone

import config
import detector
import geocoder as geo
import teslamate_import
from flask import Blueprint, jsonify, render_template, request
from flask_login import current_user
from plmn import plmn_info

from app import (ENCRYPTED_SETTINGS, _decrypt_setting, _encrypt_setting,
                 _find_odo_gaps, _settings_fernet, _trend_cache,
                 _validate_password, active_device, active_vehicle,
                 admin_required, debug_required, generate_password_hash,
                 get_bat_kwh, get_db, get_purpose_meta, haversine_m, import_job,
                 log, rebuild_charge_sessions)

admin_bp = Blueprint("admin", __name__)


@admin_bp.route("/admin")
def admin_page():
    prefill_lat = request.args.get("lat", "")
    prefill_lon = request.args.get("lon", "")
    prefill_tab = request.args.get("tab", "")
    prefill_name = request.args.get("name", "")
    db = get_db()
    vehicles = db.execute("SELECT * FROM vehicles ORDER BY id").fetchall()
    tariffs = db.execute("SELECT * FROM charge_tariffs ORDER BY valid_from DESC").fetchall()
    start_row = db.execute("SELECT value FROM settings WHERE key = 'charge_session_start'").fetchone()
    session_start = int(start_row['value']) if start_row else 1
    bu_row = db.execute("SELECT value FROM settings WHERE key = 'charge_billed_until'").fetchone()
    billed_until = bu_row['value'] if bu_row and bu_row['value'] else ''
    db.close()
    return render_template("admin.html",
                           prefill_lat=prefill_lat,
                           prefill_lon=prefill_lon,
                           prefill_tab=prefill_tab,
                           prefill_name=prefill_name,
                           vehicles=vehicles,
                           tariffs=tariffs,
                           session_start=session_start,
                           billed_until=billed_until,
                           teslamate_configured=teslamate_import.is_configured())


@admin_bp.route("/api/admin/values")
def admin_values():
    """All used values with counts for purposes, destinations, reasons."""
    db = get_db()

    purposes = db.execute(
        """SELECT purpose AS name, COUNT(*) AS count FROM trips
           WHERE purpose IS NOT NULL AND purpose != ''
           GROUP BY purpose ORDER BY purpose COLLATE NOCASE"""
    ).fetchall()

    destinations = db.execute(
        """SELECT destination AS name, COUNT(*) AS count FROM trips
           WHERE destination IS NOT NULL AND destination != ''
           GROUP BY destination ORDER BY destination COLLATE NOCASE"""
    ).fetchall()

    reasons = db.execute(
        """SELECT visit_reason AS name, COUNT(*) AS count FROM trips
           WHERE visit_reason IS NOT NULL AND visit_reason != ''
           GROUP BY visit_reason ORDER BY visit_reason COLLATE NOCASE"""
    ).fetchall()

    locations = db.execute(
        "SELECT * FROM locations ORDER BY name COLLATE NOCASE"
    ).fetchall()

    # Visit count per location (by geofence match on end coordinates)
    loc_visits = {}
    trips_with_coords = db.execute(
        "SELECT end_lat, end_lon FROM trips WHERE end_lat IS NOT NULL AND end_lon IS NOT NULL AND device = ?",
        (active_device(),),
    ).fetchall()
    for loc in locations:
        count = 0
        for t in trips_with_coords:
            if haversine_m(t["end_lat"], t["end_lon"], loc["lat"], loc["lon"]) <= loc["radius_m"]:
                count += 1
        loc_visits[loc["id"]] = count

    # Preset values (pre-saved suggestions)
    presets_dest = db.execute(
        "SELECT value AS name FROM preset_values WHERE field = 'destination' ORDER BY value COLLATE NOCASE"
    ).fetchall()
    presets_reason = db.execute(
        "SELECT value AS name FROM preset_values WHERE field = 'visit_reason' ORDER BY value COLLATE NOCASE"
    ).fetchall()

    # Merge presets into used values (deduplicated). After append, re-sort
    # because appending breaks the original alphabetic order — a brand-new
    # preset "Apotheke" would otherwise land at the end behind "Zoo".
    dest_names = {d["name"] for d in destinations}
    for p in presets_dest:
        if p["name"] not in dest_names:
            destinations.append({"name": p["name"], "count": 0})
    destinations = sorted(destinations, key=lambda x: (x["name"] or "").lower())

    reason_names = {r["name"] for r in reasons}
    for p in presets_reason:
        if p["name"] not in reason_names:
            reasons.append({"name": p["name"], "count": 0})
    reasons = sorted(reasons, key=lambda x: (x["name"] or "").lower())

    pmeta = get_purpose_meta(db)
    db.close()
    return jsonify({
        "purposes": [dict(r) if isinstance(r, sqlite3.Row) else r for r in purposes],
        "destinations": [dict(r) if isinstance(r, sqlite3.Row) else r for r in destinations],
        "visit_reasons": [dict(r) if isinstance(r, sqlite3.Row) else r for r in reasons],
        "locations": [dict(r) for r in locations],
        "location_visits": loc_visits,
        "purpose_meta": pmeta,
        "default_visit_reasons": [],
    })


@admin_bp.route("/api/settings")
def get_settings():
    """All settings as key-value object (sensitive fields decrypted)."""
    db = get_db()
    rows = db.execute("SELECT key, value FROM settings").fetchall()
    db.close()
    f = _settings_fernet()
    result = {}
    for r in rows:
        v = r["value"]
        if r["key"] in ENCRYPTED_SETTINGS:
            v = _decrypt_setting(f, v)
        result[r["key"]] = v
    return jsonify(result)


@admin_bp.route("/api/settings", methods=["POST"])
@admin_required
def save_settings():
    """Save settings — sensitive fields are stored encrypted.

    @admin_required: Settings sind globale Konfiguration (Sprache, Map-Style,
    Tokens, Rechnungs-Vorlagen) — vorher konnte jeder eingeloggte User beliebige
    Keys schreiben (Mass Assignment) inkl. der invoice_*-HTML-Felder."""
    data = request.get_json()
    db = get_db()
    f = _settings_fernet()
    for key, value in data.items():
        v = str(value)
        if key in ENCRYPTED_SETTINGS:
            v = _encrypt_setting(f, v)
        db.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = ?",
            (key, v, v),
        )
    db.commit()
    db.close()
    return jsonify({"ok": True})


@admin_bp.route("/api/trips/<int:trip_id>/clear-address", methods=["POST"])
def clear_trip_address(trip_id):
    """Clear address(es) of a single trip."""
    data = request.get_json() or {}
    which = data.get("which", "both")  # 'start', 'end', 'both'
    db = get_db()
    if which == "start":
        db.execute("UPDATE trips SET start_address = NULL WHERE id = ?", (trip_id,))
    elif which == "end":
        db.execute("UPDATE trips SET end_address = NULL WHERE id = ?", (trip_id,))
    else:
        db.execute("UPDATE trips SET start_address = NULL, end_address = NULL WHERE id = ?", (trip_id,))
    db.commit()
    db.close()
    return jsonify({"ok": True})


@admin_bp.route("/api/geocode-missing", methods=["POST"])
def geocode_missing():
    """Geocode missing addresses in the background.
    Activates the geocoder backfill window (slower rate) so we don't burn
    through Nominatim's per-second budget when catching up on a backlog."""
    import threading
    geo.extend_backfill_window()
    def _geocode():
        import geocoder as g
        g.run_once()
    threading.Thread(target=_geocode, daemon=True).start()
    return jsonify({"ok": True, "backfill_active": True})


@admin_bp.route("/api/geocode-status")
def geocode_status():
    """Return current geocoder rate-limit state for the admin UI."""
    active = geo.is_backfill_active()
    until = geo._read_backfill_until() if active else 0.0
    return jsonify({
        "backfill_active": active,
        "backfill_until": until,
        "interval_seconds": (
            config.GEOCODE_BACKFILL_INTERVAL if active else config.GEOCODE_RATE_LIMIT
        ),
        "cooldown_hours": config.GEOCODE_BACKFILL_COOLDOWN_HOURS,
    })


@admin_bp.route("/api/reverse-geocode")
def api_reverse_geocode():
    """On-demand reverse geocode for a single point → name + country code.
    Used as a geofence-name suggestion when creating a geofence from a charge
    that has no station name yet — same source trip destinations use."""
    try:
        lat = float(request.args.get("lat"))
        lon = float(request.args.get("lon"))
    except (TypeError, ValueError):
        return jsonify({"error": "lat, lon erforderlich"}), 400
    try:
        name, cc = geo.reverse_geocode(lat, lon)
    except Exception as e:
        log.warning("reverse-geocode failed for %s,%s: %s", lat, lon, e)
        return jsonify({"name": "", "country_code": ""})
    return jsonify({"name": name or "", "country_code": (cc or "").upper()[:2]})


@admin_bp.route("/api/purpose-meta", methods=["POST"])
def update_purpose_meta():
    """Create or update trip purpose (color, is_private)."""
    data = request.get_json()
    name = data.get("name", "").strip()
    if not name:
        return jsonify({"error": "Name erforderlich"}), 400

    db = get_db()
    is_main = int(data.get("is_main", 0))
    if is_main:
        db.execute("UPDATE purpose_meta SET is_main = 0")
    # FIXES 15.2: ist der Zweck neu, Ersteller vermerken + ihm Sichtbarkeit geben,
    # damit er sofort im Dropdown erscheint (auch bevor er auf einem Trip vorkam).
    is_new = db.execute("SELECT 1 FROM purpose_meta WHERE name = ?", (name,)).fetchone() is None
    uid = current_user.id if current_user.is_authenticated else None
    db.execute(
        """INSERT INTO purpose_meta (name, color, is_private, is_main, sort_order, created_by)
           VALUES (?, ?, ?, ?, (SELECT COALESCE(MAX(sort_order),0)+1 FROM purpose_meta), ?)
           ON CONFLICT(name) DO UPDATE SET color = ?, is_private = ?, is_main = ?""",
        (name, data.get("color", "#8b949e"), int(data.get("is_private", 0)), is_main, uid,
         data.get("color", "#8b949e"), int(data.get("is_private", 0)), is_main),
    )
    if is_new and uid is not None:
        db.execute("INSERT OR IGNORE INTO purpose_visibility (name, user_id) VALUES (?, ?)", (name, uid))
    db.commit()
    db.close()
    return jsonify({"ok": True})


@admin_bp.route("/api/preset-values", methods=["POST"])
def add_preset_value():
    """Save new preset value (destination or visit_reason).
    FIXES 15.2: @login_required (war @admin_required) — jeder User darf eigene
    Vorschläge anlegen; created_by + Visibility-Zeile macht sie sofort sichtbar."""
    data = request.get_json()
    field = data.get("field", "").strip()
    value = data.get("value", "").strip()
    if field not in ("destination", "visit_reason") or not value:
        return jsonify({"error": "field und value erforderlich"}), 400

    db = get_db()
    uid = current_user.id if current_user.is_authenticated else None
    cur = db.execute(
        "INSERT OR IGNORE INTO preset_values (field, value, created_by) VALUES (?, ?, ?)",
        (field, value, uid),
    )
    # id des (ggf. schon existierenden) Eintrags holen, dann Sichtbarkeit für User
    row = db.execute("SELECT id FROM preset_values WHERE field = ? AND value = ?", (field, value)).fetchone()
    if row and uid is not None:
        db.execute("INSERT OR IGNORE INTO preset_value_visibility (value_id, user_id) VALUES (?, ?)",
                   (row["id"], uid))
    db.commit()
    db.close()
    return jsonify({"ok": True})


def _may_manage_value(db, field, name):
    """FIXES 15.6: Wer darf einen Tag-Wert umbenennen/mergen/loeschen? Admins
    immer; normale User nur eigene Anlagen (created_by). Legacy (created_by NULL)
    und fremde -> nur Admin. Werte, die nur in Trips vorkommen (kein Katalog-
    Eintrag), kann ebenfalls nur der Admin anfassen (created_by unbekannt)."""
    if current_user.is_authenticated and current_user.is_admin:
        return True
    if not current_user.is_authenticated:
        return False
    if field == "purpose":
        row = db.execute("SELECT created_by FROM purpose_meta WHERE name = ?", (name,)).fetchone()
    else:
        row = db.execute("SELECT created_by FROM preset_values WHERE field = ? AND value = ?",
                         (field, name)).fetchone()
    return bool(row) and row["created_by"] == current_user.id


@admin_bp.route("/api/admin/rename", methods=["POST"])
def admin_rename():
    """Rename a value in all trips. FIXES 15.6: @login_required — jeder darf
    eigene Tags umbenennen, Admin alle."""
    data = request.get_json()
    field = data.get("field")
    old_name = data.get("old_name", "").strip()
    new_name = data.get("new_name", "").strip()

    if field not in ("purpose", "destination", "visit_reason"):
        return jsonify({"error": "Ungültiges Feld"}), 400
    if not old_name or not new_name:
        return jsonify({"error": "Name darf nicht leer sein"}), 400

    db = get_db()
    if not _may_manage_value(db, field, old_name):
        db.close()
        return jsonify({"error": "Nur selbst angelegte Tags kannst du bearbeiten — frag sonst einen Admin."}), 403
    # purpose_visibility hat FK auf purpose_meta.name ohne ON UPDATE CASCADE —
    # FK-Checks fuer diese Transaktion deferren, damit Parent+Child konsistent
    # umbenannt werden koennen (sonst FK-Fehler beim Umbenennen).
    db.execute("PRAGMA defer_foreign_keys = ON")
    cur = db.execute(
        f"UPDATE trips SET {field} = ? WHERE {field} = ?",
        (new_name, old_name)
    )
    # Also update related tables
    if field == "destination":
        db.execute("UPDATE locations SET name = ? WHERE name = ?", (new_name, old_name))
    elif field == "purpose":
        db.execute("UPDATE purpose_meta SET name = ? WHERE name = ?", (new_name, old_name))
        db.execute("UPDATE purpose_visibility SET name = ? WHERE name = ?", (new_name, old_name))
        db.execute("UPDATE route_rules SET purpose = ? WHERE purpose = ?", (new_name, old_name))
    if field in ("destination", "visit_reason"):
        db.execute("UPDATE preset_values SET value = ? WHERE field = ? AND value = ?",
                    (new_name, field, old_name))
    db.commit()
    count = cur.rowcount
    db.close()
    return jsonify({"ok": True, "updated": count})


@admin_bp.route("/api/admin/merge", methods=["POST"])
def admin_merge():
    """Merge two values (source → target). FIXES 15.6: @login_required — der
    QUELL-Wert wird geloescht, also Eigentum daran pruefen (Admin alle)."""
    data = request.get_json()
    field = data.get("field")
    source = data.get("source", "").strip()
    target = data.get("target", "").strip()

    if field not in ("purpose", "destination", "visit_reason"):
        return jsonify({"error": "Ungültiges Feld"}), 400
    if not source or not target:
        return jsonify({"error": "Beide Namen erforderlich"}), 400

    db = get_db()
    if not _may_manage_value(db, field, source):
        db.close()
        return jsonify({"error": "Nur selbst angelegte Tags kannst du bearbeiten — frag sonst einen Admin."}), 403
    cur = db.execute(
        f"UPDATE trips SET {field} = ? WHERE {field} = ?",
        (target, source)
    )
    if field == "destination":
        db.execute("DELETE FROM locations WHERE name = ?", (source,))
    elif field == "purpose":
        db.execute("DELETE FROM purpose_meta WHERE name = ?", (source,))
        db.execute("UPDATE route_rules SET purpose = ? WHERE purpose = ?", (target, source))
    if field in ("destination", "visit_reason"):
        db.execute("DELETE FROM preset_values WHERE field = ? AND value = ?", (field, source))
    db.commit()
    count = cur.rowcount
    db.close()
    return jsonify({"ok": True, "merged": count})


@admin_bp.route("/api/admin/delete-value", methods=["POST"])
def admin_delete_value():
    """Delete a value from all trips (set to empty). FIXES 15.6: @login_required —
    jeder darf eigene Tags loeschen, Admin alle."""
    data = request.get_json()
    field = data.get("field")
    name = data.get("name", "").strip()
    confirm = data.get("confirm", "").strip()

    if field not in ("purpose", "destination", "visit_reason"):
        return jsonify({"error": "Ungültiges Feld"}), 400
    if not name:
        return jsonify({"error": "Name erforderlich"}), 400
    if confirm != name:
        return jsonify({"error": "Bestätigung stimmt nicht überein"}), 400

    db = get_db()
    if not _may_manage_value(db, field, name):
        db.close()
        return jsonify({"error": "Nur selbst angelegte Tags kannst du bearbeiten — frag sonst einen Admin."}), 403
    cur = db.execute(
        f"UPDATE trips SET {field} = '' WHERE {field} = ?",
        (name,)
    )
    if field == "destination":
        db.execute("DELETE FROM locations WHERE name = ?", (name,))
    elif field == "purpose":
        db.execute("DELETE FROM purpose_meta WHERE name = ?", (name,))
    if field in ("destination", "visit_reason"):
        db.execute("DELETE FROM preset_values WHERE field = ? AND value = ?", (field, name))
    db.commit()
    count = cur.rowcount
    db.close()
    return jsonify({"ok": True, "cleared": count})


@admin_bp.route("/api/admin/gaps")
@admin_required
def admin_gaps():
    plate = request.args.get("vehicle", "").strip()
    if not plate:
        v = active_vehicle()
        plate = v["plate"] if v else ""
    if not plate:
        return jsonify({"vehicle": "", "gaps": []})
    try:
        min_km = float(request.args.get("min_km", "2"))
    except ValueError:
        min_km = 2
    date_from = request.args.get("from", "").strip()
    date_to = request.args.get("to", "").strip()
    db = get_db()
    gaps = _find_odo_gaps(db, plate, min_km=min_km, date_from=date_from, date_to=date_to)
    db.close()
    return jsonify({"vehicle": plate, "gaps": gaps,
                    "min_km": min_km, "from": date_from, "to": date_to})


@admin_bp.route("/api/admin/gaps", methods=["POST"])
@admin_required
def admin_gaps_save():
    """Save a manual mileage entry as N split trips. Splits sum must
    equal the gap's total km.
    """
    data = request.get_json() or {}
    plate = (data.get("vehicle") or "").strip()
    start_time = (data.get("start_time") or "").strip()
    end_time = (data.get("end_time") or "").strip()
    from_km = data.get("from_km")
    to_km = data.get("to_km")
    splits = data.get("splits") or []
    if not plate or not start_time or not end_time:
        return jsonify({"error": "vehicle / start_time / end_time required"}), 400
    if not splits or len(splits) > 5:
        return jsonify({"error": "1–5 splits required"}), 400
    try:
        total_km = float(to_km) - float(from_km)
    except (TypeError, ValueError):
        return jsonify({"error": "from_km / to_km invalid"}), 400
    sum_km = round(sum(float(s.get("km") or 0) for s in splits), 1)
    if abs(sum_km - round(total_km, 1)) > 0.1:
        return jsonify({"error": f"Splits ({sum_km} km) must equal gap ({round(total_km, 1)} km)"}), 400

    db = get_db()
    v = db.execute("SELECT device FROM vehicles WHERE plate = ?", (plate,)).fetchone()
    if not v or not v["device"]:
        db.close()
        return jsonify({"error": "vehicle not found"}), 404
    device = v["device"]

    # Re-assigning a gap: delete the previous manual trips first so save is
    # idempotent (no leftover splits, no double-counting).
    replace_ids = data.get("replace_trip_ids") or []
    if replace_ids:
        placeholders = ",".join("?" for _ in replace_ids)
        db.execute(
            f"DELETE FROM trips WHERE device = ? AND is_manual = 1 AND id IN ({placeholders})",
            (device, *replace_ids)
        )

    # Walk km counter forward so each split gets a fair odo_start/odo_end pair.
    running = float(from_km)
    for s in splits:
        try:
            km = float(s.get("km") or 0)
        except ValueError:
            km = 0
        if km <= 0:
            continue
        odo_start = round(running, 1)
        odo_end = round(running + km, 1)
        running = odo_end
        purpose = (s.get("purpose") or "").strip()
        destination = (s.get("destination") or "").strip()
        visit_reason = (s.get("visit_reason") or "").strip()
        note = (s.get("note") or "").strip() or None
        db.execute(
            """INSERT INTO trips
               (device, start_time, end_time, distance_km,
                odo_start, odo_end, purpose, destination, visit_reason,
                note, is_manual)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)""",
            (device, start_time, end_time, round(km, 1),
             odo_start, odo_end, purpose, destination, visit_reason, note)
        )
    db.commit()
    db.close()
    return jsonify({"ok": True, "splits_saved": len([s for s in splits if float(s.get("km") or 0) > 0])})


@admin_bp.route("/api/admin/teslamate/info")
@admin_required
def admin_teslamate_info():
    """Connection-test + summary stats. Read-only, never writes anywhere."""
    if not teslamate_import.is_configured():
        return jsonify({"ok": False, "configured": False,
                        "error": "TESLAMATE_PG_URL not set"}), 200
    info = teslamate_import.fetch_info()
    info["configured"] = True
    return jsonify(info)


@admin_bp.route("/api/admin/teslamate/day-compare", methods=["POST"])
@admin_required
def admin_teslamate_day_compare():
    """Side-by-side spot-check for a single (car_id, date) — first 25 + last
    25 samples from each side. Read-only, never writes.
    """
    if not teslamate_import.is_configured():
        return jsonify({"error": "TESLAMATE_PG_URL not set"}), 400
    data = request.get_json() or {}
    try:
        car_id = int(data.get("car_id"))
    except (TypeError, ValueError):
        return jsonify({"error": "car_id required"}), 400
    plate = (data.get("plate") or "").strip()
    date = (data.get("date") or "").strip()
    if not date or not plate:
        return jsonify({"error": "date + plate required"}), 400

    db = get_db()
    vrow = db.execute("SELECT device FROM vehicles WHERE plate = ?", (plate,)).fetchone()
    device = vrow["device"] if vrow else None
    db.close()

    try:
        tm_samples = teslamate_import.sample_positions_for_day(car_id, date, per_side=25)
    except Exception as e:
        log.exception("teslamate day-compare TM fetch failed: %s", e)
        return jsonify({"error": str(e)}), 500

    # IDMate side: pull first 25 + last 25 samples from InfluxDB for the day
    idm_samples = []
    if device:
        client = detector.get_influx()
        if client is not None:
            try:
                # Local (Europe/Berlin) day window, DST-correct: derive the
                # actual UTC offset for THIS day from zoneinfo instead of a
                # hardcoded +02:00 (wrong in winter / on DST-switch days). Stop
                # is the next local midnight (exclusive), matching the local-day
                # window used by the TM import + dedup.
                _start_local = datetime.fromisoformat(date + "T00:00:00").replace(tzinfo=detector.LOCAL_TZ)
                _stop_local = _start_local + timedelta(days=1)
                start_iso = _start_local.isoformat()
                stop_iso = _stop_local.isoformat()
                # First 25 ascending
                flux_first = (
                    f'from(bucket: "{config.INFLUX_BUCKET}")\n'
                    f'  |> range(start: {start_iso}, stop: {stop_iso})\n'
                    f'  |> filter(fn: (r) => r._measurement == "v" and r.d == "{device}")\n'
                    f'  |> filter(fn: (r) => r._field == "la" or r._field == "lo" or r._field == "s" or r._field == "v" or r._field == "p" or r._field == "od" or r._field == "et")\n'
                    f'  |> pivot(rowKey:["_time"], columnKey:["_field"], valueColumn:"_value")\n'
                    f'  |> sort(columns:["_time"], desc:false)\n'
                    f'  |> limit(n: 25)\n'
                )
                flux_last = flux_first.replace("desc:false", "desc:true")
                rows = []
                for fq in (flux_first, flux_last):
                    for tbl in client.query_api().query(fq, org=config.INFLUX_ORG):
                        for rec in tbl.records:
                            t = rec.get_time().astimezone(detector.LOCAL_TZ)
                            rows.append({
                                "date": t.strftime("%Y-%m-%d %H:%M:%S"),
                                "latitude": rec.values.get("la"),
                                "longitude": rec.values.get("lo"),
                                "battery_level": rec.values.get("s"),
                                "speed": rec.values.get("v"),
                                "power": rec.values.get("p"),
                                "odometer": rec.values.get("od"),
                                "outside_temp": rec.values.get("et"),
                            })
                # De-dup + sort
                seen = set()
                for r in rows:
                    if r["date"] in seen:
                        continue
                    seen.add(r["date"])
                    idm_samples.append(r)
                idm_samples.sort(key=lambda r: r["date"])
            except Exception as e:
                log.warning("Influx day-compare failed: %s", e)
            finally:
                client.close()

    # Plausibility checks: keine unsicheren Importe ohne Sanity-Pass
    def _check(side_name, rows, ranges):
        issues = []
        stats = {}
        for field, (lo, hi) in ranges.items():
            vals = []
            for r in rows:
                v = r.get(field)
                if v is None:
                    continue
                if not isinstance(v, (int, float)):
                    issues.append({
                        "field": field, "kind": "type",
                        "got": type(v).__name__, "example": str(v)[:32],
                    })
                    continue
                vals.append(v)
                if v < lo or v > hi:
                    issues.append({
                        "field": field, "kind": "range",
                        "value": v, "expected": [lo, hi],
                    })
            if vals:
                stats[field] = {"min": min(vals), "max": max(vals), "n": len(vals)}
            else:
                stats[field] = {"min": None, "max": None, "n": 0}
        return {"side": side_name, "ok": not issues, "issues": issues[:10],
                "issue_count": len(issues), "stats": stats}

    # Range-Check-Bounds: bewusst weit gesetzt damit Reisen quer durch Europa
    # nicht als Outlier erscheinen — Crete bis Nordkapp, Island bis Kaukasus.
    # Ziel ist nur "ist's geographisch noch sinnvoll" und "ist's ein Zahlentyp".
    tm_ranges = {
        "latitude":      (30.0, 72.0),
        "longitude":     (-30.0, 45.0),
        "battery_level": (0, 100),
        "speed":         (0, 300),
        "power":         (-600.0, 600.0),
        "odometer":      (0, 9_999_999),
    }
    idm_ranges = {
        "latitude":      (30.0, 72.0),
        "longitude":     (-30.0, 45.0),
        "battery_level": (0, 100),
        "speed":         (0, 300),
        "power":         (-600.0, 600.0),
        "odometer":      (0, 9_999_999),
    }
    checks = {
        "tm": _check("tm", tm_samples, tm_ranges),
        "idmate": _check("idmate", idm_samples, idm_ranges),
    }
    return jsonify({"date": date, "plate": plate, "device": device,
                    "car_id": car_id,
                    "tm": tm_samples, "idmate": idm_samples,
                    "checks": checks})


@admin_bp.route("/api/admin/teslamate/positions-preview", methods=["POST"])
@admin_required
def admin_teslamate_positions_preview():
    """Per-day position counts from TeslaMate vs. InfluxDB for the same
    device mapping. Read-only — no filter is applied yet, just raw counts
    so the user sees the order of magnitude before kicking off an import.
    """
    if not teslamate_import.is_configured():
        return jsonify({"error": "TESLAMATE_PG_URL not set"}), 400
    data = request.get_json() or {}
    car_map_raw = data.get("car_mapping") or {}
    car_map = {}
    for k, v in car_map_raw.items():
        if v:
            try:
                car_map[int(k)] = v
            except (TypeError, ValueError):
                log.debug("car_mapping: non-integer car id %r — entry skipped", k)
                continue
    if not car_map:
        return jsonify({"days": [], "summary": {}, "error": "no car mapping"}), 200

    date_from = (data.get("from") or "").strip()
    date_to = (data.get("to") or "").strip()

    db = get_db()
    plate_device = {}
    for plate in set(car_map.values()):
        row = db.execute(
            "SELECT device FROM vehicles WHERE plate = ?", (plate,)
        ).fetchone()
        plate_device[plate] = row["device"] if row else None
    db.close()

    car_ids = list(car_map.keys())
    try:
        tm_rows = teslamate_import.count_positions_per_day(
            car_ids, date_from, date_to
        )
    except Exception as e:
        log.exception("teslamate positions-preview TM count failed: %s", e)
        return jsonify({"error": str(e)}), 500

    # InfluxDB counts per (device, day) for the matching range
    influx_by_day = {}  # (device, 'YYYY-MM-DD') -> count
    devices = tuple(d for d in set(plate_device.values()) if d)
    if devices:
        client = detector.get_influx()
        if client is not None:
            try:
                # Use widest date range from tm_rows if no explicit range
                if not date_from and tm_rows:
                    date_from = tm_rows[0]["date"]
                if not date_to and tm_rows:
                    date_to = tm_rows[-1]["date"]
                start_iso = (date_from or "1970-01-01") + "T00:00:00Z"
                stop_iso = (date_to or "2099-12-31") + "T23:59:59Z"
                for device in devices:
                    flux = (
                        f'from(bucket: "{config.INFLUX_BUCKET}")\n'
                        f'  |> range(start: {start_iso}, stop: {stop_iso})\n'
                        f'  |> filter(fn: (r) => r._measurement == "v" and r.d == "{device}" and r._field == "la")\n'
                        f'  |> aggregateWindow(every: 1d, fn: count, createEmpty: false)\n'
                    )
                    for table in client.query_api().query(flux, org=config.INFLUX_ORG):
                        for rec in table.records:
                            day = rec.get_time().date().isoformat()
                            influx_by_day[(device, day)] = int(rec.get_value() or 0)
            except Exception as e:
                log.warning("Influx count_per_day failed: %s", e)
            finally:
                client.close()

    # Merge: pro Tag eine Zeile mit TM-, IDMate-count, geschaetzt-neu
    out = []
    tm_total = 0
    idm_total = 0
    new_estimate_total = 0
    for r in tm_rows:
        plate = car_map.get(r["car_id"])
        device = plate_device.get(plate)
        idm_n = influx_by_day.get((device, r["date"]), 0) if device else 0
        # Density-Cap: max 4320 Samples/Tag (1 alle 20s ueber 24h)
        density_capped = min(r["count"], 86400 // 20)
        # Estimate "new": density_capped minus what IDMate has already (clamp >= 0)
        est_new = max(0, density_capped - idm_n)
        tm_total += r["count"]
        idm_total += idm_n
        new_estimate_total += est_new
        out.append({
            "date": r["date"],
            "car_id": r["car_id"],
            "plate": plate,
            "device": device,
            "tm_count": r["count"],
            "idmate_count": idm_n,
            "est_new": est_new,
        })
    # Overlap is capped at 100% — same semantic as in the per-row UI.
    capped_overlap = min(idm_total, tm_total)
    summary = {
        "tm_total": tm_total,
        "idmate_total": idm_total,
        "est_new_total": new_estimate_total,
        "days": len(out),
        "overlap_pct": round((capped_overlap / tm_total * 100) if tm_total else 0, 1),
    }
    return jsonify({"days": out, "summary": summary})


@admin_bp.route("/api/admin/teslamate/import/start", methods=["POST"])
@admin_required
def admin_teslamate_import_start():
    """Kick off a background import job. Body: car_id, plate, from, to."""
    if not teslamate_import.is_configured():
        return jsonify({"error": "TESLAMATE_PG_URL not set"}), 400
    data = request.get_json() or {}
    try:
        car_id = int(data.get("car_id"))
    except (TypeError, ValueError):
        return jsonify({"error": "car_id required"}), 400
    plate = (data.get("plate") or "").strip()
    if not plate:
        return jsonify({"error": "plate required"}), 400
    db = get_db()
    row = db.execute("SELECT device FROM vehicles WHERE plate = ?", (plate,)).fetchone()
    db.close()
    device = row["device"] if row and row["device"] else config.INFLUX_DEVICE
    date_from = (data.get("from") or "").strip()
    date_to = (data.get("to") or "").strip()
    if not date_from or not date_to:
        return jsonify({"error": "from + to required"}), 400
    geo.extend_backfill_window()
    res = import_job.start(car_id, date_from, date_to, device)
    code = 200 if res.get("ok") else 409
    return jsonify(res), code


@admin_bp.route("/api/admin/teslamate/import/pause", methods=["POST"])
@admin_required
def admin_teslamate_import_pause():
    return jsonify(import_job.pause())


@admin_bp.route("/api/admin/teslamate/import/resume", methods=["POST"])
@admin_required
def admin_teslamate_import_resume():
    geo.extend_backfill_window()
    return jsonify(import_job.resume())


@admin_bp.route("/api/admin/teslamate/import/stop", methods=["POST"])
@admin_required
def admin_teslamate_import_stop():
    return jsonify(import_job.stop())


@admin_bp.route("/api/admin/teslamate/import/status")
@admin_required
def admin_teslamate_import_status():
    return jsonify(import_job.get_status())


@admin_bp.route("/api/admin/teslamate/charges-preview", methods=["POST"])
@admin_required
def admin_teslamate_charges_preview():
    """Per-day counts of TM charging_processes vs. IDMate charge_sessions
    for the same car mapping. Used so the user can spot ranges that are
    already mostly covered before starting an import."""
    if not teslamate_import.is_configured():
        return jsonify({"error": "TESLAMATE_PG_URL not set"}), 400
    data = request.get_json() or {}
    car_map_raw = data.get("car_mapping") or {}
    car_map = {}
    for k, v in car_map_raw.items():
        if v:
            try:
                car_map[int(k)] = v
            except (TypeError, ValueError):
                log.debug("car_mapping: non-integer car id %r — entry skipped", k)
                continue
    if not car_map:
        return jsonify({"days": [], "summary": {}, "error": "no car mapping"}), 200

    date_from = (data.get("from") or "").strip()
    date_to = (data.get("to") or "").strip()

    car_ids = list(car_map.keys())
    try:
        tm_rows = teslamate_import.count_charges_per_day(car_ids, date_from, date_to)
    except Exception as e:
        log.exception("teslamate charges-preview TM count failed: %s", e)
        return jsonify({"error": str(e)}), 500

    # IDMate counts per (plate, day) — match by date(start_time) on charge_sessions
    plates = set(car_map.values())
    idm_by_day = {}  # (plate, 'YYYY-MM-DD') -> count
    if plates and tm_rows:
        db = get_db()
        placeholders = ",".join(["?"] * len(plates))
        rows = db.execute(
            f"""SELECT vehicle_plate AS plate,
                       date(start_time) AS day,
                       COUNT(*) AS n
                FROM charge_sessions
                WHERE vehicle_plate IN ({placeholders})
                  AND date(start_time) BETWEEN ? AND ?
                GROUP BY vehicle_plate, day""",
            (*plates,
             date_from or tm_rows[0]["date"],
             date_to or tm_rows[-1]["date"]),
        ).fetchall()
        db.close()
        for r in rows:
            idm_by_day[(r["plate"], r["day"])] = int(r["n"])

    out = []
    tm_total = idm_total = est_new_total = 0
    for r in tm_rows:
        plate = car_map.get(r["car_id"])
        idm_n = idm_by_day.get((plate, r["date"]), 0)
        est_new = max(0, r["count"] - idm_n)
        tm_total += r["count"]
        idm_total += idm_n
        est_new_total += est_new
        out.append({
            "date": r["date"], "car_id": r["car_id"], "plate": plate,
            "tm_count": r["count"], "idmate_count": idm_n, "est_new": est_new,
        })
    capped = min(idm_total, tm_total)
    summary = {
        "tm_total": tm_total,
        "idmate_total": idm_total,
        "est_new_total": est_new_total,
        "days": len(out),
        "overlap_pct": round((capped / tm_total * 100) if tm_total else 0, 1),
    }
    return jsonify({"days": out, "summary": summary})


@admin_bp.route("/api/admin/teslamate/charges-list", methods=["POST"])
@admin_required
def admin_teslamate_charges_list():
    """Return every TM charging_process in the range plus a per-row flag
    indicating whether IDMate already has a matching session (plate +
    start_time ±5min). Used by the UI for the side-by-side preview."""
    if not teslamate_import.is_configured():
        return jsonify({"error": "TESLAMATE_PG_URL not set"}), 400
    data = request.get_json() or {}
    try:
        car_id = int(data.get("car_id"))
    except (TypeError, ValueError):
        return jsonify({"error": "car_id required"}), 400
    plate = (data.get("plate") or "").strip()
    if not plate:
        return jsonify({"error": "plate required"}), 400
    date_from = (data.get("from") or "").strip()
    date_to = (data.get("to") or "").strip()
    try:
        items = teslamate_import.fetch_charges_list(car_id, date_from, date_to)
    except Exception as e:
        log.exception("teslamate charges-list failed: %s", e)
        return jsonify({"error": str(e)}), 500

    db = get_db()
    out = []
    for it in items:
        dup_id = None
        if it.get("start_time"):
            # ±15min window — same tolerance as the import job's dedup
            row = db.execute(
                """SELECT id FROM charge_sessions
                   WHERE vehicle_plate = ?
                     AND ABS(strftime('%s', start_time) - strftime('%s', ?)) <= 900
                   LIMIT 1""",
                (plate, it["start_time"]),
            ).fetchone()
            dup_id = row["id"] if row else None
        out.append({**it, "duplicate_of": dup_id})
    db.close()
    return jsonify({"items": out, "count": len(out)})


@admin_bp.route("/api/admin/teslamate/charges-import/start", methods=["POST"])
@admin_required
def admin_teslamate_charges_import_start():
    if not teslamate_import.is_configured():
        return jsonify({"error": "TESLAMATE_PG_URL not set"}), 400
    data = request.get_json() or {}
    try:
        car_id = int(data.get("car_id"))
    except (TypeError, ValueError):
        return jsonify({"error": "car_id required"}), 400
    plate = (data.get("plate") or "").strip()
    date_from = (data.get("from") or "").strip()
    date_to = (data.get("to") or "").strip()
    if not plate or not date_from or not date_to:
        return jsonify({"error": "plate + from + to required"}), 400
    res = import_job.start_charges(car_id, date_from, date_to, plate)
    return jsonify(res), (200 if res.get("ok") else 409)


@admin_bp.route("/api/admin/teslamate/charges-import/pause", methods=["POST"])
@admin_required
def admin_teslamate_charges_import_pause():
    return jsonify(import_job.pause_charges())


@admin_bp.route("/api/admin/teslamate/charges-import/resume", methods=["POST"])
@admin_required
def admin_teslamate_charges_import_resume():
    return jsonify(import_job.resume_charges())


@admin_bp.route("/api/admin/teslamate/charges-import/stop", methods=["POST"])
@admin_required
def admin_teslamate_charges_import_stop():
    return jsonify(import_job.stop_charges())


@admin_bp.route("/api/admin/teslamate/charges-by-plate")
@admin_required
def admin_teslamate_charges_by_plate():
    """Diagnostic: per plate, how many charge_sessions are internal vs TM
    imports — so a mis-mapped import (TM rows under the wrong plate) is
    immediately visible."""
    db = get_db()
    rows = db.execute(
        """SELECT vehicle_plate AS plate,
                  SUM(CASE WHEN session_number LIKE 'TM-%' THEN 1 ELSE 0 END) AS tm,
                  SUM(CASE WHEN session_number LIKE 'TM-%' THEN 0 ELSE 1 END) AS internal
           FROM charge_sessions
           GROUP BY vehicle_plate
           ORDER BY vehicle_plate"""
    ).fetchall()
    db.close()
    return jsonify([{"plate": r["plate"], "tm": r["tm"], "internal": r["internal"]}
                    for r in rows])


@admin_bp.route("/api/admin/teslamate/charges-reassign", methods=["POST"])
@admin_required
def admin_teslamate_charges_reassign():
    """Move TM-imported charge_sessions (session_number LIKE 'TM-%') from one
    plate to another — fixes a mis-mapped import without re-importing."""
    data = request.get_json() or {}
    from_plate = (data.get("from_plate") or "").strip()
    to_plate = (data.get("to_plate") or "").strip()
    if not from_plate or not to_plate:
        return jsonify({"error": "from_plate + to_plate required"}), 400
    if from_plate == to_plate:
        return jsonify({"error": "from_plate == to_plate"}), 400
    db = get_db()
    cur = db.execute(
        "UPDATE charge_sessions SET vehicle_plate = ? "
        "WHERE vehicle_plate = ? AND session_number LIKE 'TM-%'",
        (to_plate, from_plate),
    )
    db.commit()
    moved = cur.rowcount
    db.close()
    _trend_cache.clear()  # estimates depend on plate assignment
    return jsonify({"ok": True, "moved": moved})


@admin_bp.route("/api/admin/teslamate/charges-import/status")
@admin_required
def admin_teslamate_charges_import_status():
    return jsonify(import_job.get_charges_status())


@admin_bp.route("/api/charges/delete-range", methods=["POST"])
@admin_required
def delete_charge_range():
    """Delete charge readings by ID range and rebuild sessions."""
    data = request.get_json()
    id_from = data.get("from")
    id_to = data.get("to")
    if id_from is None or id_to is None:
        return jsonify({"error": "from und to erforderlich"}), 400
    db = get_db()
    # Capture the affected time range before deleting, so the rebuild stays scoped.
    rng = db.execute(
        "SELECT MIN(timestamp) AS m FROM charge_readings WHERE id >= ? AND id <= ?",
        (id_from, id_to),
    ).fetchone()
    since = rng["m"] if rng else None
    cur = db.execute(
        "DELETE FROM charge_readings WHERE id >= ? AND id <= ?",
        (id_from, id_to),
    )
    deleted = cur.rowcount
    db.commit()
    rebuild_charge_sessions(db, since=since)
    db.close()
    return jsonify({"ok": True, "deleted": deleted})


@admin_bp.route("/api/admin/scan-debug")
@debug_required
def admin_scan_debug():
    """Show what the detector would see — without saving."""
    device = request.args.get("device") or active_device()
    hours = int(request.args.get("hours", 24))
    since = datetime.now(timezone.utc) - timedelta(hours=hours)

    db = detector.get_db()

    # Whitelist device against vehicles table. The value lands unquoted in an
    # Influx-Flux predicate (via query_drive_data), so anything but a known
    # device opens a predicate-injection.
    valid_devices = {r["device"] for r in db.execute(
        "SELECT device FROM vehicles WHERE device IS NOT NULL AND device != ''"
    ).fetchall()}
    if device not in valid_devices:
        db.close()
        return jsonify({"error": "Unbekanntes device"}), 400

    client = detector.get_influx()
    if not client:
        db.close()
        return jsonify({"error": "InfluxDB nicht erreichbar"}), 503

    last_end = detector.last_trip_end(db, device)
    rows_raw = detector.query_drive_data(client, since, device)
    client.close()

    rows = detector.expand_rows(rows_raw) if rows_raw else []
    has_ig = any(r.get("ig") is not None for r in rows)

    bat_row = db.execute(
        "SELECT battery_capacity_kwh FROM vehicles WHERE device = ? AND battery_capacity_kwh IS NOT NULL", (device,)
    ).fetchone()
    bat_kwh = float(bat_row["battery_capacity_kwh"]) if bat_row else 86.5

    trips = detector.detect_trips(rows, bat_kwh, device=device) if rows else []
    db.close()

    return jsonify({
        "device": device,
        "since_used": since.isoformat(),
        "last_trip_end_in_db": str(last_end),
        "raw_rows_count": len(rows_raw),
        "expanded_rows_count": len(rows),
        "has_ig": has_ig,
        "trips_detected": len(trips),
        "trips": [
            {
                "start": t["start_time"],
                "end": t["end_time"],
                "distance_km": t.get("distance_km"),
                "soc": f"{t.get('soc_start')}→{t.get('soc_end')}",
            }
            for t in trips
        ],
        "first_row_time": str(rows[0].get("_time")) if rows else None,
        "last_row_time": str(rows[-1].get("_time")) if rows else None,
    })


@admin_bp.route("/api/admin/stats/stick-battery")
@admin_required
def stats_stick_battery():
    """ESP-stick battery (bd field) per device for last 48h."""
    client = detector.get_influx()
    if not client:
        return jsonify({"devices": []})
    try:
        query = f'''
        from(bucket: "{config.INFLUX_BUCKET}")
          |> range(start: -48h)
          |> filter(fn: (r) => r._measurement == "v" and r._field == "bd")
          |> aggregateWindow(every: 15m, fn: mean, createEmpty: false)
          |> sort(columns: ["_time"])
        '''
        tables = client.query_api().query(query, org=config.INFLUX_ORG)
        # Group by device tag
        by_device = {}
        for table in tables:
            for rec in table.records:
                dev = rec.values.get("d") or "unknown"
                t = rec.get_time()
                v = rec.get_value()
                if t is None or v is None:
                    continue
                ts_ms = int(t.timestamp() * 1000)
                by_device.setdefault(dev, []).append([ts_ms, round(v, 1)])
    finally:
        client.close()

    # Stable colors per device
    palette = ["#58a6ff", "#f85149", "#3fb950", "#d29922", "#bc8cff", "#f0883e"]
    devices = []
    for i, (dev, points) in enumerate(sorted(by_device.items())):
        devices.append({
            "name": dev,
            "color": palette[i % len(palette)],
            "data": points,
        })
    return jsonify({"devices": devices})


@admin_bp.route("/api/admin/stats/data-volume")
@admin_required
def stats_data_volume():
    """Hourly count of telemetry points per device (last 48h)."""
    client = detector.get_influx()
    if not client:
        return jsonify({"hours": [], "devices": []})
    try:
        # Use a single field (la) to count "rows" — multi-field points share a timestamp
        query = f'''
        from(bucket: "{config.INFLUX_BUCKET}")
          |> range(start: -48h)
          |> filter(fn: (r) => r._measurement == "v" and r._field == "la")
          |> aggregateWindow(every: 1h, fn: count, createEmpty: true)
        '''
        tables = client.query_api().query(query, org=config.INFLUX_ORG)
        # Build matrix: hour timestamp -> device -> count
        by_device = {}
        all_hours = set()
        for table in tables:
            for rec in table.records:
                dev = rec.values.get("d") or "unknown"
                t = rec.get_time()
                cnt = rec.get_value() or 0
                if t is None:
                    continue
                ts_ms = int(t.timestamp() * 1000)
                all_hours.add(ts_ms)
                by_device.setdefault(dev, {})[ts_ms] = cnt
    finally:
        client.close()

    hours = sorted(all_hours)
    palette = ["#58a6ff", "#f85149", "#3fb950", "#d29922", "#bc8cff", "#f0883e"]
    devices = []
    for i, dev in enumerate(sorted(by_device.keys())):
        # ~80 bytes per point estimate
        data = [round(by_device[dev].get(h, 0) * 80 / 1024, 1) for h in hours]  # KB
        devices.append({
            "name": dev,
            "color": palette[i % len(palette)],
            "data": data,
        })
    return jsonify({"hours": hours, "devices": devices})


@admin_bp.route("/api/admin/stats/carrier-coverage")
@admin_required
def stats_carrier_coverage():
    """LTE signal strength per carrier on a coordinate grid (last 30 days).

    Returns clusters of points grouped by carrier with average signal.
    """
    client = detector.get_influx()
    if not client:
        return jsonify({"carriers": []})
    try:
        # `last` (not `mean`) keeps real GPS samples instead of fictional time
        # averages — otherwise curves and turns get cut into chords. 30s window
        # downsamples to a manageable rate without losing road-following detail.
        query = f'''
        from(bucket: "{config.INFLUX_BUCKET}")
          |> range(start: -30d)
          |> filter(fn: (r) => r._measurement == "v")
          |> filter(fn: (r) => r._field == "la" or r._field == "lo" or r._field == "ls" or r._field == "lp")
          |> aggregateWindow(every: 30s, fn: last, createEmpty: false)
          |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
          |> filter(fn: (r) => exists r.la and exists r.lo and exists r.ls and exists r.lp)
        '''
        tables = client.query_api().query(query, org=config.INFLUX_ORG)
        # Group by carrier + grid cell (4 decimal places ≈ 11m / road width)
        cells = {}  # (plmn, lat_grid, lon_grid) -> {"sum": ls, "n": ..., "la_sum": ..., "lo_sum": ...}
        for table in tables:
            for rec in table.records:
                la = rec.values.get("la")
                lo = rec.values.get("lo")
                ls = rec.values.get("ls")
                lp = rec.values.get("lp")
                if la is None or lo is None or ls is None or lp is None:
                    continue
                if abs(la) < 0.5 or abs(lo) < 0.5 or ls > 31:
                    continue
                lp_int = int(lp)
                key = (lp_int, round(la, 4), round(lo, 4))
                if key not in cells:
                    cells[key] = {"sum": 0, "n": 0, "la_sum": 0, "lo_sum": 0}
                c = cells[key]
                c["sum"] += ls
                c["n"] += 1
                c["la_sum"] += la
                c["lo_sum"] += lo
    finally:
        client.close()

    # Group cells by carrier *name* (Telekom 26201 + 26206 merge into one
    # legend entry). Brand color comes from plmn.py so every European
    # provider gets its own consistent corporate-design color.
    carriers_dict: dict[str, dict] = {}
    for (plmn, _, _), c in cells.items():
        name, color = plmn_info(plmn)
        if not name:
            name = f"PLMN {plmn}"
        entry = carriers_dict.setdefault(name, {
            "key": name,
            "name": name,
            "color": color,
            "plmns": set(),
            "points": [],
        })
        entry["plmns"].add(plmn)
        entry["points"].append({
            "lat": round(c["la_sum"] / c["n"], 5),
            "lon": round(c["lo_sum"] / c["n"], 5),
            "csq": round(c["sum"] / c["n"], 1),
            "n": c["n"],
        })

    carriers = []
    for entry in sorted(carriers_dict.values(), key=lambda e: e["name"]):
        carriers.append({
            "key": entry["key"],
            "name": entry["name"],
            "color": entry["color"],
            "plmns": sorted(entry["plmns"]),
            "points": entry["points"],
            "total_n": sum(p["n"] for p in entry["points"]),
        })
    return jsonify({"carriers": carriers})


@admin_bp.route("/api/admin/influx-delete", methods=["POST"])
@debug_required
def admin_influx_delete():
    """Delete individual data points from InfluxDB (by exact timestamp)."""
    data = request.get_json() or {}
    device = data.get("device", "")
    timestamps = data.get("timestamps", [])
    if not device or not timestamps:
        return jsonify({"ok": False, "error": "device und timestamps erforderlich"}), 400

    # Whitelist device against vehicles table. The value lands unquoted in an
    # Influx-Flux predicate (line below), so anything but a known device opens a
    # predicate-injection that could delete arbitrary points in the time window.
    db = get_db()
    valid_devices = {r["device"] for r in db.execute(
        "SELECT device FROM vehicles WHERE device IS NOT NULL AND device != ''"
    ).fetchall()}
    db.close()
    if device not in valid_devices:
        return jsonify({"ok": False, "error": "Unbekanntes device"}), 400

    client = detector.get_influx()
    if not client:
        return jsonify({"ok": False, "error": "InfluxDB nicht erreichbar"}), 503

    delete_api = client.delete_api()
    deleted = 0
    try:
        for ts in timestamps:
            # Delete exact timestamp: start = ts, stop = ts + 1µs
            start = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            stop = start + timedelta(microseconds=1)
            delete_api.delete(
                start, stop,
                predicate=f'_measurement="v" AND d="{device}"',
                bucket=config.INFLUX_BUCKET,
                org=config.INFLUX_ORG,
            )
            deleted += 1
    except Exception as e:
        log.exception("InfluxDB delete failed")
        return jsonify({"ok": False, "error": str(e)}), 500
    finally:
        client.close()

    return jsonify({"ok": True, "deleted": deleted})


@admin_bp.route("/api/admin/rescan", methods=["POST"])
@admin_required
def admin_rescan():
    """Rescan trips and charges for active vehicle.
    Deletes all trips/charges in the period first, then re-detects."""
    data = request.get_json() or {}
    date_from = data.get("date_from", "")
    date_to = data.get("date_to", "")
    try:
        since = datetime.fromisoformat(date_from).replace(tzinfo=detector.LOCAL_TZ).astimezone(timezone.utc) if date_from else datetime.now(timezone.utc) - timedelta(days=30)
        until = (datetime.fromisoformat(date_to).replace(tzinfo=detector.LOCAL_TZ).astimezone(timezone.utc) + timedelta(days=1)) if date_to else None
    except ValueError:
        return jsonify({"error": "Ungültiges Datumsformat"}), 400

    dev = active_device()
    since_local = since.astimezone(detector.LOCAL_TZ).strftime("%Y-%m-%dT%H:%M:%S")
    until_local = until.astimezone(detector.LOCAL_TZ).strftime("%Y-%m-%dT%H:%M:%S") if until else "9999-12-31T23:59:59"

    db = detector.get_db()
    client = detector.get_influx()
    if not client:
        db.close()
        return jsonify({"error": "InfluxDB nicht erreichbar"}), 503

    # Delete all existing trips + charges in the period for this device
    deleted_trips = db.execute(
        """DELETE FROM trips WHERE device = ?
           AND datetime(start_time) >= datetime(?)
           AND datetime(start_time) <= datetime(?)""",
        (dev, since_local, until_local),
    ).rowcount
    # Clean up GPX waypoints and journey assignments
    db.execute(
        """DELETE FROM gpx_waypoints WHERE trip_id NOT IN (SELECT id FROM trips)""")
    db.execute(
        """DELETE FROM journey_trips WHERE trip_id NOT IN (SELECT id FROM trips)""")

    deleted_charges = db.execute(
        """DELETE FROM charges WHERE device = ?
           AND datetime(start_time) >= datetime(?)
           AND datetime(start_time) <= datetime(?)""",
        (dev, since_local, until_local),
    ).rowcount
    db.commit()
    log.info("Rescan %s: %d trips + %d charges deleted in period", dev, deleted_trips, deleted_charges)

    # Re-detect
    trips_found = 0
    charges_found = 0
    try:
        rows = detector.query_drive_data(client, since, dev, until=until)
        if rows:
            rows = detector.expand_rows(rows)
            bat_kwh = get_bat_kwh(db, dev)
            trips = detector.detect_trips(rows, bat_kwh, device=dev)
            charges = detector.detect_charges(rows, device=dev)
            if trips:
                detector.save_trips(db, trips)
                trips_found = len(trips)
            if charges:
                detector.save_charges(db, charges)
                charges_found = len(charges)
        detector.auto_categorize(db)
    except Exception as e:
        log.exception("Error during rescan")
        db.close()
        client.close()
        return jsonify({"error": str(e)}), 500

    db.close()
    client.close()
    return jsonify({
        "device": dev,
        "deleted_trips": deleted_trips,
        "deleted_charges": deleted_charges,
        "trips_found": trips_found,
        "charges_found": charges_found,
    })


@admin_bp.route("/api/admin/users")
@admin_required
def list_users():
    db = get_db()
    rows = db.execute("SELECT id, username, is_admin, created_at, totp_enabled FROM users ORDER BY id").fetchall()
    # Pro-User-Fahrzeug-Sichtbarkeit: leere Liste = alle Fahrzeuge (keine Einschraenkung).
    access = {}
    for r in db.execute("SELECT user_id, vehicle_id FROM user_vehicle_access").fetchall():
        access.setdefault(r["user_id"], []).append(r["vehicle_id"])
    db.close()
    out = []
    for r in rows:
        d = dict(r)
        d["vehicle_ids"] = sorted(access.get(r["id"], []))
        out.append(d)
    return jsonify(out)


@admin_bp.route("/api/admin/users/<int:user_id>/vehicles", methods=["POST"])
@admin_required
def set_user_vehicles(user_id):
    """Welche Fahrzeuge der User sehen darf. Leere Liste = alle (keine Einschraenkung),
    nicht-leere Liste = genau diese (Zeilen ersetzen)."""
    data = request.get_json(silent=True) or {}
    raw = data.get("vehicle_ids") or []
    try:
        ids = [int(v) for v in raw]
    except (TypeError, ValueError):
        return jsonify({"error": "Ungültige Fahrzeug-IDs"}), 400
    db = get_db()
    valid = {r["id"] for r in db.execute("SELECT id FROM vehicles").fetchall()}
    ids = [v for v in ids if v in valid]
    with db:
        db.execute("DELETE FROM user_vehicle_access WHERE user_id = ?", (user_id,))
        for v in ids:
            db.execute("INSERT OR IGNORE INTO user_vehicle_access (user_id, vehicle_id) VALUES (?, ?)",
                       (user_id, v))
    db.close()
    return jsonify({"ok": True, "vehicle_ids": sorted(ids)})


@admin_bp.route("/api/admin/users", methods=["POST"])
@admin_required
def create_user():
    data = request.get_json()
    username = data.get("username", "").strip()
    password = data.get("password", "")
    is_admin = 1 if data.get("is_admin") else 0

    if not username or not password:
        return jsonify({"error": "Benutzername und Passwort erforderlich"}), 400
    pw_err = _validate_password(password)
    if pw_err:
        return jsonify({"error": pw_err}), 400

    db = get_db()
    existing = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if existing:
        db.close()
        return jsonify({"error": "Benutzername existiert bereits"}), 400

    db.execute(
        "INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)",
        (username, generate_password_hash(password), is_admin),
    )
    db.commit()
    db.close()
    return jsonify({"ok": True})


@admin_bp.route("/api/admin/users/<int:user_id>", methods=["DELETE"])
@admin_required
def delete_user(user_id):
    if user_id == current_user.id:
        return jsonify({"error": "Eigenen Account nicht loeschbar"}), 400
    db = get_db()
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    db.close()
    return jsonify({"ok": True})


@admin_bp.route("/api/admin/users/<int:user_id>/password", methods=["POST"])
@admin_required
def change_password(user_id):
    data = request.get_json()
    password = data.get("password", "")
    pw_err = _validate_password(password)
    if pw_err:
        return jsonify({"error": pw_err}), 400
    db = get_db()
    db.execute("UPDATE users SET password_hash = ? WHERE id = ?",
               (generate_password_hash(password), user_id))
    db.commit()
    db.close()
    return jsonify({"ok": True})


@admin_bp.route("/api/admin/db-stats")
@admin_required
def admin_db_stats():
    import time
    import os
    result = {"sqlite": {}, "influx": {}}

    db = get_db()
    try:
        try:
            result["sqlite"]["file_bytes"] = os.path.getsize(config.DB_PATH)
        except Exception:
            result["sqlite"]["file_bytes"] = 0

        pc = db.execute("PRAGMA page_count").fetchone()[0]
        ps = db.execute("PRAGMA page_size").fetchone()[0]
        fl = db.execute("PRAGMA freelist_count").fetchone()[0]
        result["sqlite"]["fragmentation_pct"] = round(fl / pc * 100, 1) if pc > 0 else 0

        tables = [
            "trips", "locations", "charges", "route_rules", "users",
            "purpose_meta", "preset_values", "settings", "vehicles",
            "charge_tariffs", "charge_readings", "charge_sessions",
            "charge_locations", "journeys", "journey_trips",
        ]
        counts = {}
        for tbl in tables:
            try:
                counts[tbl] = db.execute(f"SELECT COUNT(*) FROM {tbl}").fetchone()[0]
            except Exception:
                counts[tbl] = None
        result["sqlite"]["tables"] = counts
        result["sqlite"]["total_rows"] = sum(v for v in counts.values() if v is not None)

        t0 = time.time()
        ic = db.execute("PRAGMA integrity_check(20)").fetchall()
        result["sqlite"]["integrity_ms"] = round((time.time() - t0) * 1000)
        result["sqlite"]["integrity_ok"] = ic[0][0] == "ok"
        result["sqlite"]["integrity_issues"] = [r[0] for r in ic if r[0] != "ok"]

        t0 = time.time()
        db.execute("CREATE TEMP TABLE _spd (x INTEGER)")
        for i in range(100):
            db.execute("INSERT INTO _spd VALUES (?)", (i,))
        db.execute("SELECT COUNT(*) FROM _spd")
        db.execute("DROP TABLE _spd")
        result["sqlite"]["write_100_ms"] = round((time.time() - t0) * 1000)
    finally:
        db.close()

    if not config.INFLUX_TOKEN:
        result["influx"]["status"] = "not_configured"
    else:
        try:
            from influxdb_client import InfluxDBClient
            client = InfluxDBClient(url=config.INFLUX_URL, token=config.INFLUX_TOKEN, org=config.INFLUX_ORG)
            t0 = time.time()
            health = client.health()
            result["influx"]["ping_ms"] = round((time.time() - t0) * 1000)
            result["influx"]["status"] = str(health.status)
            result["influx"]["version"] = getattr(health, "version", None)

            q_api = client.query_api()
            t0 = time.time()
            tbl_l = q_api.query(
                f'from(bucket:"{config.INFLUX_BUCKET}") |> range(start:-90d)'
                f' |> filter(fn:(r)=>r._measurement=="v") |> last() |> keep(columns:["_time"])',
                org=config.INFLUX_ORG,
            )
            result["influx"]["query_ms"] = round((time.time() - t0) * 1000)
            latest = None
            for tbl in tbl_l:
                for rec in tbl.records:
                    ts = rec.get_time()
                    if ts and (latest is None or ts > latest):
                        latest = ts
            result["influx"]["latest_record"] = latest.isoformat() if latest else None

            t0 = time.time()
            tbl_c = q_api.query(
                f'from(bucket:"{config.INFLUX_BUCKET}") |> range(start:-7d)'
                f' |> filter(fn:(r)=>r._measurement=="v") |> count() |> sum(column:"_value")',
                org=config.INFLUX_ORG,
            )
            result["influx"]["count_query_ms"] = round((time.time() - t0) * 1000)
            pts = 0
            for tbl in tbl_c:
                for rec in tbl.records:
                    v = rec.get_value()
                    if v:
                        pts += int(v)
            result["influx"]["points_7d"] = pts
            client.close()

            # Disk size via Prometheus /metrics endpoint
            import urllib.request as _ur
            try:
                _req = _ur.Request(
                    f"{config.INFLUX_URL}/metrics",
                    headers={"Authorization": f"Token {config.INFLUX_TOKEN}"},
                )
                with _ur.urlopen(_req, timeout=5) as _resp:
                    _metrics = _resp.read().decode("utf-8", errors="replace")
                _disk = 0
                for _line in _metrics.splitlines():
                    if not _line.startswith("#") and "disk_bytes" in _line:
                        _parts = _line.split()
                        if len(_parts) >= 2:
                            try:
                                _disk += float(_parts[-1])
                            except ValueError:
                                log.debug("influx metrics: non-numeric disk_bytes value %r — skipped", _parts[-1])
                result["influx"]["disk_bytes"] = int(_disk) if _disk else None
            except Exception:
                result["influx"]["disk_bytes"] = None
        except Exception as e:
            result["influx"]["status"] = "error"
            result["influx"]["error"] = str(e)

    return jsonify(result)

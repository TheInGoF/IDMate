"""Trip detection — reads InfluxDB, detects trips + charging sessions, writes to SQLite."""

import sqlite3
import time
import logging
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

LOCAL_TZ = ZoneInfo("Europe/Berlin")

def _local_iso(dt):
    """UTC datetime → local time ISO string without offset suffix."""
    return dt.astimezone(LOCAL_TZ).strftime("%Y-%m-%dT%H:%M:%S")

from influxdb_client import InfluxDBClient

import math

import config

log = logging.getLogger("triplog.detector")


def haversine_m(lat1, lon1, lat2, lon2):
    """Distance in meters between two GPS coordinates."""
    R = 6371000
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat/2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon/2)**2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))


# Bit index → field name (must match ESP32 firmware)
FIELDS = {
    0:  's',   # SOC
    1:  'u',   # Voltage
    2:  'i',   # Current
    3:  'p',   # Power
    4:  'v',   # Speed
    5:  'c',   # IsCharging
    6:  'dc',  # IsDCFC
    7:  'bt',  # BattTemp
    8:  'et',  # ExtTemp
    9:  'r',   # Range
    10: 'la',  # Latitude
    11: 'lo',  # Longitude
    12: 'hd',  # Heading
    15: 'ls',  # LTESignal
    17: 'ca',  # Capacity
    18: 'kw',  # kWhCharged
    19: 'pk',  # IsParked
    20: 'od',  # Odometer
    21: 'bd',  # BattDevice
    22: 'ig',  # Ignition (0=off, 1=on)
}


def expand_rows(rows):
    """Resolves delta compression: copy _eq fields from predecessor, _na fields → None."""
    expanded = []
    prev = {}
    for row in rows:
        eq_mask = int(row.get('_eq') or 0)
        na_mask = int(row.get('_na') or 0)

        result = {k: v for k, v in row.items() if k not in ('_eq', '_na')}

        for bit, key in FIELDS.items():
            if key in row and row[key] is not None:
                continue  # Value explicitly present
            if eq_mask & (1 << bit):
                result[key] = prev.get(key)
            elif na_mask & (1 << bit):
                result[key] = None

        prev = result
        expanded.append(result)
    return expanded


def get_db():
    db = sqlite3.connect(config.DB_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    if not getattr(get_db, '_schema_done', False):
        with open("schema.sql") as f:
            db.executescript(f.read())
        # Migration: add new columns if missing
        cols = [r[1] for r in db.execute("PRAGMA table_info(trips)").fetchall()]
        if "destination" not in cols:
            db.execute("ALTER TABLE trips ADD COLUMN destination TEXT")
        if "visit_reason" not in cols:
            db.execute("ALTER TABLE trips ADD COLUMN visit_reason TEXT")
        if "odo_start" not in cols:
            db.execute("ALTER TABLE trips ADD COLUMN odo_start REAL")
        if "odo_end" not in cols:
            db.execute("ALTER TABLE trips ADD COLUMN odo_end REAL")
        if "kw_start" not in cols:
            db.execute("ALTER TABLE trips ADD COLUMN kw_start REAL")
        if "kw_end" not in cols:
            db.execute("ALTER TABLE trips ADD COLUMN kw_end REAL")
        loc_cols = [r[1] for r in db.execute("PRAGMA table_info(locations)").fetchall()]
        if "icon" not in loc_cols:
            db.execute("ALTER TABLE locations ADD COLUMN icon TEXT DEFAULT 'pin'")
        if "color" not in loc_cols:
            db.execute("ALTER TABLE locations ADD COLUMN color TEXT DEFAULT '#58a6ff'")
        if "icon_color" not in loc_cols:
            db.execute("ALTER TABLE locations ADD COLUMN icon_color TEXT DEFAULT 'white'")
        db.execute("UPDATE locations SET icon_color = 'white' WHERE icon_color IS NULL")
        cl_cols = [r[1] for r in db.execute("PRAGMA table_info(charge_locations)").fetchall()]
        if "polygon_coords" not in cl_cols:
            db.execute("ALTER TABLE charge_locations ADD COLUMN polygon_coords TEXT")
        db.commit()
        get_db._schema_done = True
    return db


def get_influx():
    if not config.INFLUX_TOKEN:
        return None
    return InfluxDBClient(
        url=config.INFLUX_URL,
        token=config.INFLUX_TOKEN,
        org=config.INFLUX_ORG,
    )


def last_trip_end(db, device):
    """Timestamp of the last detected trip end, at least 24h back."""
    row = db.execute(
        "SELECT end_time FROM trips WHERE device = ? ORDER BY end_time DESC LIMIT 1",
        (device,),
    ).fetchone()
    min_lookback = datetime.now(timezone.utc) - timedelta(hours=24)
    if row:
        ts = row["end_time"].strip().replace("Z", "+00:00")
        last = datetime.fromisoformat(ts)
        if last.tzinfo is None:
            # Stored times are local time (Europe/Berlin) without offset
            last = last.replace(tzinfo=LOCAL_TZ)
        last_utc = last.astimezone(timezone.utc)
        # Always look back at least 24h to close gaps
        return min(last_utc, min_lookback)
    return datetime.now(timezone.utc) - timedelta(days=7)


def _merge_rows(rows):
    """Merges rows with the same _time into a single row.
    InfluxDB pivot produces multiple tables with different fields —
    without merging, data gets incorrectly interleaved."""
    if not rows:
        return rows
    merged = []
    current = dict(rows[0])
    for row in rows[1:]:
        if row.get("_time") == current.get("_time"):
            # Same timestamp: merge fields (prefer existing values)
            for k, v in row.items():
                if v is not None and (k not in current or current[k] is None):
                    current[k] = v
        else:
            merged.append(current)
            current = dict(row)
    merged.append(current)
    return merged


def query_drive_data(client, since, device, until=None):
    """Fetches all vehicle fields incl. _eq/_na bitmasks from `since` to `until`."""
    # Flux requires RFC3339 with Z (no +00:00)
    ts = since.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    stop_clause = f", stop: {until.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}" if until else ""
    query = f'''
    from(bucket: "{config.INFLUX_BUCKET}")
      |> range(start: {ts}{stop_clause})
      |> filter(fn: (r) => r._measurement == "v" and r.d == "{device}")
      |> filter(fn: (r) => r._field == "v" or r._field == "s" or r._field == "p" or r._field == "od" or r._field == "la" or r._field == "lo" or r._field == "pk" or r._field == "c" or r._field == "dc" or r._field == "ca" or r._field == "ig" or r._field == "kw" or r._field == "_eq" or r._field == "_na")
      |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
      |> sort(columns: ["_time"])
    '''
    tables = client.query_api().query(query, org=config.INFLUX_ORG)
    rows = []
    for table in tables:
        for record in table.records:
            rows.append(record.values)
    # Pivot produces multiple tables with different fields —
    # merge rows with the same _time into one row
    rows.sort(key=lambda r: r.get("_time") or datetime.min.replace(tzinfo=timezone.utc))
    return _merge_rows(rows)


DATA_GAP_MINUTES = 5   # Data gap >= 5 min = trip end
STOP_MINUTES = 3       # v==0 for >= 3 min = trip end
SOC_JUMP_MIN = 5       # SoC increase >= 5% with standstill = charging → trip end


def _save_trip(trips, trip_start, trip_points, bat_kwh, device):
    """Helper: builds trip and appends if valid."""
    if not trip_points:
        return
    trip = build_trip(trip_start, trip_points[-1], trip_points, bat_kwh, device=device)
    if trip and (trip["distance_km"] or 0) >= config.TRIP_MIN_DISTANCE_KM:
        trips.append(trip)


def detect_trips(rows, bat_kwh=86.5, device=None):
    """Detects trips from pivoted InfluxDB rows.

    Purely speed-based detection (ig is ignored):

    - Trip starts when v > 0
    - Trip ends on:
      - Data gap >= DATA_GAP_MINUTES (5 min)
      - v == 0 for >= STOP_MINUTES (3 min)
      - SoC jump >= 5% upward with v==0 in between (charging)
    - Open trip: save if last point is older than DATA_GAP_MINUTES
    """
    # Ensure rows are sorted chronologically
    rows = sorted(rows, key=lambda r: r.get("_time") or datetime.min.replace(tzinfo=timezone.utc))

    trips = []
    in_trip = False
    trip_start = None
    trip_points = []
    last_time = None
    last_moving_time = None   # last timestamp with v > 0
    _last_soc = None
    _had_standstill = False   # was there v==0 since last SoC value?
    _prev_lat = None
    _prev_lon = None

    for row in rows:
        t = row.get("_time")
        if t is None:
            continue

        v = row.get("v")
        soc = row.get("s")
        gap = (t - last_time).total_seconds() / 60 if last_time and t else 0

        # Detect movement: v > 0 OR GPS progress as fallback when v is missing
        la = row.get("la")
        lo = row.get("lo")
        if v is not None:
            moving = v > 0
        elif la and lo and _prev_lat and _prev_lon:
            dt_sec = (t - last_time).total_seconds() if last_time and t else 0
            gps_dist = haversine_m(_prev_lat, _prev_lon, la, lo)
            # > 50m in one interval = clearly moving
            moving = gps_dist > 50 and dt_sec > 0
        else:
            moving = False
        if la and lo:
            _prev_lat = la
            _prev_lon = lo

        # Track standstill
        if v is not None and v == 0:
            _had_standstill = True

        # Detect SoC jump (only with standstill in between)
        soc_jump = False
        if soc is not None and _last_soc is not None:
            if soc - _last_soc >= SOC_JUMP_MIN and _had_standstill:
                soc_jump = True
        if soc is not None:
            _last_soc = soc
            _had_standstill = False

        # How long has the car been stationary?
        standstill_min = 0
        if not moving and last_moving_time and t:
            standstill_min = (t - last_moving_time).total_seconds() / 60

        if not in_trip:
            if moving:
                in_trip = True
                trip_start = row
                trip_points = [row]
                last_moving_time = t
        else:
            end_trip = False

            if gap >= DATA_GAP_MINUTES:
                end_trip = True
            elif standstill_min >= STOP_MINUTES:
                end_trip = True
            elif soc_jump:
                end_trip = True

            if end_trip:
                _save_trip(trips, trip_start, trip_points, bat_kwh, device)
                in_trip = False
                trip_points = []
                trip_start = None
                if moving:
                    in_trip = True
                    trip_start = row
                    trip_points = [row]
                    last_moving_time = t
            else:
                trip_points.append(row)
                if moving:
                    last_moving_time = t

        last_time = t

    # Open trip at end (still in_trip = end_trip never triggered)
    if in_trip and trip_points and last_time is not None:
        age_min = (datetime.now(timezone.utc) - last_time).total_seconds() / 60
        if age_min >= DATA_GAP_MINUTES:
            _save_trip(trips, trip_start, trip_points, bat_kwh, device)
        else:
            log.debug("Open trip still active (last point %.1f min ago), skipping", age_min)

    # Only return the last completed trip when it is definitely over:
    # Only when the last data point is >= DATA_GAP_MINUTES ago,
    # we can be sure no more data is coming.
    if trips and last_time is not None:
        age_min = (datetime.now(timezone.utc) - last_time).total_seconds() / 60
        if age_min < DATA_GAP_MINUTES:
            removed = trips.pop()
            log.debug("Last trip (%s) withheld — data still too fresh (%.1f min)",
                       removed.get("end_time"), age_min)

    return trips


GPS_MAX_KMH = 500  # GPS jumps > 500 km/h are filtered as invalid


def _filter_gps_jumps(points):
    """Filters GPS jumps: removes points with implied speed > GPS_MAX_KMH."""
    filtered = []
    for pt in points:
        la, lo, t = pt.get("la"), pt.get("lo"), pt.get("_time")
        if la is None or lo is None or t is None:
            filtered.append(pt)
            continue
        if not filtered:
            filtered.append(pt)
            continue
        # Find last point with valid GPS data
        prev = None
        for p in reversed(filtered):
            if p.get("la") is not None and p.get("lo") is not None and p.get("_time") is not None:
                prev = p
                break
        if prev is None:
            filtered.append(pt)
            continue
        dist_m = haversine_m(prev["la"], prev["lo"], la, lo)
        dt_h = (t - prev["_time"]).total_seconds() / 3600
        if dt_h > 0 and dist_m / 1000 / dt_h > GPS_MAX_KMH:
            continue  # GPS jump → discard point
        filtered.append(pt)
    return filtered


def build_trip(start_row, end_row, points, bat_kwh=86.5, device=None):
    """Builds a trip dict from start/end/intermediate points."""
    # Filter GPS jumps
    points = _filter_gps_jumps(points)
    if not points:
        return None

    # Start/end from filtered GPS points
    gps_start = next((p for p in points if p.get("la") and p.get("lo")), start_row)
    gps_end = next((p for p in reversed(points) if p.get("la") and p.get("lo")), end_row)

    # Odometer: find first and last valid value from all points
    od_start = None
    od_end = None
    for pt in points:
        v = pt.get("od")
        if v is not None:
            if od_start is None:
                od_start = v
            od_end = v
    distance = (od_end - od_start) if od_start is not None and od_end is not None else None

    # GPS distance as fallback when no odometer available
    if distance is None:
        gps_pts = [(pt.get("la"), pt.get("lo")) for pt in points if pt.get("la") and pt.get("lo")]
        if len(gps_pts) >= 2:
            dist_gps = sum(
                haversine_m(gps_pts[i][0], gps_pts[i][1], gps_pts[i+1][0], gps_pts[i+1][1])
                for i in range(len(gps_pts) - 1)
            )
            distance = round(dist_gps / 1000, 2)

    # SoC: first/last non-None value from all points (delta-compressed data)
    soc_start = None
    soc_end = None
    for pt in points:
        s = pt.get("s")
        if s is not None:
            if soc_start is None:
                soc_start = s
            soc_end = s

    # kWh counter (cumulative): first/last valid value
    kw_start = None
    kw_end = None
    for pt in points:
        k = pt.get("kw")
        if k is not None:
            if kw_start is None:
                kw_start = k
            kw_end = k

    # Battery capacity: from InfluxDB (ca field) if available, otherwise from settings
    cap = None
    for pt in reversed(points):
        ca = pt.get("ca")
        if ca and ca > 0:
            cap = ca
            break
    if not cap:
        cap = bat_kwh

    # Energy from SoC difference × battery capacity (ca from InfluxDB)
    # kw_start/kw_end are only stored for charge-to-charge analysis
    energy = None
    consumption = None
    if soc_start and soc_end and soc_start > soc_end:
        energy = round((soc_start - soc_end) / 100 * cap, 2)
        if distance and distance >= 10:
            consumption = round(energy / distance * 100, 1)

    return {
        "device": device or config.INFLUX_DEVICE,
        "start_time": _local_iso(start_row["_time"]),
        "end_time": _local_iso(end_row["_time"]),
        "start_lat": gps_start.get("la"),
        "start_lon": gps_start.get("lo"),
        "end_lat": gps_end.get("la"),
        "end_lon": gps_end.get("lo"),
        "odo_start": round(od_start, 1) if od_start is not None else None,
        "odo_end": round(od_end, 1) if od_end is not None else None,
        "distance_km": round(distance, 1) if distance is not None else None,
        "soc_start": round(soc_start, 1) if soc_start is not None else None,
        "soc_end": round(soc_end, 1) if soc_end else None,
        "energy_kwh": round(energy, 2) if energy else None,
        "consumption": round(consumption, 1) if consumption else None,
        "kw_start": round(kw_start, 2) if kw_start is not None else None,
        "kw_end": round(kw_end, 2) if kw_end is not None else None,
    }


def detect_charges(rows, device=None):
    """Detects charging sessions from pivoted rows."""
    charges = []
    charging = False
    charge_start = None
    charge_points = []

    for row in rows:
        c = row.get("c", 0) or 0
        dc = row.get("dc", 0) or 0
        is_charging = c == 1 or dc == 1

        if not charging and is_charging:
            charging = True
            charge_start = row
            charge_points = [row]
        elif charging and is_charging:
            charge_points.append(row)
        elif charging and not is_charging:
            charge = build_charge(charge_start, row, charge_points, device=device)
            if charge:
                charges.append(charge)
            charging = False
            charge_points = []

    return charges


def build_charge(start_row, end_row, points, device=None):
    """Builds a charge dict."""
    soc_start = start_row.get("s")
    soc_end = end_row.get("s")

    charge_type = "dc" if any((pt.get("dc", 0) or 0) == 1 for pt in points) else "ac"

    max_power = 0.0
    energy = 0.0
    for pt in points:
        p = abs(pt.get("p", 0) or 0)
        if p > max_power:
            max_power = p
        energy += p * 60 / 3600

    return {
        "device": device or config.INFLUX_DEVICE,
        "start_time": _local_iso(start_row["_time"]),
        "end_time": _local_iso(end_row["_time"]),
        "lat": start_row.get("la"),
        "lon": start_row.get("lo"),
        "type": charge_type,
        "soc_start": round(soc_start, 1) if soc_start else None,
        "soc_end": round(soc_end, 1) if soc_end else None,
        "energy_kwh": round(energy, 2) if energy else None,
        "max_power_kw": round(max_power, 1),
    }


def match_location(db, lat, lon):
    """Finds the nearest saved location within its radius."""
    if not lat or not lon:
        return None
    locations = db.execute("SELECT * FROM locations").fetchall()
    best = None
    best_dist = float('inf')
    for loc in locations:
        dist = haversine_m(lat, lon, loc["lat"], loc["lon"])
        if dist <= loc["radius_m"] and dist < best_dist:
            best = loc
            best_dist = dist
    return best


def match_route_rule(db, start_loc, end_loc):
    """Finds a route rule for start and destination location.

    Matching priority:
    1. Exact rule (from + to)
    2. Wildcard rule (from=location, to=any OR from=any, to=location)
    """
    if not start_loc and not end_loc:
        return None
    start_id = start_loc["id"] if start_loc else None
    end_id = end_loc["id"] if end_loc else None

    # 1. Exact rule
    if start_id and end_id:
        row = db.execute(
            "SELECT * FROM route_rules WHERE from_location_id = ? AND to_location_id = ?",
            (start_id, end_id),
        ).fetchone()
        if row:
            return dict(row)

    # 2. Wildcard rules (NULL = any)
    row = db.execute(
        """SELECT * FROM route_rules
           WHERE (from_location_id = ? OR from_location_id IS NULL)
             AND (to_location_id = ? OR to_location_id IS NULL)
             AND (from_location_id IS NOT NULL OR to_location_id IS NOT NULL)
           ORDER BY
             (CASE WHEN from_location_id IS NOT NULL THEN 1 ELSE 0 END
              + CASE WHEN to_location_id IS NOT NULL THEN 1 ELSE 0 END) DESC
           LIMIT 1""",
        (start_id, end_id),
    ).fetchone()
    return dict(row) if row else None


def save_trips(db, trips):
    for t in trips:
        # Duplicate check: overlap with existing trip in same time window
        # (exact start_time match is not enough — timestamps may slightly differ)
        existing = db.execute(
            """SELECT id, end_time FROM trips WHERE device = ?
               AND datetime(start_time) < datetime(?)
               AND datetime(end_time)   > datetime(?)""",
            (t["device"], t["end_time"], t["start_time"]),
        ).fetchone()
        if existing:
            # Extend trip if new data goes beyond the previous end
            if t["end_time"] > existing["end_time"]:
                db.execute(
                    """UPDATE trips SET
                       end_time = :end_time, end_lat = :end_lat, end_lon = :end_lon,
                       odo_end = :odo_end, soc_end = :soc_end, energy_kwh = :energy_kwh,
                       consumption = :consumption, kw_end = :kw_end,
                       distance_km = :distance_km
                       WHERE id = :_id""",
                    {**t, "_id": existing["id"]},
                )
                log.info("Trip %d extended to %s", existing["id"], t["end_time"])
            else:
                log.debug("Trip overlaps with existing: %s %s", t["device"], t["start_time"])
            continue

        # Distance: odo_end of previous trip → odo_end of this trip
        # More accurate than odo_start→odo_end, since odo_start often arrives delayed
        if t.get("odo_end") is not None:
            prev = db.execute(
                """SELECT odo_end FROM trips WHERE device = ?
                   AND odo_end IS NOT NULL
                   AND datetime(end_time) < datetime(?)
                   ORDER BY end_time DESC LIMIT 1""",
                (t["device"], t["start_time"]),
            ).fetchone()
            if prev and prev["odo_end"] is not None:
                dist = t["odo_end"] - prev["odo_end"]
                if dist > 0:
                    t["distance_km"] = round(dist, 1)
                    # Recalculate consumption with corrected distance
                    if t.get("energy_kwh") and dist >= 10:
                        t["consumption"] = round(t["energy_kwh"] / dist * 100, 1)

        start_loc = match_location(db, t.get("start_lat"), t.get("start_lon"))
        end_loc = match_location(db, t.get("end_lat"), t.get("end_lon"))

        # Check route rule
        rule = match_route_rule(db, start_loc, end_loc)
        if rule:
            t["purpose"] = rule["purpose"]
            t["destination"] = rule.get("destination") or (end_loc["name"] if end_loc else "")
            t["visit_reason"] = rule.get("visit_reason") or ""
            log.info("Route rule: %s -> %s = %s",
                     start_loc["name"] if start_loc else "*",
                     end_loc["name"] if end_loc else "*",
                     rule["purpose"])
        elif end_loc:
            t["purpose"] = ""
            t["destination"] = end_loc["name"]
            t["visit_reason"] = end_loc["default_reason"] or "" if end_loc["default_reason"] else ""
        else:
            t.setdefault("purpose", "")
            t.setdefault("destination", "")
            t.setdefault("visit_reason", "")

        db.execute(
            """INSERT INTO trips
               (device, start_time, end_time, start_lat, start_lon, end_lat, end_lon,
                odo_start, odo_end, distance_km, soc_start, soc_end, energy_kwh, consumption,
                kw_start, kw_end, purpose, destination, visit_reason)
               VALUES (:device, :start_time, :end_time, :start_lat, :start_lon,
                       :end_lat, :end_lon, :odo_start, :odo_end,
                       :distance_km, :soc_start, :soc_end,
                       :energy_kwh, :consumption, :kw_start, :kw_end,
                       :purpose, :destination, :visit_reason)""",
            t,
        )
    db.commit()
    log.info("Saved: %d trips", len(trips))


def save_charges(db, charges):
    for c in charges:
        if db.execute(
            "SELECT id FROM charges WHERE device = ? AND start_time = ?",
            (c["device"], c["start_time"]),
        ).fetchone():
            continue
        db.execute(
            """INSERT INTO charges
               (device, start_time, end_time, lat, lon, type,
                soc_start, soc_end, energy_kwh, max_power_kw)
               VALUES (:device, :start_time, :end_time, :lat, :lon, :type,
                       :soc_start, :soc_end, :energy_kwh, :max_power_kw)""",
            c,
        )
    db.commit()
    log.info("Saved: %d charging sessions", len(charges))


def auto_categorize(db):
    """Automatically set uncategorized trips older than 7 days as private."""
    row = db.execute(
        "SELECT name FROM purpose_meta WHERE is_private = 1 ORDER BY sort_order LIMIT 1"
    ).fetchone()
    if not row:
        return
    priv_name = row["name"]
    result = db.execute(
        """UPDATE trips SET purpose = ?
           WHERE (purpose IS NULL OR purpose = '')
             AND start_time < datetime('now', '-7 days')""",
        (priv_name,),
    )
    if result.rowcount > 0:
        db.commit()
        log.info("Auto-categorized: %d trips as %s", result.rowcount, priv_name)


def cleanup_db(db):
    """Remove orphaned records and compact DB."""
    # Orphaned GPX waypoints (trip deleted)
    r1 = db.execute(
        "DELETE FROM gpx_waypoints WHERE trip_id NOT IN (SELECT id FROM trips)"
    )
    # Orphaned journey assignments
    r2 = db.execute(
        "DELETE FROM journey_trips WHERE trip_id NOT IN (SELECT id FROM trips)"
    )
    r3 = db.execute(
        "DELETE FROM journey_trips WHERE journey_id NOT IN (SELECT id FROM journeys)"
    )
    # Orphaned charge readings (session deleted)
    r4 = db.execute(
        "DELETE FROM charge_readings WHERE session_id IS NOT NULL "
        "AND session_id NOT IN (SELECT id FROM charge_sessions)"
    )
    total = r1.rowcount + r2.rowcount + r3.rowcount + r4.rowcount
    if total > 0:
        db.commit()
        db.execute("VACUUM")
        log.info("DB cleanup: %d orphaned records removed", total)


def downsample_influx(client):
    """Downsample data points older than 7 days to max 60s resolution."""
    delete_api = client.delete_api()
    query_api = client.query_api()

    # Find duplicates: points that are < 60s after the previous one, older than 7 days
    flux = f'''
        import "experimental"

        from(bucket: "{config.INFLUX_BUCKET}")
          |> range(start: -365d, stop: -7d)
          |> filter(fn: (r) => r._measurement == "v")
          |> filter(fn: (r) => r._field == "s")
          |> elapsed(unit: 1s)
          |> filter(fn: (r) => r.elapsed < 60 and r.elapsed > 0)
          |> count()
          |> yield(name: "count")
    '''
    try:
        tables = query_api.query(flux)
        count = 0
        for table in tables:
            for record in table.records:
                count = record.get_value()
        if count and count > 0:
            log.info("InfluxDB: %d data points with <60s interval found (older than 7d)", count)
    except Exception:
        log.debug("InfluxDB downsampling: query not possible (possibly missing permissions)")


def run_once():
    """Single run: detect new trips + charging sessions for all vehicles."""
    db = get_db()
    client = get_influx()

    # Determine all vehicles with device tag; fallback to config
    vehicle_rows = db.execute(
        "SELECT DISTINCT device FROM vehicles WHERE device IS NOT NULL AND device != ''"
    ).fetchall()
    devices = [r["device"] for r in vehicle_rows]
    if not devices:
        devices = [config.INFLUX_DEVICE]

    for device in devices:
        since = last_trip_end(db, device)
        log.info("Device %s: searching for new trips since %s", device, since.isoformat())

        rows = query_drive_data(client, since, device)
        if not rows:
            log.info("Device %s: no new data", device)
            continue

        rows = expand_rows(rows)

        bat_row = db.execute(
            "SELECT battery_capacity_kwh FROM vehicles WHERE device = ? AND battery_capacity_kwh IS NOT NULL",
            (device,)
        ).fetchone()
        if not bat_row:
            bat_row = db.execute("SELECT value FROM settings WHERE key = 'battery_capacity_kwh'").fetchone()
            bat_kwh = float(bat_row["value"]) if bat_row else 86.5
        else:
            bat_kwh = float(bat_row["battery_capacity_kwh"])

        trips = detect_trips(rows, bat_kwh, device=device)
        charges = detect_charges(rows, device=device)

        if trips:
            save_trips(db, trips)
        if charges:
            save_charges(db, charges)

    auto_categorize(db)
    cleanup_db(db)

    client.close()
    db.close()


def run_loop():
    """Infinite loop — search for new trips every SCAN_INTERVAL_MINUTES.
    First scan only after SCAN_INTERVAL_MINUTES (no scan at server start)."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    log.info("Triplog Detector started (interval: %d min, first scan in %d min)",
             config.SCAN_INTERVAL_MINUTES, config.SCAN_INTERVAL_MINUTES)

    while True:
        time.sleep(config.SCAN_INTERVAL_MINUTES * 60)
        try:
            run_once()
        except Exception:
            log.exception("Error in detector")


if __name__ == "__main__":
    run_loop()

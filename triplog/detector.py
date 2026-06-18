"""Trip detection — reads InfluxDB, detects trips + charging sessions, writes to SQLite."""

import time
import logging
import threading
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

# Serialize scans: four unsynchronized triggers (MQTT-silence timer, admin
# rescan, import job, 10-min loop) can run run_once() concurrently. save_trips/
# save_charges dedup is SELECT-then-INSERT, so two parallel scans over the same
# window both see "no overlap" and insert the same trip/charge twice. Only one
# scan may run at a time; a second trigger skips instead of duplicating.
_scan_lock = threading.Lock()


def _round_nonneg(v, ndigits):
    """Round v to ndigits, clamp negative to 0, pass None through unchanged.

    Replaces the `round(x, n) if x else None` falsy-pattern that silently
    converted real zeros (battery empty, regen exactly cancelling) to None.
    Rule: real measurement (incl. 0) → store as-is; <0 → 0; no measurement → None.
    """
    if v is None:
        return None
    if v < 0:
        return 0.0
    return round(v, ndigits)


def sanitize_soc(v):
    """Repair SoC values corrupted by firmware u16-underflow, then clamp to [0, 100].

    Bug: the telemetry stick packed SoC as `(uint16_t)(soc * 10)`. Negative BMS
    readings (the BMS occasionally reports -1..-5 % near empty) wrapped to
    65486..65535 raw → ~6548..6553 % after the server's /10 division.

    Recovery: any value > 110 % is treated as a wraparound — reinterpret the
    raw u16 as signed int16 to recover the original negative reading, then
    clamp to [0, 100] (sub-zero SoC is physically impossible; the BMS error
    is unknown so we conservatively clip to 0).

    Returns None for None / non-numeric input. Returns a float in [0, 100] otherwise.
    """
    if v is None:
        return None
    try:
        v = float(v)
    except (TypeError, ValueError):
        return None
    if math.isnan(v) or math.isinf(v):
        return None
    if v > 110.0:
        raw_u16 = int(round(v * 10.0)) & 0xFFFF
        signed = raw_u16 - 0x10000 if raw_u16 >= 0x8000 else raw_u16
        v = signed / 10.0
    if v < 0.0:
        return 0.0
    if v > 100.0:
        return 100.0
    return v


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
    """Open a DB connection. Delegates to app.get_db so that schema init,
    migrations and PRAGMAs live in exactly one place. Lazy-import avoids the
    circular load at module init (app imports detector before its own get_db
    is defined). At call time app is always fully loaded."""
    from app import get_db as _app_get_db
    return _app_get_db()


def get_influx(timeout_ms=None):
    """InfluxDB client. timeout_ms bounds each request (default ~10 s) — pass a
    short value for paths that must never hang (e.g. the charge rebuild's SoC
    refinement, which otherwise blocks the SQLite write lock 'forever' when
    Influx is slow/unreachable)."""
    if not config.INFLUX_TOKEN:
        return None
    kwargs = dict(url=config.INFLUX_URL, token=config.INFLUX_TOKEN, org=config.INFLUX_ORG)
    if timeout_ms is not None:
        kwargs["timeout"] = timeout_ms
    return InfluxDBClient(**kwargs)


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
      - Data gap >= config.DATA_GAP_MINUTES (5 min)
      - v == 0 for >= config.TRIP_STOP_MINUTES (5 min)
      - SoC jump >= 5% upward while avg speed < 1 km/h in between (charging)
    - Open trip: save if last point is older than config.DATA_GAP_MINUTES
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
    _v_sum_since_soc = 0.0     # speed samples since last SoC reading (avg-speed standstill check)
    _v_cnt_since_soc = 0
    _prev_lat = None
    _prev_lon = None

    for row in rows:
        t = row.get("_time")
        if t is None:
            continue

        v = row.get("v")
        soc = sanitize_soc(row.get("s"))
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

        # Accumulate speed samples since the last SoC reading, so the SoC jump
        # is judged against the AVERAGE speed in between (not a strict v==0).
        if v is not None:
            _v_sum_since_soc += v
            _v_cnt_since_soc += 1

        # Detect SoC jump: SoC rose >= config.SOC_JUMP_MIN while the car was, on average,
        # standing still (avg speed < config.SOC_JUMP_STILL_KMH) → charging happened, so
        # split the trip here. Average instead of strict v==0 because some sources
        # never report exactly 0 (GPS/sensor jitter, sparse TM speed) — otherwise
        # the trip runs straight through the charge and is never split.
        soc_jump = False
        if soc is not None and _last_soc is not None and soc - _last_soc >= config.SOC_JUMP_MIN:
            avg_v = (_v_sum_since_soc / _v_cnt_since_soc) if _v_cnt_since_soc else None
            if avg_v is not None and avg_v < config.SOC_JUMP_STILL_KMH:
                soc_jump = True
        if soc is not None:
            _last_soc = soc
            _v_sum_since_soc = 0.0
            _v_cnt_since_soc = 0

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

            if gap >= config.DATA_GAP_MINUTES:
                end_trip = True
            elif standstill_min >= config.TRIP_STOP_MINUTES:
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
        if age_min >= config.DATA_GAP_MINUTES:
            _save_trip(trips, trip_start, trip_points, bat_kwh, device)
        else:
            log.debug("Open trip still active (last point %.1f min ago), skipping", age_min)

    # Only return the last completed trip when it is definitely over:
    # Only when the last data point is >= config.DATA_GAP_MINUTES ago,
    # we can be sure no more data is coming.
    if trips and last_time is not None:
        age_min = (datetime.now(timezone.utc) - last_time).total_seconds() / 60
        if age_min < config.DATA_GAP_MINUTES:
            removed = trips.pop()
            log.debug("Last trip (%s) withheld — data still too fresh (%.1f min)",
                       removed.get("end_time"), age_min)

    return trips


def _filter_gps_jumps(points):
    """Filters GPS jumps: removes points with implied speed > config.GPS_MAX_KMH."""
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
        if dt_h > 0 and dist_m / 1000 / dt_h > config.GPS_MAX_KMH:
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
        s = sanitize_soc(pt.get("s"))
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

    # Battery capacity: from InfluxDB (ca field) if available, otherwise the
    # fallback. bat_kwh may be a float OR a callable(start_time)->float so the
    # caller can supply the rolling auto-estimate that applied at trip time.
    cap = None
    for pt in reversed(points):
        ca = pt.get("ca")
        if ca and ca > 0:
            cap = ca
            break
    if not cap:
        cap = bat_kwh(start_row.get("_time")) if callable(bat_kwh) else bat_kwh

    # Energy from SoC difference × battery capacity (ca from InfluxDB)
    # kw_start/kw_end are only stored for charge-to-charge analysis
    energy = None
    consumption = None
    if soc_start is not None and soc_end is not None and soc_start > soc_end:
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
        "soc_end": _round_nonneg(soc_end, 1),
        "energy_kwh": _round_nonneg(energy, 2),
        "consumption": _round_nonneg(consumption, 1),
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
    # Sanitize SoC at the source — raw start/end_row carry the u16-underflow
    # garbage from the firmware (negative BMS reading wraps to ~6553%). Without
    # this, every rebuild rewrites the bad value back into charge_sessions even
    # after the underflow-repair migration cleaned the table once.
    soc_start = sanitize_soc(start_row.get("s"))
    soc_end = sanitize_soc(end_row.get("s"))

    charge_type = "dc" if any((pt.get("dc", 0) or 0) == 1 for pt in points) else "ac"

    max_power = 0.0
    energy = 0.0
    # Integrate energy over the real time between samples instead of assuming a
    # fixed 60-s cadence: 10-s telegrams used to overstate kWh ~6×, 5-min gaps
    # understated it. Cap each interval at DATA_GAP_MINUTES so a telemetry gap
    # (no readings) does not inflate the integral. The first point has no prev_t
    # and therefore contributes nothing.
    gap_cap_h = config.DATA_GAP_MINUTES / 60.0
    prev_t = None
    for pt in points:
        p = abs(pt.get("p", 0) or 0)
        if p > max_power:
            max_power = p
        t = pt.get("_time")
        if prev_t is not None and t is not None:
            dt_h = (t - prev_t).total_seconds() / 3600
            if dt_h > gap_cap_h:
                dt_h = gap_cap_h
            if dt_h > 0:
                energy += p * dt_h
        if t is not None:
            prev_t = t

    return {
        "device": device or config.INFLUX_DEVICE,
        "start_time": _local_iso(start_row["_time"]),
        "end_time": _local_iso(end_row["_time"]),
        "lat": start_row.get("la"),
        "lon": start_row.get("lo"),
        "type": charge_type,
        "soc_start": _round_nonneg(soc_start, 1),
        "soc_end": _round_nonneg(soc_end, 1),
        "energy_kwh": _round_nonneg(energy, 2),
        "max_power_kw": round(max_power, 1),
    }


def match_location(db, lat, lon, locations=None):
    """Finds the nearest saved location within its radius.

    Pass `locations` (a pre-fetched list of location rows) to avoid one
    `SELECT * FROM locations` per call — used by save_trips, which matches up
    to 4× per trip in a loop. When None, the list is fetched from the DB.
    """
    if not lat or not lon:
        return None
    if locations is None:
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


MERGE_LOOKBACK_HOURS = 2  # only re-examine trips this recent (perf cap)


def save_trips(db, trips):
    # Load saved locations once — match_location() would otherwise re-query
    # them on every call (up to 4× per trip). save_trips never writes the
    # locations table, so the snapshot stays valid for the whole loop.
    locations = db.execute("SELECT * FROM locations").fetchall()
    for t in trips:
        # Duplicate check: overlap with existing trip in same time window
        # (exact start_time match is not enough — timestamps may slightly differ)
        existing = db.execute(
            """SELECT id, start_time, end_time, odo_start FROM trips WHERE device = ?
               AND datetime(start_time) < datetime(?)
               AND datetime(end_time)   > datetime(?)""",
            (t["device"], t["end_time"], t["start_time"]),
        ).fetchone()
        if existing:
            extended = False
            # Extend end if new data reaches further into the future
            if t["end_time"] > existing["end_time"]:
                # distance_km from t covers only t's own window. If the scan/import
                # window clipped the trip start, t's odo_start is later than the
                # existing trip's → writing t["distance_km"] would shrink the
                # stored distance below the real odo_end−odo_start span. Recompute
                # over the existing odo_start when both odometer values exist;
                # otherwise fall back to t's value (previous behaviour).
                end_dist = t.get("distance_km")
                end_cons = t.get("consumption")
                if t.get("odo_end") is not None and existing["odo_start"] is not None:
                    end_dist = round(t["odo_end"] - existing["odo_start"], 1)
                    energy = t.get("energy_kwh")
                    end_cons = (round(energy / end_dist * 100, 1)
                                if energy and end_dist and end_dist >= 10 else None)
                db.execute(
                    """UPDATE trips SET
                       end_time = :end_time, end_lat = :end_lat, end_lon = :end_lon,
                       odo_end = :odo_end, soc_end = :soc_end, energy_kwh = :energy_kwh,
                       consumption = :consumption, kw_end = :kw_end,
                       distance_km = :distance_km
                       WHERE id = :_id""",
                    {**t, "distance_km": end_dist, "consumption": end_cons,
                     "_id": existing["id"]},
                )
                log.info("Trip %d extended end to %s", existing["id"], t["end_time"])
                extended = True
            # Extend start if newly detected trip began earlier (reverse-day
            # import: the older day fills in the true start of an overnight trip).
            if t["start_time"] < existing["start_time"]:
                db.execute(
                    """UPDATE trips SET
                       start_time = :start_time, start_lat = :start_lat,
                       start_lon = :start_lon, odo_start = :odo_start,
                       soc_start = :soc_start, kw_start = :kw_start,
                       distance_km = :distance_km
                       WHERE id = :_id""",
                    {**t, "_id": existing["id"]},
                )
                log.info("Trip %d extended start to %s", existing["id"], t["start_time"])
                extended = True
            if not extended:
                log.debug("Trip overlaps with existing: %s %s", t["device"], t["start_time"])
            continue

        # Dead-zone merge: data dropouts (tunnel / dead-zone) make the detector
        # close one trip and open another a few minutes later. If the new trip
        # starts shortly after a recent trip ended, absorb it into that trip
        # instead of creating a duplicate. Bounded by MERGE_LOOKBACK_HOURS so
        # this never scans the whole history.
        cutoff = (datetime.now(LOCAL_TZ) - timedelta(hours=MERGE_LOOKBACK_HOURS)).strftime("%Y-%m-%dT%H:%M:%S")
        split = db.execute(
            """SELECT id, start_time, end_time, start_lat, start_lon,
                      odo_start, soc_start, energy_kwh, distance_km,
                      purpose, destination, visit_reason
               FROM trips WHERE device = ?
                 AND end_time < ?
                 AND end_time > ?
                 AND (julianday(?) - julianday(end_time)) * 1440 <= ?
               ORDER BY end_time DESC LIMIT 1""",
            (t["device"], t["start_time"], cutoff, t["start_time"], config.MERGE_GAP_MIN),
        ).fetchone()
        if split:
            # Distance: prefer odo delta (covers the data-gap km too); fall back to sum
            if t.get("odo_end") is not None and split["odo_start"] is not None:
                merged_dist = round(t["odo_end"] - split["odo_start"], 1)
            else:
                merged_dist = round((split["distance_km"] or 0) + (t.get("distance_km") or 0), 1)
            # Energy: sum what was actually recorded (energy during the gap is lost)
            e1, e2 = split["energy_kwh"], t.get("energy_kwh")
            merged_energy = round((e1 or 0) + (e2 or 0), 2) if (e1 is not None or e2 is not None) else None
            new_cons = round(merged_energy / merged_dist * 100, 1) if merged_energy and merged_dist and merged_dist >= 10 else None
            # Re-resolve destination/purpose for the new end location, but keep
            # whatever the user (or earlier auto-tagging) already wrote.
            end_loc = match_location(db, t.get("end_lat"), t.get("end_lon"), locations)
            start_loc = match_location(db, split["start_lat"], split["start_lon"], locations)
            rule = match_route_rule(db, start_loc, end_loc)
            if rule:
                auto_purp = rule["purpose"]
                auto_dest = rule.get("destination") or (end_loc["name"] if end_loc else "")
                auto_vr = rule.get("visit_reason") or ""
            elif end_loc:
                auto_purp = ""
                auto_dest = end_loc["name"]
                auto_vr = end_loc["default_reason"] or "" if end_loc["default_reason"] else ""
            else:
                auto_purp, auto_dest, auto_vr = "", "", ""
            purp = split["purpose"] or auto_purp
            dest = split["destination"] or auto_dest
            vr = split["visit_reason"] or auto_vr
            db.execute(
                """UPDATE trips SET
                   end_time = :end_time, end_lat = :end_lat, end_lon = :end_lon,
                   odo_end = :odo_end, soc_end = :soc_end, kw_end = :kw_end,
                   distance_km = :distance_km, energy_kwh = :energy_kwh,
                   consumption = :consumption,
                   destination = :destination, purpose = :purpose,
                   visit_reason = :visit_reason
                   WHERE id = :_id""",
                {**t, "distance_km": merged_dist,
                 "energy_kwh": merged_energy, "consumption": new_cons,
                 "destination": dest, "purpose": purp, "visit_reason": vr,
                 "_id": split["id"]},
            )
            log.info("Trip %d dead-zone-merged: gap-end %s, resumed %s",
                     split["id"], split["end_time"], t["start_time"])
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

        start_loc = match_location(db, t.get("start_lat"), t.get("start_lon"), locations)
        end_loc = match_location(db, t.get("end_lat"), t.get("end_lon"), locations)

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
        # Duplicate check: overlap with existing charge in same time window
        # (exact start_time match is not enough — a rescan window that clips a
        # charge yields a slightly different start_time → would insert a second
        # row. Mirror save_trips' overlap test instead.)
        if db.execute(
            """SELECT id FROM charges WHERE device = ?
               AND datetime(start_time) < datetime(?)
               AND datetime(end_time)   > datetime(?)""",
            (c["device"], c["end_time"], c["start_time"]),
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
    # Orphaned charge readings (session gone) — UNLINK, never delete. Readings
    # are user-paid energy data; losing them is a billing problem. Once unlinked
    # they surface in the readings editor's "unassigned" view so they can
    # be reassigned (and the next rebuild picks them up).
    r4 = db.execute(
        "UPDATE charge_readings SET session_id = NULL WHERE session_id IS NOT NULL "
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


def run_once(scope_from=None, scope_to=None):
    """Single run: detect new trips + charging sessions for all vehicles.

    When ``scope_from`` / ``scope_to`` (UTC datetimes) are given, the Influx
    query is restricted to that window — used by the TeslaMate import job
    to re-detect freshly imported days without scanning all history."""
    # Non-blocking: if another scan already holds the lock, skip this trigger
    # rather than queue up a redundant (and duplicate-prone) parallel scan.
    if not _scan_lock.acquire(blocking=False):
        log.info("scan already running, skipping")
        return
    try:
        db = get_db()
        client = get_influx()
        # get_influx() returns None when INFLUX_TOKEN is empty — without a client
        # query_drive_data()/client.close() would raise AttributeError every cycle
        # and skip db.close() (connection leak per run). Bail out cleanly here.
        if client is None:
            log.warning("Influx not configured (empty INFLUX_TOKEN) — skipping scan")
            db.close()
            return

        try:
            _run_scan(db, client, scope_from, scope_to)
        finally:
            # Always release both connections, even if scanning raised.
            try:
                client.close()
            finally:
                db.close()
    finally:
        _scan_lock.release()


def _run_scan(db, client, scope_from, scope_to):
    # Determine all vehicles with device tag; fallback to config
    vehicle_rows = db.execute(
        "SELECT DISTINCT device FROM vehicles WHERE device IS NOT NULL AND device != ''"
    ).fetchall()
    devices = [r["device"] for r in vehicle_rows]
    if not devices:
        devices = [config.INFLUX_DEVICE]

    for device in devices:
        since = scope_from if scope_from is not None else last_trip_end(db, device)
        log.info("Device %s: searching for new trips since %s%s",
                 device, since.isoformat(),
                 f" until {scope_to.isoformat()}" if scope_to else "")

        rows = query_drive_data(client, since, device, until=scope_to)
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
            anchor_kwh = float(bat_row["value"]) if bat_row else 86.5
        else:
            anchor_kwh = float(bat_row["battery_capacity_kwh"])

        # Rolling capacity per trip-time: prefer the auto-estimate that
        # applied around the trip's start, fall back to the manual anchor.
        def _cap_at(ts, _dev=device, _anchor=anchor_kwh):
            try:
                from app import get_bat_kwh
                iso = _local_iso(ts) if ts else None
                return get_bat_kwh(db, _dev, at_time=iso) or _anchor
            except Exception:
                return _anchor

        trips = detect_trips(rows, _cap_at, device=device)
        charges = detect_charges(rows, device=device)

        if trips:
            save_trips(db, trips)
        if charges:
            save_charges(db, charges)

    auto_categorize(db)
    cleanup_db(db)

    # Propagate freshly detected trips into recent charge sessions, so the
    # post-charge soc_end / odometer (the "charged to 80%" value) appears
    # without waiting for the next webhook reading or a manual rebuild. Scoped
    # to ~36h and bounded by the manual "settled until" freeze on the app side.
    try:
        from app import rebuild_charge_sessions
        since = (datetime.now(LOCAL_TZ) - timedelta(hours=36)).strftime("%Y-%m-%dT%H:%M:%S")
        rebuild_charge_sessions(db, since=since)
    except Exception:
        log.exception("post-scan charge rebuild failed")

    try:
        from app import detect_external_from_trips
        n = detect_external_from_trips(db)
        if n:
            log.info("detect_external: %d new external charge(s) created", n)
    except Exception:
        log.exception("post-scan external-charge detection failed")


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

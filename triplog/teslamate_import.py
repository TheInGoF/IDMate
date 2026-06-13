"""TeslaMate Postgres import — read-side helpers.

Pure data access, no Flask. Used by app.py admin endpoints under
``/api/admin/teslamate/*``. Feature is fully opt-in via
``TESLAMATE_PG_URL`` env var (see config.py).

Phase 1 scope: connect + info queries (cars, counts, date range).
Trip/charge mapping and import live in later phases.
"""
from __future__ import annotations

import logging
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import config

log = logging.getLogger("triplog.teslamate")

# Match IDMate's storage convention so duplicate detection works across both DBs.
_LOCAL_TZ = ZoneInfo("Europe/Berlin")


def _local_day_utc_bounds(date: str) -> tuple[datetime, datetime]:
    """Return the [start, stop) UTC-naive timestamps spanning the LOCAL
    (Europe/Berlin) day ``date`` (YYYY-MM-DD).

    TeslaMate's ``positions.date`` column is naive UTC, but IDMate's dedup
    (import_job._existing_timestamps_for_day) builds its sample window over the
    LOCAL day's UTC range. Filtering the TM read by a naive UTC calendar day
    instead would offset both windows by the UTC↔Berlin shift (1–2 h, DST-aware)
    → the ±20 s dedup list wouldn't cover the day's edge samples. Computing the
    bounds here from the local midnight keeps both sides aligned (DST-correct).

    Returned datetimes are tz-naive and expressed in UTC, ready to compare
    against the naive-UTC ``positions.date`` column.
    """
    start_local = datetime.fromisoformat(date + "T00:00:00").replace(tzinfo=_LOCAL_TZ)
    stop_local = start_local + timedelta(days=1)
    start_utc = start_local.astimezone(timezone.utc).replace(tzinfo=None)
    stop_utc = stop_local.astimezone(timezone.utc).replace(tzinfo=None)
    return start_utc, stop_utc


def is_configured() -> bool:
    """True when the TeslaMate ENV is set — gates UI and API registration."""
    return bool((config.TESLAMATE_PG_URL or "").strip())


@contextmanager
def _connect():
    """Yield a short-lived psycopg connection. Raises on configuration or
    network errors — callers translate to user-facing errors.
    """
    if not is_configured():
        raise RuntimeError("TESLAMATE_PG_URL not set")
    # Lazy import so missing psycopg doesn't break the rest of the app
    import psycopg
    conn = psycopg.connect(config.TESLAMATE_PG_URL, connect_timeout=5)
    try:
        yield conn
    finally:
        conn.close()


def sample_positions_for_day(car_id: int, date: str,
                              per_side: int = 25) -> list[dict]:
    """Return first N + last N positions of (car_id, date) for spot-check.

    Always sorted ascending by time. Datetimes are local Europe/Berlin
    naive strings (matches what IDMate's side uses).
    """
    # Local (Europe/Berlin) day bounds, expressed in UTC to match the naive-UTC
    # positions.date column and IDMate's local-day dedup window. Upper bound is
    # exclusive (next local midnight).
    day_from, day_to = _local_day_utc_bounds(date)
    sql_first = """
        SELECT date, latitude, longitude, battery_level, speed, power, odometer,
               outside_temp
        FROM positions
        WHERE car_id = %s AND date >= %s AND date < %s
        ORDER BY date ASC LIMIT %s
    """
    sql_last = """
        SELECT * FROM (
            SELECT date, latitude, longitude, battery_level, speed, power, odometer,
                   outside_temp
            FROM positions
            WHERE car_id = %s AND date >= %s AND date < %s
            ORDER BY date DESC LIMIT %s
        ) sub ORDER BY date ASC
    """
    out = []
    with _connect() as conn:
        with conn.cursor() as cur:
            cur.execute(sql_first, (car_id, day_from, day_to, per_side))
            first = cur.fetchall()
            cur.execute(sql_last, (car_id, day_from, day_to, per_side))
            last = cur.fetchall()
            cols = [c.name for c in cur.description]
            # De-dup by timestamp in case the day has fewer rows than 2*per_side
            seen = set()
            for r in list(first) + list(last):
                row = dict(zip(cols, r))
                ts = row["date"]
                if ts in seen:
                    continue
                seen.add(ts)
                # Convert naive UTC → Europe/Berlin local naive
                if getattr(ts, "tzinfo", None) is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                ts = ts.astimezone(_LOCAL_TZ).replace(tzinfo=None)
                row["date"] = ts.isoformat(sep=" ", timespec="seconds")
                for k in ("latitude", "longitude", "speed", "power", "odometer", "outside_temp"):
                    if row.get(k) is not None:
                        row[k] = float(row[k])
                out.append(row)
    out.sort(key=lambda r: r["date"])
    return out


_TM_RANGES = {
    "latitude":      (30.0, 72.0),
    "longitude":     (-30.0, 45.0),
    "battery_level": (0, 100),
    "speed":         (0, 300),
    "power":         (-600.0, 600.0),
    "odometer":      (0, 9_999_999),
    "outside_temp":  (-50.0, 60.0),
}


def _plausible(row: dict) -> bool:
    """Reject rows that violate the plausibility ranges. lat/lon are mandatory;
    all other fields are optional but, when present, must be in range."""
    for k in ("latitude", "longitude"):
        v = row.get(k)
        if v is None:
            return False
        lo, hi = _TM_RANGES[k]
        if not (lo <= float(v) <= hi):
            return False
    for k, (lo, hi) in _TM_RANGES.items():
        if k in ("latitude", "longitude"):
            continue
        v = row.get(k)
        if v is None:
            continue
        try:
            v = float(v)
        except (TypeError, ValueError):
            return False
        if not (lo <= v <= hi):
            return False
    return True


def fetch_positions_day_filtered(car_id: int, date: str,
                                  density_seconds: int = 20) -> list[dict]:
    """Read all TM positions for (car_id, date), then keep at most one
    sample per ``density_seconds`` window and drop implausible rows.

    Output: list of dicts sorted ascending by ``ts_utc`` (UTC unix seconds),
    fields: ts_utc, ts_local (Europe/Berlin naive ISO), latitude, longitude,
    battery_level, speed, power, odometer, outside_temp.
    """
    # Local (Europe/Berlin) day bounds, expressed in UTC to match the naive-UTC
    # positions.date column and IDMate's local-day dedup window. Upper bound is
    # exclusive (next local midnight).
    day_from, day_to = _local_day_utc_bounds(date)
    sql = """
        SELECT date, latitude, longitude, battery_level, speed, power, odometer,
               outside_temp
        FROM positions
        WHERE car_id = %s AND date >= %s AND date < %s
        ORDER BY date ASC
    """
    out: list[dict] = []
    last_ts = None
    with _connect() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, (car_id, day_from, day_to))
            cols = [c.name for c in cur.description]
            for r in cur.fetchall():
                row = dict(zip(cols, r))
                ts = row["date"]
                if getattr(ts, "tzinfo", None) is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                ts_utc = ts.timestamp()
                if last_ts is not None and (ts_utc - last_ts) < density_seconds:
                    continue
                if not _plausible(row):
                    continue
                local = ts.astimezone(_LOCAL_TZ).replace(tzinfo=None)
                out.append({
                    "ts_utc": ts_utc,
                    "ts_local": local.isoformat(sep=" ", timespec="seconds"),
                    "latitude": float(row["latitude"]),
                    "longitude": float(row["longitude"]),
                    "battery_level": int(row["battery_level"]) if row.get("battery_level") is not None else None,
                    "speed": int(round(float(row["speed"]))) if row.get("speed") is not None else None,
                    "power": float(row["power"]) if row.get("power") is not None else None,
                    "odometer": float(row["odometer"]) if row.get("odometer") is not None else None,
                    "outside_temp": float(row["outside_temp"]) if row.get("outside_temp") is not None else None,
                })
                last_ts = ts_utc
    return out


def count_positions_per_day(car_ids: list, date_from: str = "",
                             date_to: str = "") -> list[dict]:
    """Per-day position counts from TeslaMate, scoped to mapped cars.

    Returns: [{date: 'YYYY-MM-DD', car_id, count}, ...] — sorted ascending.
    """
    if not car_ids:
        return []
    sql = """
        SELECT date_trunc('day', date)::date AS day,
               car_id,
               COUNT(*) AS n
        FROM positions
        WHERE car_id = ANY(%s)
    """
    params: list = [list(car_ids)]
    if date_from:
        sql += " AND date >= %s"
        params.append(date_from + " 00:00:00")
    if date_to:
        sql += " AND date <= %s"
        params.append(date_to + " 23:59:59")
    sql += " GROUP BY day, car_id ORDER BY day ASC"
    with _connect() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return [{"date": r[0].isoformat(), "car_id": int(r[1]), "count": int(r[2])}
                    for r in cur.fetchall()]


def count_charges_per_day(car_ids: list, date_from: str = "",
                           date_to: str = "") -> list[dict]:
    """Per-day count of completed charging_processes per car."""
    if not car_ids:
        return []
    sql = """
        SELECT date_trunc('day', start_date)::date AS day,
               car_id,
               COUNT(*) AS n
        FROM charging_processes
        WHERE car_id = ANY(%s) AND end_date IS NOT NULL
    """
    params: list = [list(car_ids)]
    if date_from:
        sql += " AND start_date >= %s"
        params.append(date_from + " 00:00:00")
    if date_to:
        sql += " AND start_date <= %s"
        params.append(date_to + " 23:59:59")
    sql += " GROUP BY day, car_id ORDER BY day ASC"
    with _connect() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            return [{"date": r[0].isoformat(), "car_id": int(r[1]), "count": int(r[2])}
                    for r in cur.fetchall()]


def fetch_charges_list(car_id: int, date_from: str = "",
                        date_to: str = "") -> list[dict]:
    """Return all completed charging_processes for car_id in the date range,
    joined with start-position (lat/lon/odometer) and address (location name)
    and aggregated charger_power from ``charges`` for kw_avg / kw_max.

    Times are returned as naive Europe/Berlin ISO strings — matches IDMate's
    charge_sessions storage format so duplicate detection is straightforward.
    """
    sql = """
        SELECT cp.id, cp.car_id,
               cp.start_date, cp.end_date,
               cp.duration_min,
               cp.start_battery_level, cp.end_battery_level,
               cp.charge_energy_added, cp.charge_energy_used,
               cp.cost,
               p.latitude, p.longitude, p.odometer,
               a.display_name,
               (SELECT AVG(charger_power) FROM charges c
                  WHERE c.charging_process_id = cp.id AND c.charger_power > 0) AS kw_avg,
               (SELECT MAX(charger_power) FROM charges c
                  WHERE c.charging_process_id = cp.id) AS kw_max
        FROM charging_processes cp
        LEFT JOIN positions p ON p.id = cp.position_id
        LEFT JOIN addresses a ON a.id = cp.address_id
        WHERE cp.car_id = %s AND cp.end_date IS NOT NULL
    """
    params: list = [car_id]
    if date_from:
        sql += " AND cp.start_date >= %s"
        params.append(date_from + " 00:00:00")
    if date_to:
        sql += " AND cp.start_date <= %s"
        params.append(date_to + " 23:59:59")
    sql += " ORDER BY cp.start_date ASC"

    def _to_local(ts):
        if ts is None:
            return None
        if getattr(ts, "tzinfo", None) is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts.astimezone(_LOCAL_TZ).replace(tzinfo=None).isoformat(
            sep="T", timespec="seconds")

    out = []
    with _connect() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            for r in cur.fetchall():
                (cp_id, car, sd, ed, dur, sb, eb, kwh, kwh_used, cost,
                 lat, lon, odo, addr, kw_avg, kw_max) = r
                out.append({
                    "tm_id": int(cp_id),
                    "car_id": int(car),
                    "start_time": _to_local(sd),
                    "end_time": _to_local(ed),
                    "duration_minutes": int(dur) if dur is not None else None,
                    "soc_start": int(sb) if sb is not None else None,
                    "soc_end": int(eb) if eb is not None else None,
                    "total_kwh": float(kwh) if kwh is not None else None,
                    "energy_used_kwh": float(kwh_used) if kwh_used is not None else None,
                    "cost_total": float(cost) if cost is not None else None,
                    "lat": float(lat) if lat is not None else None,
                    "lon": float(lon) if lon is not None else None,
                    "odometer": float(odo) if odo is not None else None,
                    "location_name": addr,
                    "avg_kw": float(kw_avg) if kw_avg is not None else None,
                    "max_kw": float(kw_max) if kw_max is not None else None,
                })
    return out


def fetch_info() -> dict:
    """Return connection metadata + counts for the dashboard.

    Shape:
        {
          "ok": bool, "error": str | None,
          "pg_version": str,                       # e.g. "PostgreSQL 15.4"
          "cars": [{id, name, vin, efficiency, model}],
          "drives_total": int,
          "charges_total": int,
          "first_date": "YYYY-MM-DD" | None,
          "last_date":  "YYYY-MM-DD" | None,
        }
    """
    out = {
        "ok": False, "error": None, "pg_version": None, "cars": [],
        "drives_total": 0, "charges_total": 0,
        "first_date": None, "last_date": None,
    }
    try:
        with _connect() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT version()")
                out["pg_version"] = (cur.fetchone() or [""])[0].split(" on ")[0]

                cur.execute(
                    "SELECT id, name, vin, efficiency, model "
                    "FROM cars ORDER BY id"
                )
                out["cars"] = [
                    {"id": r[0], "name": r[1], "vin": r[2],
                     "efficiency": float(r[3]) if r[3] is not None else None,
                     "model": r[4]}
                    for r in cur.fetchall()
                ]

                cur.execute("SELECT COUNT(*) FROM drives")
                out["drives_total"] = int((cur.fetchone() or [0])[0])

                cur.execute("SELECT COUNT(*) FROM charging_processes")
                out["charges_total"] = int((cur.fetchone() or [0])[0])

                cur.execute(
                    "SELECT MIN(start_date)::date, MAX(end_date)::date FROM drives"
                )
                row = cur.fetchone() or (None, None)
                out["first_date"] = row[0].isoformat() if row[0] else None
                out["last_date"] = row[1].isoformat() if row[1] else None
        out["ok"] = True
    except Exception as e:
        log.warning("TeslaMate info failed: %s", e)
        out["error"] = str(e)
    return out

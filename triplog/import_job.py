"""TeslaMate → InfluxDB background import job.

Phase 3b: walks day-by-day in reverse (newest first), pulls TM positions
with 20s density filter, deduplicates ±20s against existing InfluxDB
samples for the same device, and writes plausible rows as Influx points
matching IDMate's schema (la/lo/s/v/p/od).

State is kept in the sqlite ``settings`` table so progress survives restarts;
after restart the status is forced to 'paused' so nothing runs without
explicit user action.

Single-process / single-job: only one job at a time, guarded by a lock.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from datetime import date as date_cls, datetime, timedelta, timezone
from typing import Optional

import config
import detector
import geocoder as geo
import teslamate_import as tm

log = logging.getLogger("triplog.import_job")

# settings table keys
_STATE_KEY = "tm_import_state"
_STATE_KEY_CHG = "tm_charges_import_state"

# state values
S_IDLE = "idle"
S_RUNNING = "running"
S_PAUSED = "paused"
S_ERROR = "error"
S_DONE = "done"

_lock = threading.Lock()
_thread: Optional[threading.Thread] = None
_stop_flag = threading.Event()

_lock_chg = threading.Lock()
_thread_chg: Optional[threading.Thread] = None
_stop_flag_chg = threading.Event()


def _get_db():
    db = sqlite3.connect(config.DB_PATH, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    return db


def _read_state(key: str = _STATE_KEY) -> dict:
    db = _get_db()
    row = db.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    db.close()
    if not row or not row["value"]:
        return {"status": S_IDLE}
    try:
        return json.loads(row["value"])
    except Exception:
        return {"status": S_IDLE}


def _write_state(state: dict, key: str = _STATE_KEY) -> None:
    state["updated"] = time.time()
    db = _get_db()
    db.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, json.dumps(state)),
    )
    db.commit()
    db.close()


def _update_state(key: str = _STATE_KEY, **kwargs) -> dict:
    state = _read_state(key)
    state.update(kwargs)
    _write_state(state, key)
    return state


def get_status() -> dict:
    """Return current state — augmented with derived progress info."""
    s = _read_state()
    total = int(s.get("total_days", 0) or 0)
    done = int(s.get("done_days", 0) or 0)
    s["progress_pct"] = round(done * 100.0 / total, 1) if total else 0.0
    return s


def reset_on_boot():
    """Called once at app startup. If a previous run was 'running',
    force it to 'paused' so we never silently resume."""
    for key, label in ((_STATE_KEY, "positions"), (_STATE_KEY_CHG, "charges")):
        s = _read_state(key)
        if s.get("status") == S_RUNNING:
            s["status"] = S_PAUSED
            s["pause_reason"] = "restart"
            _write_state(s, key)
            log.info("Import job (%s) set to paused after restart", label)


# ── InfluxDB write helper ───────────────────────────────────────

_influx_client = None
_influx_write = None


def _influx():
    global _influx_client, _influx_write
    if _influx_write is None:
        from influxdb_client import InfluxDBClient
        from influxdb_client.client.write_api import SYNCHRONOUS
        _influx_client = InfluxDBClient(
            url=config.INFLUX_URL, token=config.INFLUX_TOKEN, org=config.INFLUX_ORG
        )
        _influx_write = _influx_client.write_api(write_options=SYNCHRONOUS)
    return _influx_write


def _existing_timestamps_for_day(device: str, day_local: str) -> list[float]:
    """Return UTC unix-second list of existing 'la' samples for the device
    on the given local day. Used to skip TM samples within ±20s of an
    existing sample."""
    from influxdb_client import InfluxDBClient
    # Convert local day to UTC range (Europe/Berlin → UTC)
    from zoneinfo import ZoneInfo
    tz = ZoneInfo("Europe/Berlin")
    start_local = datetime.fromisoformat(day_local + "T00:00:00").replace(tzinfo=tz)
    stop_local = start_local + timedelta(days=1)
    start_iso = start_local.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    stop_iso = stop_local.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    flux = (
        f'from(bucket: "{config.INFLUX_BUCKET}")\n'
        f'  |> range(start: {start_iso}, stop: {stop_iso})\n'
        f'  |> filter(fn: (r) => r._measurement == "v" and r.d == "{device}" '
        f'and r._field == "la")\n'
        f'  |> keep(columns: ["_time"])\n'
        f'  |> sort(columns: ["_time"])\n'
    )
    client = InfluxDBClient(
        url=config.INFLUX_URL, token=config.INFLUX_TOKEN, org=config.INFLUX_ORG
    )
    try:
        tables = client.query_api().query(flux)
        out = []
        for table in tables:
            for record in table.records:
                t = record.get_time()
                out.append(t.timestamp())
        return out
    finally:
        client.close()


def _write_day_to_influx(device: str, points: list[dict]) -> int:
    """Write the filtered points as InfluxDB Points. Returns count written."""
    if not points:
        return 0
    from influxdb_client import Point, WritePrecision
    batch = []
    for p in points:
        pt = Point("v").tag("d", device)
        # Field types MUST match the MQTT bridge/replay (app.py) exactly,
        # otherwise we get a 422 field-type-conflict and the whole day is
        # discarded. Single source of truth: config.influx_field_value /
        # config.INFLUX_INT_FIELDS — never cast by hand here.
        pt.field("la", config.influx_field_value("la", p["latitude"]))
        pt.field("lo", config.influx_field_value("lo", p["longitude"]))
        if p.get("battery_level") is not None:
            pt.field("s", config.influx_field_value("s", p["battery_level"]))
        if p.get("speed") is not None:
            pt.field("v", config.influx_field_value("v", p["speed"]))
        if p.get("power") is not None:
            pt.field("p", config.influx_field_value("p", p["power"]))
        if p.get("odometer") is not None:
            pt.field("od", config.influx_field_value("od", p["odometer"]))
        if p.get("outside_temp") is not None:
            pt.field("et", config.influx_field_value("et", p["outside_temp"]))
        pt.time(int(p["ts_utc"] * 1_000_000_000), WritePrecision.NS)
        batch.append(pt)
    writer = _influx()
    writer.write(bucket=config.INFLUX_BUCKET, record=batch)
    return len(batch)


# ── Job control ─────────────────────────────────────────────────


def start(car_id: int, date_from: str, date_to: str, device: str) -> dict:
    """Initialize a new job and start the worker thread."""
    with _lock:
        cur = _read_state()
        if cur.get("status") == S_RUNNING:
            return {"ok": False, "error": "Job already running"}

        try:
            d_from = date_cls.fromisoformat(date_from)
            d_to = date_cls.fromisoformat(date_to)
        except ValueError:
            return {"ok": False, "error": "Invalid date format"}
        if d_to < d_from:
            return {"ok": False, "error": "date_to before date_from"}

        total = (d_to - d_from).days + 1
        state = {
            "status": S_RUNNING,
            "car_id": int(car_id),
            "device": device,
            "date_from": d_from.isoformat(),
            "date_to": d_to.isoformat(),
            "cursor": d_to.isoformat(),     # newest first → start at date_to
            "total_days": total,
            "done_days": 0,
            "written_points": 0,
            "skipped_density": 0,
            "skipped_existing": 0,
            "implausible": 0,
            "last_day": None,
            "error": None,
            "started": time.time(),
        }
        _write_state(state)
        _spawn_worker()
        return {"ok": True, "state": state}


def pause() -> dict:
    with _lock:
        s = _read_state()
        if s.get("status") != S_RUNNING:
            return {"ok": False, "error": "Job not running"}
        _stop_flag.set()
        _update_state(status=S_PAUSED, pause_reason="user")
        return {"ok": True}


def resume() -> dict:
    with _lock:
        s = _read_state()
        if s.get("status") not in (S_PAUSED, S_ERROR):
            return {"ok": False, "error": "Job not paused"}
        _update_state(status=S_RUNNING, pause_reason=None, error=None)
        _spawn_worker()
        return {"ok": True}


def stop() -> dict:
    with _lock:
        _stop_flag.set()
        _update_state(status=S_IDLE)
        return {"ok": True}


def _spawn_worker():
    global _thread
    _stop_flag.clear()
    if _thread and _thread.is_alive():
        return
    _thread = threading.Thread(target=_run, daemon=True, name="tm-import")
    _thread.start()


# ── Worker ──────────────────────────────────────────────────────


def _run():
    """Main loop. Processes one day per iteration, newest first.
    Each day:
      1. Read TM positions with 20s density filter + plausibility
      2. Get existing InfluxDB sample timestamps for the same day
      3. Drop TM samples within ±20s of any existing
      4. Write remaining points to InfluxDB
      5. Update state + extend geocoder backfill window
    """
    log.info("Import worker started")
    try:
        while not _stop_flag.is_set():
            s = _read_state()
            if s.get("status") != S_RUNNING:
                break

            cursor = s.get("cursor")
            d_from = s.get("date_from")
            if not cursor or not d_from:
                _update_state(status=S_ERROR, error="missing cursor or date_from")
                break

            cur_d = date_cls.fromisoformat(cursor)
            from_d = date_cls.fromisoformat(d_from)
            if cur_d < from_d:
                _update_state(status=S_DONE)
                log.info("Import job done")
                break

            car_id = int(s.get("car_id"))
            device = s.get("device") or config.INFLUX_DEVICE
            day_str = cur_d.isoformat()

            try:
                tm_points = tm.fetch_positions_day_filtered(car_id, day_str)
            except Exception as e:
                log.exception("TM read failed for %s", day_str)
                _update_state(status=S_ERROR, error=f"TM read {day_str}: {e}")
                break

            try:
                existing = _existing_timestamps_for_day(device, day_str)
            except Exception as e:
                log.exception("Influx query failed for %s", day_str)
                _update_state(status=S_ERROR, error=f"Influx query {day_str}: {e}")
                break

            # ±20s dedup
            existing.sort()
            kept = []
            skipped_existing = 0
            i = 0
            for p in tm_points:
                t = p["ts_utc"]
                # advance i so existing[i] is the first >= t-20
                while i < len(existing) and existing[i] < t - 20:
                    i += 1
                clash = False
                j = i
                while j < len(existing) and existing[j] <= t + 20:
                    clash = True
                    break
                if clash:
                    skipped_existing += 1
                else:
                    kept.append(p)

            try:
                written = _write_day_to_influx(device, kept)
            except Exception as e:
                log.exception("Influx write failed for %s", day_str)
                _update_state(status=S_ERROR, error=f"Influx write {day_str}: {e}")
                break

            # success → advance state
            new_state = _read_state()
            new_state["written_points"] = int(new_state.get("written_points", 0)) + written
            new_state["skipped_existing"] = int(new_state.get("skipped_existing", 0)) + skipped_existing
            new_state["done_days"] = int(new_state.get("done_days", 0)) + 1
            new_state["last_day"] = day_str
            new_state["last_day_written"] = written
            new_state["last_day_skipped"] = skipped_existing
            new_state["cursor"] = (cur_d - timedelta(days=1)).isoformat()
            _write_state(new_state)

            log.info("Imported %s: %d written, %d skipped",
                     day_str, written, skipped_existing)
            geo.extend_backfill_window()

            # Scoped detector run for the freshly imported day. Buffer ±1h so
            # midnight-spanning trips are seen as a whole; bidirectional merge
            # in save_trips fixes earlier-start overlaps.
            try:
                from zoneinfo import ZoneInfo
                tz = ZoneInfo("Europe/Berlin")
                day_start_local = datetime.fromisoformat(day_str + "T00:00:00").replace(tzinfo=tz)
                scope_from = (day_start_local - timedelta(hours=1)).astimezone(timezone.utc)
                scope_to = (day_start_local + timedelta(days=1, hours=1)).astimezone(timezone.utc)
                detector.run_once(scope_from=scope_from, scope_to=scope_to)
            except Exception:
                log.exception("Scoped detector run failed for %s", day_str)

            # tiny breather so the UI poll has time to read state
            for _ in range(10):
                if _stop_flag.is_set():
                    break
                time.sleep(0.1)

        # Final sweep — only when the job ran to completion (cursor < from)
        s = _read_state()
        if s.get("status") == S_DONE:
            try:
                from zoneinfo import ZoneInfo
                tz = ZoneInfo("Europe/Berlin")
                d_from = datetime.fromisoformat(s["date_from"] + "T00:00:00").replace(tzinfo=tz)
                d_to = datetime.fromisoformat(s["date_to"] + "T00:00:00").replace(tzinfo=tz)
                scope_from = (d_from - timedelta(hours=12)).astimezone(timezone.utc)
                scope_to = (d_to + timedelta(days=1, hours=12)).astimezone(timezone.utc)
                detector.run_once(scope_from=scope_from, scope_to=scope_to)
                log.info("Final-sweep detector run done for %s..%s",
                         s["date_from"], s["date_to"])
            except Exception:
                log.exception("Final-sweep detector run failed")
    except Exception as e:
        log.exception("Import worker crashed")
        _update_state(status=S_ERROR, error=f"crash: {e}")
    finally:
        log.info("Import worker exited")


# ── Charges-Import (Phase 3d) ───────────────────────────────────


def get_charges_status() -> dict:
    s = _read_state(_STATE_KEY_CHG)
    total = int(s.get("total_sessions", 0) or 0)
    done = int(s.get("processed", 0) or 0)
    s["progress_pct"] = round(done * 100.0 / total, 1) if total else 0.0
    return s


def _find_duplicate_charge(db, plate: str, start_time: str) -> Optional[int]:
    """Match a TM session against existing IDMate charge_sessions via
    plate + start_time ±15min. Returns the existing id when found."""
    if not plate or not start_time:
        return None
    # ±15min window — TM and IDMate detect charge start at different moments
    # (TM logs the API event, IDMate detects via polling), so the start times
    # can drift well beyond a few minutes.
    row = db.execute(
        """SELECT id FROM charge_sessions
           WHERE vehicle_plate = ?
             AND ABS(strftime('%s', start_time) - strftime('%s', ?)) <= 900
           LIMIT 1""",
        (plate, start_time),
    ).fetchone()
    return row["id"] if row else None


def _insert_external_charge(db, plate: str, tm: dict) -> None:
    """Insert a TM charging_process as an external IDMate charge_session."""
    db.execute(
        """INSERT INTO charge_sessions (
              session_number, is_external, vehicle_plate,
              start_time, end_time, total_kwh, duration_minutes, avg_kw,
              odometer, cost_total, lat, lon, location_name,
              soc_start, soc_end, note
           ) VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            f"TM-{tm['tm_id']}",
            plate,
            tm.get("start_time"),
            tm.get("end_time"),
            tm.get("total_kwh"),
            tm.get("duration_minutes"),
            tm.get("avg_kw"),
            tm.get("odometer"),
            tm.get("cost_total"),
            tm.get("lat"),
            tm.get("lon"),
            tm.get("location_name"),
            tm.get("soc_start"),
            tm.get("soc_end"),
            f"TeslaMate import (kwh_used={tm.get('energy_used_kwh')}, kw_max={tm.get('max_kw')})",
        ),
    )


def start_charges(car_id: int, date_from: str, date_to: str, plate: str) -> dict:
    """Initialize the charges-import job and spawn the worker."""
    with _lock_chg:
        cur = _read_state(_STATE_KEY_CHG)
        if cur.get("status") == S_RUNNING:
            return {"ok": False, "error": "Charge job already running"}
        try:
            d_from = date_cls.fromisoformat(date_from)
            d_to = date_cls.fromisoformat(date_to)
        except ValueError:
            return {"ok": False, "error": "Invalid date format"}
        if d_to < d_from:
            return {"ok": False, "error": "date_to before date_from"}
        if not plate:
            return {"ok": False, "error": "plate required"}

        state = {
            "status": S_RUNNING,
            "car_id": int(car_id),
            "plate": plate,
            "date_from": d_from.isoformat(),
            "date_to": d_to.isoformat(),
            "total_sessions": 0,
            "processed": 0,
            "imported": 0,
            "skipped_duplicate": 0,
            "skipped_incomplete": 0,
            "last_session": None,
            "error": None,
            "started": time.time(),
        }
        _write_state(state, _STATE_KEY_CHG)
        _spawn_charges_worker()
        return {"ok": True, "state": state}


def pause_charges() -> dict:
    with _lock_chg:
        s = _read_state(_STATE_KEY_CHG)
        if s.get("status") != S_RUNNING:
            return {"ok": False, "error": "Job not running"}
        _stop_flag_chg.set()
        _update_state(_STATE_KEY_CHG, status=S_PAUSED, pause_reason="user")
        return {"ok": True}


def resume_charges() -> dict:
    with _lock_chg:
        s = _read_state(_STATE_KEY_CHG)
        if s.get("status") not in (S_PAUSED, S_ERROR):
            return {"ok": False, "error": "Job not paused"}
        _update_state(_STATE_KEY_CHG, status=S_RUNNING, pause_reason=None, error=None)
        _spawn_charges_worker()
        return {"ok": True}


def stop_charges() -> dict:
    with _lock_chg:
        _stop_flag_chg.set()
        _update_state(_STATE_KEY_CHG, status=S_IDLE)
        return {"ok": True}


def _spawn_charges_worker():
    global _thread_chg
    _stop_flag_chg.clear()
    if _thread_chg and _thread_chg.is_alive():
        return
    _thread_chg = threading.Thread(target=_run_charges, daemon=True, name="tm-charges")
    _thread_chg.start()


def _run_charges():
    """Worker for the charges import. One DB roundtrip pulls every relevant
    TM session, then we walk through them with a per-iteration pause flag so
    the UI stays responsive even for large date ranges."""
    log.info("Charges worker started")
    try:
        s = _read_state(_STATE_KEY_CHG)
        if s.get("status") != S_RUNNING:
            return

        car_id = int(s["car_id"])
        plate = s["plate"]
        date_from = s["date_from"]
        date_to = s["date_to"]

        try:
            tm_list = tm.fetch_charges_list(car_id, date_from, date_to)
        except Exception as e:
            log.exception("TM charges fetch failed")
            _update_state(_STATE_KEY_CHG, status=S_ERROR, error=f"TM fetch: {e}")
            return

        _update_state(_STATE_KEY_CHG, total_sessions=len(tm_list))
        if not tm_list:
            _update_state(_STATE_KEY_CHG, status=S_DONE)
            return

        db = _get_db()
        try:
            for idx, item in enumerate(tm_list, start=1):
                if _stop_flag_chg.is_set():
                    break
                # Reject sessions without meaningful payload — we never store
                # zero-energy / no-soc rows; otherwise the log fills with junk.
                if (item.get("total_kwh") in (None, 0)
                        and item.get("duration_minutes") in (None, 0)):
                    _update_state(_STATE_KEY_CHG,
                                  processed=idx,
                                  skipped_incomplete=int(
                                      _read_state(_STATE_KEY_CHG).get("skipped_incomplete", 0)) + 1,
                                  last_session=item.get("start_time"))
                    continue
                try:
                    dup_id = _find_duplicate_charge(db, plate, item.get("start_time"))
                    if dup_id:
                        cur = _read_state(_STATE_KEY_CHG)
                        cur["processed"] = idx
                        cur["skipped_duplicate"] = int(cur.get("skipped_duplicate", 0)) + 1
                        cur["last_session"] = item.get("start_time")
                        _write_state(cur, _STATE_KEY_CHG)
                        continue
                    _insert_external_charge(db, plate, item)
                    db.commit()
                except Exception as e:
                    db.rollback()
                    log.exception("Charge insert failed for TM #%s", item.get("tm_id"))
                    _update_state(_STATE_KEY_CHG, status=S_ERROR,
                                  error=f"insert TM #{item.get('tm_id')}: {e}")
                    return
                cur = _read_state(_STATE_KEY_CHG)
                cur["processed"] = idx
                cur["imported"] = int(cur.get("imported", 0)) + 1
                cur["last_session"] = item.get("start_time")
                _write_state(cur, _STATE_KEY_CHG)
                # Small breather so the UI poll has time to observe progress
                time.sleep(0.05)
            # Loop exit
            final = _read_state(_STATE_KEY_CHG)
            if final.get("status") == S_RUNNING:
                _update_state(_STATE_KEY_CHG, status=S_DONE)
                log.info("Charges import done")
        finally:
            db.close()
    except Exception as e:
        log.exception("Charges worker crashed")
        _update_state(_STATE_KEY_CHG, status=S_ERROR, error=f"crash: {e}")
    finally:
        log.info("Charges worker exited")


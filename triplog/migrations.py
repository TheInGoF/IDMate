"""Schema migrations for the IDMate SQLite database.

Replaces the inline ~280-line migration block that used to live in
``app.get_db()``. Migrations are ordered and tracked via SQLite's native
``PRAGMA user_version`` — no SQLAlchemy/Alembic dependency.

Design notes
------------
* ``schema.sql`` (run by ``get_db`` before this module) creates the *base*
  tables with ``CREATE TABLE IF NOT EXISTS``. Everything here evolves that
  baseline via ``ALTER TABLE`` / table rebuilds / one-off data fixes.
* Each migration keeps its original *idempotent guard* (``if col not in
  cols``). That makes the runner safe for the large installed base of
  databases that pre-date version tracking: such a DB reports
  ``user_version == 0`` even though every column already exists, so the runner
  re-walks all migrations — but each one is a no-op on already-applied schema
  and the version is then stamped to ``SCHEMA_VERSION`` for instant skips on
  every later startup.
* To add a migration: append a ``(version, name, fn)`` tuple with the next
  integer and bump nothing else — ``SCHEMA_VERSION`` is derived from the list.

Helpers from ``app``/``detector`` that data-migrations need are imported lazily
inside the function (the established pattern in ``detector.get_db``) to avoid a
circular import at module load, since ``app`` imports this module.
"""

from detector import sanitize_soc as _sanitize_soc


# ── small introspection helpers ──────────────────────────────────

def _cols(db, table):
    """Column names of *table* (empty list if the table does not exist)."""
    return [r[1] for r in db.execute(f"PRAGMA table_info({table})").fetchall()]


def _tables(db):
    return {r[0] for r in db.execute(
        "SELECT name FROM sqlite_master WHERE type='table'").fetchall()}


# ── individual migrations (each is its own user_version step) ─────

def m001_trips_is_gpx(db, log):
    if "is_gpx" not in _cols(db, "trips"):
        db.execute("ALTER TABLE trips ADD COLUMN is_gpx INTEGER DEFAULT 0")


def m002_trips_odo(db, log):
    cols = _cols(db, "trips")
    if "odo_start" not in cols:
        db.execute("ALTER TABLE trips ADD COLUMN odo_start REAL")
        db.execute("ALTER TABLE trips ADD COLUMN odo_end REAL")


def m003_trips_country_code(db, log):
    if "country_code" not in _cols(db, "trips"):
        db.execute("ALTER TABLE trips ADD COLUMN country_code TEXT")


def m004_trips_is_manual(db, log):
    if "is_manual" not in _cols(db, "trips"):
        db.execute("ALTER TABLE trips ADD COLUMN is_manual INTEGER NOT NULL DEFAULT 0")
        log.info("Migration: trips.is_manual added")
        # Backfill country_code from start_address (format: "DE - City - Street")
        db.execute("""
            UPDATE trips SET country_code = UPPER(SUBSTR(start_address, 1, 2))
            WHERE country_code IS NULL AND start_address IS NOT NULL
              AND LENGTH(start_address) >= 2
              AND SUBSTR(start_address, 3, 3) IN (' - ', ' –', ' — ')
        """)
        log.info("Migration: trips.country_code backfilled")


def m005_trips_geocode_anchors(db, log):
    # Store the coordinates an address was geocoded for, so the background
    # geocoder can re-fetch when start/end shifts (e.g. a trip prematurely
    # closed before arrival and later extended).
    if "start_geo_lat" not in _cols(db, "trips"):
        db.execute("ALTER TABLE trips ADD COLUMN start_geo_lat REAL")
        db.execute("ALTER TABLE trips ADD COLUMN start_geo_lon REAL")
        db.execute("ALTER TABLE trips ADD COLUMN end_geo_lat REAL")
        db.execute("ALTER TABLE trips ADD COLUMN end_geo_lon REAL")
        # Anchor existing addresses to their current coordinates (no API calls):
        # history stays as-is, but any future coordinate shift now triggers a
        # re-geocode — including trips that are still open right now.
        db.execute("""UPDATE trips SET start_geo_lat = start_lat, start_geo_lon = start_lon
                      WHERE start_address IS NOT NULL AND start_lat IS NOT NULL""")
        db.execute("""UPDATE trips SET end_geo_lat = end_lat, end_geo_lon = end_lon
                      WHERE end_address IS NOT NULL AND end_lat IS NOT NULL""")
        log.info("Migration: trips geocode-anchor columns added")


def m006_recalc_consumption(db, log):
    # Recalculate consumption where SoC exists but energy/consumption is missing.
    missing = db.execute(
        """SELECT id, device, soc_start, soc_end, distance_km FROM trips
           WHERE energy_kwh IS NULL AND soc_start IS NOT NULL AND soc_end IS NOT NULL
             AND soc_start > soc_end"""
    ).fetchall()
    if not missing:
        return
    from app import get_bat_kwh  # lazy: app imports this module; only needed with data
    for t in missing:
        bat_kwh = get_bat_kwh(db, t["device"])
        energy = round((t["soc_start"] - t["soc_end"]) / 100 * bat_kwh, 2)
        cons = round(energy / t["distance_km"] * 100, 1) if t["distance_km"] and t["distance_km"] >= 10 else None
        db.execute("UPDATE trips SET energy_kwh = ?, consumption = ? WHERE id = ?",
                   (energy, cons, t["id"]))
    log.info("Consumption recalculated: %d trips", len(missing))


def m007_users_default_device(db, log):
    if "default_device" not in _cols(db, "users"):
        db.execute("ALTER TABLE users ADD COLUMN default_device TEXT")


def m008_users_active_vehicle(db, log):
    # Temporary selection, persisted in DB.
    if "active_vehicle_id" not in _cols(db, "users"):
        db.execute("ALTER TABLE users ADD COLUMN active_vehicle_id INTEGER")


def m009_users_totp(db, log):
    if "totp_secret" not in _cols(db, "users"):
        db.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT")
        db.execute("ALTER TABLE users ADD COLUMN totp_enabled INTEGER DEFAULT 0")
        db.execute("ALTER TABLE users ADD COLUMN setup_required INTEGER DEFAULT 0")


def m010_users_recovery_codes(db, log):
    if "recovery_codes" not in _cols(db, "users"):
        db.execute("ALTER TABLE users ADD COLUMN recovery_codes TEXT")


def m011_users_default_trip_purpose(db, log):
    if "default_trip_purpose" not in _cols(db, "users"):
        db.execute("ALTER TABLE users ADD COLUMN default_trip_purpose TEXT")


def m012_users_avatar(db, log):
    if "avatar_filename" not in _cols(db, "users"):
        db.execute("ALTER TABLE users ADD COLUMN avatar_filename TEXT")


def m013_cs_session_number(db, log):
    if "session_number" not in _cols(db, "charge_sessions"):
        db.execute("ALTER TABLE charge_sessions ADD COLUMN session_number TEXT")
        db.execute("ALTER TABLE charge_sessions ADD COLUMN is_external INTEGER DEFAULT 0")


def m014_cs_note_cost(db, log):
    if "note" not in _cols(db, "charge_sessions"):
        db.execute("ALTER TABLE charge_sessions ADD COLUMN note TEXT")
        db.execute("ALTER TABLE charge_sessions ADD COLUMN cost_total REAL")


def m015_cs_location(db, log):
    if "lat" not in _cols(db, "charge_sessions"):
        db.execute("ALTER TABLE charge_sessions ADD COLUMN lat REAL")
        db.execute("ALTER TABLE charge_sessions ADD COLUMN lon REAL")
        db.execute("ALTER TABLE charge_sessions ADD COLUMN location_name TEXT")


def m016_purpose_meta_is_main(db, log):
    if "is_main" not in _cols(db, "purpose_meta"):
        db.execute("ALTER TABLE purpose_meta ADD COLUMN is_main INTEGER NOT NULL DEFAULT 0")


def m017_route_rules_nullable(db, log):
    # Make from/to nullable (wildcard rules).
    rr_info = db.execute("PRAGMA table_info(route_rules)").fetchall()
    rr_cols = {r[1]: r[3] for r in rr_info}  # name -> notnull
    if rr_cols.get("from_location_id") == 1:  # still NOT NULL
        db.executescript("""
            CREATE TABLE route_rules_new (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                from_location_id INTEGER REFERENCES locations(id) ON DELETE CASCADE,
                to_location_id   INTEGER REFERENCES locations(id) ON DELETE CASCADE,
                purpose          TEXT NOT NULL,
                destination      TEXT,
                visit_reason     TEXT,
                created_at       TEXT DEFAULT (datetime('now')),
                UNIQUE(from_location_id, to_location_id)
            );
            INSERT INTO route_rules_new SELECT * FROM route_rules;
            DROP TABLE route_rules;
            ALTER TABLE route_rules_new RENAME TO route_rules;
        """)
        log.info("Migration: route_rules – from/to nullable")


def m018_vehicles_device(db, log):
    if "device" not in _cols(db, "vehicles"):
        db.execute("ALTER TABLE vehicles ADD COLUMN device TEXT")
        log.info("Migration: vehicles.device added")


def m019_vehicles_model(db, log):
    if "model" not in _cols(db, "vehicles"):
        db.execute("ALTER TABLE vehicles ADD COLUMN model TEXT")


def m020_vehicles_battery(db, log):
    if "battery_capacity_kwh" not in _cols(db, "vehicles"):
        db.execute("ALTER TABLE vehicles ADD COLUMN battery_capacity_kwh REAL")
        log.info("Migration: vehicles.battery_capacity_kwh added")


def m021_users_default_vehicle(db, log):
    if "default_vehicle_id" not in _cols(db, "users"):
        db.execute("ALTER TABLE users ADD COLUMN default_vehicle_id INTEGER")
        log.info("Migration: users.default_vehicle_id added")


def m022_locations_color(db, log):
    loc_cols = _cols(db, "locations")
    if loc_cols and "color" not in loc_cols:
        db.execute("ALTER TABLE locations ADD COLUMN color TEXT DEFAULT '#21262d'")
        log.info("Migration: locations.color added")


def m023_cl_icon_filename(db, log):
    cl_cols = _cols(db, "charge_locations")
    if cl_cols and "icon_filename" not in cl_cols:
        db.execute("ALTER TABLE charge_locations ADD COLUMN icon_filename TEXT")


def m024_cl_country_code(db, log):
    cl_cols = _cols(db, "charge_locations")
    if cl_cols and "country_code" not in cl_cols:
        db.execute("ALTER TABLE charge_locations ADD COLUMN country_code TEXT DEFAULT 'DE'")


def m025_cl_color(db, log):
    cl_cols = _cols(db, "charge_locations")
    if cl_cols and "color" not in cl_cols:
        db.execute("ALTER TABLE charge_locations ADD COLUMN color TEXT DEFAULT '#8b949e'")


def m026_cl_shape(db, log):
    cl_cols = _cols(db, "charge_locations")
    if cl_cols and "shape" not in cl_cols:
        db.execute("ALTER TABLE charge_locations ADD COLUMN shape TEXT DEFAULT 'circle'")
        db.execute("ALTER TABLE charge_locations ADD COLUMN lat2 REAL")
        db.execute("ALTER TABLE charge_locations ADD COLUMN lon2 REAL")


def m027_cs_operator(db, log):
    if "operator" not in _cols(db, "charge_sessions"):
        db.execute("ALTER TABLE charge_sessions ADD COLUMN operator TEXT")


def m028_cr_soc(db, log):
    if "soc" not in _cols(db, "charge_readings"):
        db.execute("ALTER TABLE charge_readings ADD COLUMN soc REAL")


def m029_cs_soc(db, log):
    if "soc_start" not in _cols(db, "charge_sessions"):
        db.execute("ALTER TABLE charge_sessions ADD COLUMN soc_start REAL")
        db.execute("ALTER TABLE charge_sessions ADD COLUMN soc_end REAL")


def m046_cs_manual_fields(db, log):
    # CSV of fields an admin manually backfilled (odometer/soc_start/soc_end) on
    # an automatic session — preserved across rebuild_charge_sessions so the
    # correction sticks instead of reverting to NULL on the next rebuild.
    if "manual_fields" not in _cols(db, "charge_sessions"):
        db.execute("ALTER TABLE charge_sessions ADD COLUMN manual_fields TEXT")


def m030_operators_table(db, log):
    # Operators with custom icon/color.
    if "operators" not in _tables(db):
        db.execute("""CREATE TABLE operators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            color TEXT DEFAULT '#8b949e',
            icon_filename TEXT
        )""")
        log.info("Migration: operators table created")


def m031_cl_operator_id(db, log):
    cl_cols = _cols(db, "charge_locations")
    if cl_cols and "operator_id" not in cl_cols:
        db.execute("ALTER TABLE charge_locations ADD COLUMN operator_id INTEGER REFERENCES operators(id) ON DELETE SET NULL")
        log.info("Migration: charge_locations.operator_id added")


def m032_user_notes(db, log):
    # Per-user notes (dashboard scratchpad).
    if "user_notes" not in _tables(db):
        db.execute("""CREATE TABLE user_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            vehicle_plate TEXT,
            content TEXT NOT NULL DEFAULT '',
            pinned INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT
        )""")
        db.execute("CREATE INDEX idx_user_notes_user ON user_notes(user_id, vehicle_plate, pinned DESC, id DESC)")
        log.info("Migration: user_notes table created")
    else:
        # vehicle_plate column added later — keep legacy NULL rows visible for
        # every vehicle (backward compat).
        if "vehicle_plate" not in _cols(db, "user_notes"):
            db.execute("ALTER TABLE user_notes ADD COLUMN vehicle_plate TEXT")
            log.info("Migration: user_notes.vehicle_plate added")


def m033_soc_underflow_repair(db, log):
    # Retroactively fix the SoC-Underflow bug (firmware cast of a negative float
    # to uint16 → ~6552 % instead of ~-1 %). Idempotent: already-repaired values
    # are back in range and no longer match the >110/<0 filter.
    repaired = 0
    for table, cols in (
        ("charge_readings", ("soc",)),
        ("charge_sessions", ("soc_start", "soc_end")),
        ("trips",           ("soc_start", "soc_end")),
    ):
        existing = set(_cols(db, table))
        for col in cols:
            if col not in existing:
                continue
            rows = db.execute(
                f"SELECT rowid, {col} FROM {table} WHERE {col} IS NOT NULL "
                f"AND ({col} > 110 OR {col} < 0)"
            ).fetchall()
            for rowid, raw in rows:
                fixed = _sanitize_soc(raw)
                if fixed is None:
                    # impossible to repair → NULL rather than keep nonsense
                    db.execute(f"UPDATE {table} SET {col} = NULL WHERE rowid = ?", (rowid,))
                else:
                    db.execute(f"UPDATE {table} SET {col} = ? WHERE rowid = ?", (fixed, rowid))
                repaired += 1
    if repaired:
        log.info("Migration: SoC-Underflow-Reparatur (%d Werte korrigiert)", repaired)


def m034_trips_kw(db, log):
    if "kw_start" not in _cols(db, "trips"):
        db.execute("ALTER TABLE trips ADD COLUMN kw_start REAL")
        db.execute("ALTER TABLE trips ADD COLUMN kw_end REAL")
        log.info("Migration: trips.kw_start/kw_end added")


def m035_locations_icon(db, log):
    if "icon" not in _cols(db, "locations"):
        db.execute("ALTER TABLE locations ADD COLUMN icon TEXT DEFAULT 'pin'")
        log.info("Migration: locations.icon added")


def m036_locations_icon_color(db, log):
    if "icon_color" not in _cols(db, "locations"):
        db.execute("ALTER TABLE locations ADD COLUMN icon_color TEXT DEFAULT 'white'")
        db.execute("UPDATE locations SET icon_color = 'white' WHERE icon_color IS NULL")
        log.info("Migration: locations.icon_color added")


def m037_cl_polygon(db, log):
    cl_cols = _cols(db, "charge_locations")
    if cl_cols and "polygon_coords" not in cl_cols:
        db.execute("ALTER TABLE charge_locations ADD COLUMN polygon_coords TEXT")
        log.info("Migration: charge_locations.polygon_coords added")


def m038_users_map_style(db, log):
    if "map_style" not in _cols(db, "users"):
        db.execute("ALTER TABLE users ADD COLUMN map_style TEXT")
        log.info("Migration: users.map_style added")


def m039_users_theme(db, log):
    # UI-Theme pro User: NULL/'' = dunkel (Standard), 'light', 'gt'.
    if "theme" not in _cols(db, "users"):
        db.execute("ALTER TABLE users ADD COLUMN theme TEXT")
        log.info("Migration: users.theme added")


# ── FIXES 15.1 — Fahrt-Tags: globaler Katalog + Sichtbarkeit pro User ──
# Modell: EIN Katalog je Tag-Typ (keine Duplikate), eine Visibility-Junction
# regelt, welcher User welchen Eintrag im Tagging-Dropdown sieht. Semantik:
# ein Tag ist fuer User X sichtbar, wenn (a) eine Zeile (tag, X) existiert ODER
# (b) der Tag GAR KEINE Visibility-Zeilen hat (= Legacy/global, kein Backfill).
# Alles additiv (ADD COLUMN / CREATE TABLE) — kein Rebuild, kein Datenrisiko.

def m040_purpose_meta_created_by(db, log):
    if "created_by" not in _cols(db, "purpose_meta"):
        db.execute("ALTER TABLE purpose_meta ADD COLUMN created_by INTEGER REFERENCES users(id) ON DELETE SET NULL")
        log.info("Migration: purpose_meta.created_by added")


def m041_purpose_visibility(db, log):
    if "purpose_visibility" not in _tables(db):
        db.execute("""CREATE TABLE purpose_visibility (
            name    TEXT    NOT NULL REFERENCES purpose_meta(name) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            PRIMARY KEY (name, user_id)
        )""")
        log.info("Migration: purpose_visibility table created")


def m042_preset_values_visibility(db, log):
    if "created_by" not in _cols(db, "preset_values"):
        db.execute("ALTER TABLE preset_values ADD COLUMN created_by INTEGER REFERENCES users(id) ON DELETE SET NULL")
    if "preset_value_visibility" not in _tables(db):
        db.execute("""CREATE TABLE preset_value_visibility (
            value_id INTEGER NOT NULL REFERENCES preset_values(id) ON DELETE CASCADE,
            user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            PRIMARY KEY (value_id, user_id)
        )""")
        log.info("Migration: preset_value_visibility table created")


def m043_route_rules_visibility(db, log):
    if "created_by" not in _cols(db, "route_rules"):
        db.execute("ALTER TABLE route_rules ADD COLUMN created_by INTEGER REFERENCES users(id) ON DELETE SET NULL")
    if "route_rule_visibility" not in _tables(db):
        db.execute("""CREATE TABLE route_rule_visibility (
            rule_id INTEGER NOT NULL REFERENCES route_rules(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            PRIMARY KEY (rule_id, user_id)
        )""")
        log.info("Migration: route_rule_visibility table created")


def m044_users_language(db, log):
    # Anzeige-Sprache pro User (FIXES 15.5): NULL = globaler Settings-Fallback.
    if "language" not in _cols(db, "users"):
        db.execute("ALTER TABLE users ADD COLUMN language TEXT")
        log.info("Migration: users.language added")


def m045_user_vehicle_access(db, log):
    # Pro-User-Fahrzeug-Sichtbarkeit: welche Fahrzeuge ein User sehen darf.
    # Semantik wie bei den Tags: KEINE Zeile fuer einen User = alle Fahrzeuge
    # (Standard/Rueckwaertskompat); Zeilen vorhanden = nur diese. Admins immer alle.
    if "user_vehicle_access" not in _tables(db):
        db.execute("""CREATE TABLE user_vehicle_access (
            user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            vehicle_id INTEGER NOT NULL REFERENCES vehicles(id) ON DELETE CASCADE,
            PRIMARY KEY (user_id, vehicle_id)
        )""")
        log.info("Migration: user_vehicle_access table created")


# ── ordered migration registry ───────────────────────────────────
# (version, name, fn). Append new entries with the next integer.

MIGRATIONS = [
    (1,  "trips_is_gpx",            m001_trips_is_gpx),
    (2,  "trips_odo",              m002_trips_odo),
    (3,  "trips_country_code",     m003_trips_country_code),
    (4,  "trips_is_manual",        m004_trips_is_manual),
    (5,  "trips_geocode_anchors",  m005_trips_geocode_anchors),
    (6,  "recalc_consumption",     m006_recalc_consumption),
    (7,  "users_default_device",   m007_users_default_device),
    (8,  "users_active_vehicle",   m008_users_active_vehicle),
    (9,  "users_totp",             m009_users_totp),
    (10, "users_recovery_codes",   m010_users_recovery_codes),
    (11, "users_default_purpose",  m011_users_default_trip_purpose),
    (12, "users_avatar",           m012_users_avatar),
    (13, "cs_session_number",      m013_cs_session_number),
    (14, "cs_note_cost",           m014_cs_note_cost),
    (15, "cs_location",            m015_cs_location),
    (16, "purpose_meta_is_main",   m016_purpose_meta_is_main),
    (17, "route_rules_nullable",   m017_route_rules_nullable),
    (18, "vehicles_device",        m018_vehicles_device),
    (19, "vehicles_model",         m019_vehicles_model),
    (20, "vehicles_battery",       m020_vehicles_battery),
    (21, "users_default_vehicle",  m021_users_default_vehicle),
    (22, "locations_color",        m022_locations_color),
    (23, "cl_icon_filename",       m023_cl_icon_filename),
    (24, "cl_country_code",        m024_cl_country_code),
    (25, "cl_color",               m025_cl_color),
    (26, "cl_shape",               m026_cl_shape),
    (27, "cs_operator",            m027_cs_operator),
    (28, "cr_soc",                 m028_cr_soc),
    (29, "cs_soc",                 m029_cs_soc),
    (30, "operators_table",        m030_operators_table),
    (31, "cl_operator_id",         m031_cl_operator_id),
    (32, "user_notes",             m032_user_notes),
    (33, "soc_underflow_repair",   m033_soc_underflow_repair),
    (34, "trips_kw",               m034_trips_kw),
    (35, "locations_icon",         m035_locations_icon),
    (36, "locations_icon_color",   m036_locations_icon_color),
    (37, "cl_polygon",             m037_cl_polygon),
    (38, "users_map_style",        m038_users_map_style),
    (39, "users_theme",            m039_users_theme),
    (40, "purpose_meta_created_by", m040_purpose_meta_created_by),
    (41, "purpose_visibility",     m041_purpose_visibility),
    (42, "preset_values_vis",      m042_preset_values_visibility),
    (43, "route_rules_vis",        m043_route_rules_visibility),
    (44, "users_language",         m044_users_language),
    (45, "user_vehicle_access",    m045_user_vehicle_access),
    (46, "cs_manual_fields",       m046_cs_manual_fields),
]

SCHEMA_VERSION = MIGRATIONS[-1][0]


def run_migrations(db, log):
    """Apply every migration whose version exceeds the DB's ``user_version``.

    Safe for fresh DBs (base tables from schema.sql, all migrations run) and for
    legacy unversioned DBs (``user_version`` 0 with columns already present —
    each guarded migration is a no-op, then the version is stamped to head).
    Each migration commits individually so a failure leaves the DB at the last
    fully-applied version rather than half-migrated.
    """
    current = db.execute("PRAGMA user_version").fetchone()[0]
    if current >= SCHEMA_VERSION:
        return
    for version, name, fn in MIGRATIONS:
        if version <= current:
            continue
        fn(db, log)
        # PRAGMA does not accept bound params; version is a trusted int literal.
        db.execute(f"PRAGMA user_version = {version}")
        db.commit()

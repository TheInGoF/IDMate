-- IDMate Triplog — SQLite Schema

CREATE TABLE IF NOT EXISTS trips (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    device          TEXT    NOT NULL DEFAULT 'id7',

    -- Zeitstempel
    start_time      TEXT    NOT NULL,   -- ISO 8601
    end_time        TEXT    NOT NULL,

    -- Positionen
    start_lat       REAL,
    start_lon       REAL,
    end_lat         REAL,
    end_lon         REAL,

    -- Geocoding
    start_address   TEXT,
    end_address     TEXT,
    -- Position, für die start/end_address geocodet wurde (Koordinaten-Anker).
    -- Verschiebt sich start/end_lat/lon hiergegen, holt der Worker die Adresse neu.
    start_geo_lat   REAL,
    start_geo_lon   REAL,
    end_geo_lat     REAL,
    end_geo_lon     REAL,

    -- Fahrdaten
    odo_start       REAL,               -- Kilometerstand bei Start
    odo_end         REAL,               -- Kilometerstand bei Ende
    distance_km     REAL,               -- od(Ende) - od(Start)
    soc_start       REAL,               -- % bei Start
    soc_end         REAL,               -- % bei Ende
    energy_kwh      REAL,               -- ∫ p dt
    consumption     REAL,               -- kWh/100km

    -- Fahrtenlog
    purpose         TEXT,                          -- Fahrtzweck (Fahrtenbuch)
    destination     TEXT,                      -- Fahrziel: Firma, Person, Ort
    visit_reason    TEXT,                      -- Besuchsgrund (nur nicht-privat)
    note            TEXT,

    created_at      TEXT    DEFAULT (datetime('now'))
);

-- Gespeicherte Orte (Geofencing)
CREATE TABLE IF NOT EXISTS locations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL,           -- "Firma Müller", "Eltern", "Büro"
    lat             REAL    NOT NULL,
    lon             REAL    NOT NULL,
    radius_m        INTEGER DEFAULT 200,        -- Geofence-Radius in Metern
    category        TEXT    DEFAULT 'kunde',     -- kunde, privat, arbeit, werkstatt
    default_reason  TEXT,                        -- Standard-Besuchsgrund für diesen Ort
    icon            TEXT    DEFAULT 'pin',        -- Icon-Name für Kartenanzeige
    color           TEXT    DEFAULT '#58a6ff',    -- Hintergrundfarbe des Kartenmarkers
    icon_color      TEXT    DEFAULT 'white',      -- Füllfarbe des Icons
    created_at      TEXT    DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS charges (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    device          TEXT    NOT NULL DEFAULT 'id7',

    start_time      TEXT    NOT NULL,
    end_time        TEXT    NOT NULL,

    -- Position
    lat             REAL,
    lon             REAL,
    address         TEXT,

    -- Ladedaten
    type            TEXT,               -- 'ac' | 'dc'
    soc_start       REAL,
    soc_end         REAL,
    energy_kwh      REAL,
    max_power_kw    REAL,

    created_at      TEXT    DEFAULT (datetime('now'))
);

-- Routen-Regeln (automatische Fahrtzweck-Zuordnung)
CREATE TABLE IF NOT EXISTS route_rules (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    from_location_id INTEGER REFERENCES locations(id) ON DELETE CASCADE,
    to_location_id   INTEGER REFERENCES locations(id) ON DELETE CASCADE,
    purpose         TEXT    NOT NULL,           -- z.B. "Dienstfahrt", "Arbeitsweg"
    destination     TEXT,                        -- optionales Fahrziel
    visit_reason    TEXT,                        -- optionaler Besuchsgrund
    created_at      TEXT    DEFAULT (datetime('now')),
    UNIQUE(from_location_id, to_location_id)
);

-- Benutzer
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT    NOT NULL UNIQUE,
    password_hash   TEXT    NOT NULL,
    is_admin        INTEGER DEFAULT 0,
    avatar_filename TEXT,
    created_at      TEXT    DEFAULT (datetime('now'))
);

-- Fahrtzwecke (zentral verwaltet)
CREATE TABLE IF NOT EXISTS purpose_meta (
    name            TEXT    PRIMARY KEY,
    color           TEXT    NOT NULL DEFAULT '#8b949e',  -- Kontrastfarbe (hex)
    is_private      INTEGER NOT NULL DEFAULT 0,          -- 1 = privat (kein Besuchsgrund)
    is_main         INTEGER NOT NULL DEFAULT 0,          -- 1 = Standard-Fahrtzweck (Quick-Button)
    sort_order      INTEGER NOT NULL DEFAULT 0
);


-- Vorschlagswerte (Fahrziele, Besuchsgründe etc.)
CREATE TABLE IF NOT EXISTS preset_values (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    field           TEXT    NOT NULL,           -- 'destination' | 'visit_reason'
    value           TEXT    NOT NULL,
    UNIQUE(field, value)
);

-- Einstellungen (Key-Value)
CREATE TABLE IF NOT EXISTS settings (
    key             TEXT    PRIMARY KEY,
    value           TEXT    NOT NULL
);

-- Defaults
INSERT OR IGNORE INTO settings (key, value) VALUES ('battery_capacity_kwh', '86.5');
INSERT OR IGNORE INTO settings (key, value) VALUES ('charge_session_start', '1');

CREATE INDEX IF NOT EXISTS idx_trips_device_time ON trips(device, start_time);
CREATE INDEX IF NOT EXISTS idx_charges_device_time ON charges(device, start_time);

-- ── Ladetracker ─────────────────────────────────────────────

-- Fahrzeuge (verknuepft InfluxDB-Device mit Ladetracker-Kennzeichen)
CREATE TABLE IF NOT EXISTS vehicles (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    plate           TEXT    NOT NULL UNIQUE,
    name            TEXT,
    model           TEXT,
    device          TEXT,                           -- InfluxDB device tag (z.B. "id7")
    vin             TEXT,
    created_at      TEXT    DEFAULT (datetime('now'))
);

-- Strompreis-Pauschale (jaehrlich anpassbar)
CREATE TABLE IF NOT EXISTS charge_tariffs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    valid_from      TEXT    NOT NULL UNIQUE,
    pauschale_kwh   REAL    NOT NULL,
    created_at      TEXT    DEFAULT (datetime('now'))
);

INSERT OR IGNORE INTO charge_tariffs (valid_from, pauschale_kwh) VALUES ('2026-01-01', 0.34);

-- Einzel-Messwerte (15-Min-Intervalle von Home Assistant)
CREATE TABLE IF NOT EXISTS charge_readings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT    NOT NULL,
    vehicle_plate   TEXT    NOT NULL,
    meter_start     REAL,
    meter_end       REAL,
    kwh             REAL    NOT NULL DEFAULT 0,
    tibber_price    REAL,
    tibber_grundgebuehr REAL,
    odometer        REAL,
    soc             REAL,
    session_id      INTEGER,
    created_at      TEXT    DEFAULT (datetime('now'))
);

-- Aggregierte Ladesessions (berechnet aus charge_readings)
CREATE TABLE IF NOT EXISTS charge_sessions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_number  TEXT,
    is_external     INTEGER DEFAULT 0,
    vehicle_plate   TEXT    NOT NULL,
    start_time      TEXT,
    end_time        TEXT,
    meter_start     REAL,
    meter_end       REAL,
    total_kwh       REAL,
    duration_minutes INTEGER,
    avg_kw          REAL,
    odometer        REAL,
    distance        REAL,
    cost_tibber     REAL,
    cost_pauschale  REAL,
    cost_diff       REAL,
    avg_tibber_price REAL,
    note            TEXT,
    cost_total      REAL,
    lat             REAL,
    lon             REAL,
    location_name   TEXT,
    soc_start       REAL,
    soc_end         REAL,
    manual_fields   TEXT,                 -- CSV der admin-gesetzten Felder (odometer,soc_start,soc_end) — beim Rebuild erhalten
    created_at      TEXT    DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_cr_session ON charge_readings(session_id);
CREATE INDEX IF NOT EXISTS idx_cr_vehicle ON charge_readings(vehicle_plate, timestamp);
CREATE INDEX IF NOT EXISTS idx_cs_vehicle ON charge_sessions(vehicle_plate, start_time);

-- ── Lade-Standorte (Geofencing für Ladevorgänge) ────────────

CREATE TABLE IF NOT EXISTS charge_locations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL,           -- "Wallbox Zuhause", "Ionity A1"
    lat             REAL    NOT NULL,
    lon             REAL    NOT NULL,
    radius_m        INTEGER DEFAULT 200,
    shape           TEXT    DEFAULT 'circle',   -- 'circle' | 'polygon'
    lat2            REAL,                       -- veraltet, bleibt für Migration
    lon2            REAL,
    polygon_coords  TEXT,                       -- JSON [[lat,lon],...] für Polygon
    type            TEXT    DEFAULT 'ac',       -- ac, dc, hpc
    operator        TEXT,                       -- Betreiber-Key (ionity, enbw, ...)
    color           TEXT    DEFAULT '#8b949e',  -- Fallback-Farbe wenn kein SVG
    note            TEXT,
    created_at      TEXT    DEFAULT (datetime('now'))
);

-- ── GPX-Import Wegpunkte ──────────────────────────────────

CREATE TABLE IF NOT EXISTS gpx_waypoints (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    trip_id         INTEGER NOT NULL REFERENCES trips(id) ON DELETE CASCADE,
    lat             REAL    NOT NULL,
    lon             REAL    NOT NULL,
    timestamp       TEXT,
    elevation       REAL,
    speed           REAL,
    seq             INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_gpx_trip ON gpx_waypoints(trip_id, seq);

-- ── Journeys (mehrere Fahrten zusammenfassen) ─────────────

CREATE TABLE IF NOT EXISTS journeys (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    device          TEXT    NOT NULL DEFAULT 'id7',
    title           TEXT    NOT NULL,
    date_from       TEXT    NOT NULL,           -- ISO 8601 Datum
    date_to         TEXT    NOT NULL,
    notes           TEXT,
    created_at      TEXT    DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS journey_trips (
    journey_id      INTEGER NOT NULL REFERENCES journeys(id) ON DELETE CASCADE,
    trip_id         INTEGER NOT NULL REFERENCES trips(id) ON DELETE CASCADE,
    PRIMARY KEY (journey_id, trip_id)
);

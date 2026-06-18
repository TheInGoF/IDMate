-- IDMate Triplog — SQLite Schema

CREATE TABLE IF NOT EXISTS trips (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    device          TEXT    NOT NULL DEFAULT 'id7',

    -- Timestamps
    start_time      TEXT    NOT NULL,   -- ISO 8601
    end_time        TEXT    NOT NULL,

    -- Positions
    start_lat       REAL,
    start_lon       REAL,
    end_lat         REAL,
    end_lon         REAL,

    -- Geocoding
    start_address   TEXT,
    end_address     TEXT,
    -- Position for which start/end_address was geocoded (coordinate anchor).
    -- If start/end_lat/lon drifts away from this, the worker re-fetches the address.
    start_geo_lat   REAL,
    start_geo_lon   REAL,
    end_geo_lat     REAL,
    end_geo_lon     REAL,

    -- Driving data
    odo_start       REAL,               -- Odometer reading at start
    odo_end         REAL,               -- Odometer reading at end
    distance_km     REAL,               -- odo(end) - odo(start)
    soc_start       REAL,               -- % at start
    soc_end         REAL,               -- % at end
    energy_kwh      REAL,               -- ∫ p dt
    consumption     REAL,               -- kWh/100km

    -- Trip log
    purpose         TEXT,                          -- Trip purpose (logbook)
    destination     TEXT,                      -- Destination: company, person, place
    visit_reason    TEXT,                      -- Visit reason (non-private only)
    note            TEXT,

    created_at      TEXT    DEFAULT (datetime('now'))
);

-- Saved locations (geofencing)
CREATE TABLE IF NOT EXISTS locations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL,           -- "Firma Mueller", "Parents", "Office"
    lat             REAL    NOT NULL,
    lon             REAL    NOT NULL,
    radius_m        INTEGER DEFAULT 200,        -- Geofence radius in meters (circle)
    shape           TEXT    DEFAULT 'circle',   -- 'circle' | 'polygon'
    polygon_coords  TEXT,                       -- JSON [[lat,lon],...] for polygon
    category        TEXT    DEFAULT 'kunde',     -- kunde, privat, arbeit, werkstatt
    default_reason  TEXT,                        -- Default visit reason for this location
    icon            TEXT    DEFAULT 'pin',        -- Icon name for map display
    color           TEXT    DEFAULT '#58a6ff',    -- Background color of the map marker
    icon_color      TEXT    DEFAULT 'white',      -- Fill color of the icon
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

    -- Charge data
    type            TEXT,               -- 'ac' | 'dc'
    soc_start       REAL,
    soc_end         REAL,
    energy_kwh      REAL,
    max_power_kw    REAL,

    created_at      TEXT    DEFAULT (datetime('now'))
);

-- Route rules (automatic trip-purpose assignment)
CREATE TABLE IF NOT EXISTS route_rules (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    from_location_id INTEGER REFERENCES locations(id) ON DELETE CASCADE,
    to_location_id   INTEGER REFERENCES locations(id) ON DELETE CASCADE,
    purpose         TEXT    NOT NULL,           -- e.g. "Dienstfahrt", "Arbeitsweg"
    destination     TEXT,                        -- optional destination
    visit_reason    TEXT,                        -- optional visit reason
    created_at      TEXT    DEFAULT (datetime('now')),
    UNIQUE(from_location_id, to_location_id)
);

-- Users
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT    NOT NULL UNIQUE,
    password_hash   TEXT    NOT NULL,
    is_admin        INTEGER DEFAULT 0,
    avatar_filename TEXT,
    created_at      TEXT    DEFAULT (datetime('now'))
);

-- Trip purposes (centrally managed)
CREATE TABLE IF NOT EXISTS purpose_meta (
    name            TEXT    PRIMARY KEY,
    color           TEXT    NOT NULL DEFAULT '#8b949e',  -- Contrast color (hex)
    is_private      INTEGER NOT NULL DEFAULT 0,          -- 1 = private (no visit reason)
    is_main         INTEGER NOT NULL DEFAULT 0,          -- 1 = default trip purpose (quick button)
    sort_order      INTEGER NOT NULL DEFAULT 0
);


-- Suggestion values (destinations, visit reasons, etc.)
CREATE TABLE IF NOT EXISTS preset_values (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    field           TEXT    NOT NULL,           -- 'destination' | 'visit_reason'
    value           TEXT    NOT NULL,
    UNIQUE(field, value)
);

-- Settings (key-value)
CREATE TABLE IF NOT EXISTS settings (
    key             TEXT    PRIMARY KEY,
    value           TEXT    NOT NULL
);

-- Defaults
INSERT OR IGNORE INTO settings (key, value) VALUES ('battery_capacity_kwh', '86.5');
INSERT OR IGNORE INTO settings (key, value) VALUES ('charge_session_start', '1');

CREATE INDEX IF NOT EXISTS idx_trips_device_time ON trips(device, start_time);
CREATE INDEX IF NOT EXISTS idx_charges_device_time ON charges(device, start_time);

-- ── Charge tracker ──────────────────────────────────────────

-- Vehicles (links InfluxDB device with charge-tracker license plate)
CREATE TABLE IF NOT EXISTS vehicles (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    plate           TEXT    NOT NULL UNIQUE,
    name            TEXT,
    model           TEXT,
    device          TEXT,                           -- InfluxDB device tag (e.g. "id7")
    vin             TEXT,
    created_at      TEXT    DEFAULT (datetime('now'))
);

-- Electricity price flat rate (adjustable yearly)
CREATE TABLE IF NOT EXISTS charge_tariffs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    valid_from      TEXT    NOT NULL UNIQUE,
    pauschale_kwh   REAL    NOT NULL,
    created_at      TEXT    DEFAULT (datetime('now'))
);

INSERT OR IGNORE INTO charge_tariffs (valid_from, pauschale_kwh) VALUES ('2026-01-01', 0.34);

-- Individual readings (15-minute intervals from Home Assistant)
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

-- Aggregated charge sessions (computed from charge_readings)
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
    manual_fields   TEXT,                 -- CSV of admin-set fields (odometer,soc_start,soc_end) — preserved on rebuild
    created_at      TEXT    DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_cr_session ON charge_readings(session_id);
CREATE INDEX IF NOT EXISTS idx_cr_vehicle ON charge_readings(vehicle_plate, timestamp);
CREATE INDEX IF NOT EXISTS idx_cs_vehicle ON charge_sessions(vehicle_plate, start_time);

-- ── Charge locations (geofencing for charging events) ───────

CREATE TABLE IF NOT EXISTS charge_locations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL,           -- "Wallbox Home", "Ionity A1"
    lat             REAL    NOT NULL,
    lon             REAL    NOT NULL,
    radius_m        INTEGER DEFAULT 200,
    shape           TEXT    DEFAULT 'circle',   -- 'circle' | 'polygon'
    lat2            REAL,                       -- deprecated, kept for migration
    lon2            REAL,
    polygon_coords  TEXT,                       -- JSON [[lat,lon],...] for polygon
    type            TEXT    DEFAULT 'ac',       -- ac, dc, hpc
    operator        TEXT,                       -- Operator key (ionity, enbw, ...)
    color           TEXT    DEFAULT '#8b949e',  -- Fallback color when no SVG
    note            TEXT,
    created_at      TEXT    DEFAULT (datetime('now'))
);

-- ── GPX import waypoints ──────────────────────────────────

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

-- ── Journeys (group multiple trips together) ──────────────

CREATE TABLE IF NOT EXISTS journeys (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    device          TEXT    NOT NULL DEFAULT 'id7',
    title           TEXT    NOT NULL,
    date_from       TEXT    NOT NULL,           -- ISO 8601 date
    date_to         TEXT    NOT NULL,
    notes           TEXT,
    created_at      TEXT    DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS journey_trips (
    journey_id      INTEGER NOT NULL REFERENCES journeys(id) ON DELETE CASCADE,
    trip_id         INTEGER NOT NULL REFERENCES trips(id) ON DELETE CASCADE,
    PRIMARY KEY (journey_id, trip_id)
);

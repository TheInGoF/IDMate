# TeslaMate import

Optional feature to do a one-time import of historic drives and charges from an existing
TeslaMate stack into IDmate. Fully opt-in via a second compose file — the base compose
stays untouched.

> Status: Phase 1 (connection test + car mapping) is live. Preview & import logic follow
> in later releases.

## Requirements

- A running TeslaMate stack with a Postgres container (default images
  `teslamate/teslamate` + `postgres`)
- The IDmate stack on the same Docker host
- An admin login in IDmate

## Setup

### 1. Give the TeslaMate network an explicit name

In **TeslaMate's own** `docker-compose.yml`:

```yaml
networks:
  teslamate-network:
    driver: bridge
    name: teslamate-network   # forces the name without the compose prefix
```

Without `name:`, Docker prepends the project name (e.g.
`car-teslamate_teslamate-network`), which makes the external reference from IDmate
fragile. After the change:

```bash
cd path/to/teslamate
docker compose down
docker compose up -d
docker network ls | grep teslamate    # should show exactly 'teslamate-network'
```

### 2. Extend IDmate's `.env`

```bash
TESLAMATE_PG_URL=postgresql://teslamate:YOUR_PASSWORD@TeslaMate-DB:5432/teslamate
```

- **Hostname** = container name from the TeslaMate compose (default: `TeslaMate-DB`)
- **Port** = `5432` (Postgres default *inside the container* — the host port is irrelevant)
- **Password** = `POSTGRES_PASSWORD` from your TeslaMate `.env`

### 3. Start IDmate with the override

```bash
cd path/to/idmate
docker compose -f docker-compose.yml -f docker-compose.teslamate.yml up -d
```

The override adds only two things to the `triplog` service:
- the `TESLAMATE_PG_URL` env var (read at startup)
- the extra network membership in `teslamate-network`

### 4. Test in the admin panel

- Log in as admin
- Open the **"TeslaMate import"** tab (only visible when the env var is set)
- Click **"Test connection"**
- Expected: green status + Postgres version + drive/charge counts +
  a list of TeslaMate cars with a dropdown to map them to IDmate vehicles

## Troubleshooting

| Problem | Fix |
| --- | --- |
| `network teslamate-network declared as external but could not be found` | `docker network ls` — if the name has a prefix: set `name:` in the TeslaMate compose (see step 1) |
| Connection test red, "connection refused" | Wrong container name or port — `docker exec -it triplog ping -c1 TeslaMate-DB` checks name resolution |
| Connection test red, "password authentication failed" | The password in `.env` does not match TeslaMate's `POSTGRES_PASSWORD` |
| Tab does not appear in admin | Env var not set, or the override file was forgotten at startup (`-f docker-compose.teslamate.yml`) |

## Security

- The TeslaMate DB stays on the internal Docker network — no host port exposed
- IDmate has read-only access (Phase 1 only does `SELECT`)
- Postgres credentials come from `.env` and are not baked into the image
- When you no longer need the import: just restart IDmate without the override
  file — the tab disappears and the module stays inactive

## What gets imported (later)

| TeslaMate | IDmate |
| --- | --- |
| `drives` | `trips` (with `is_manual=0`, `note='TM #id'`) |
| `charging_processes` | `charge_sessions` (`is_external=1`, incl. `cost`) |
| `positions` (opt-in) | InfluxDB bucket `can-scan` |

Details and column mapping: see the import module source
([triplog/teslamate_import.py](../triplog/teslamate_import.py)).

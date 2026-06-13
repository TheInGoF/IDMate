# TeslaMate-Import

Optionales Feature, um historische Drives und Charges aus einem bestehenden
TeslaMate-Stack einmalig nach IDMate zu importieren. Aktivierung komplett
opt-in über ein zweites Compose-File — die Basis-Compose bleibt unangetastet.

> Status: Phase 1 (Connection-Test + Car-Mapping) ist live. Preview &
> Import-Logik folgen in späteren Releases.

## Voraussetzungen

- Laufender TeslaMate-Stack mit Postgres-Container (Standard-Image
  `teslamate/teslamate` + `postgres`)
- IDMate-Stack auf demselben Docker-Host
- Admin-Login in IDMate

## Setup

### 1. TeslaMate-Netzwerk explizit benennen

In der **TeslaMate-eigenen** `docker-compose.yml`:

```yaml
networks:
  teslamate-network:
    driver: bridge
    name: teslamate-network   # erzwingt den Namen ohne Compose-Prefix
```

Ohne `name:` hängt Docker den Projekt-Namen davor (z.B.
`car-teslamate_teslamate-network`), was die externe Referenz aus IDMate
brüchig macht. Nach der Änderung:

```bash
cd path/to/teslamate
docker compose down
docker compose up -d
docker network ls | grep teslamate    # sollte exakt 'teslamate-network' zeigen
```

### 2. IDMate-`.env` ergänzen

```bash
TESLAMATE_PG_URL=postgresql://teslamate:DEIN_PASSWORT@TeslaMate-DB:5432/teslamate
```

- **Hostname** = Container-Name aus der TeslaMate-Compose (Standard: `TeslaMate-DB`)
- **Port** = `5432` (Postgres-Default *im Container* — der Host-Port spielt keine Rolle)
- **Passwort** = `POSTGRES_PASSWORD` aus deiner TeslaMate-`.env`

### 3. IDMate mit dem Override starten

```bash
cd path/to/idmate
docker compose -f docker-compose.yml -f docker-compose.teslamate.yml up -d
```

Der Override fügt nur zwei Dinge zum `triplog`-Service hinzu:
- die `TESLAMATE_PG_URL`-ENV (wird ausgelesen)
- die zusätzliche Netzwerk-Mitgliedschaft in `teslamate-network`

### 4. Im Admin-Panel testen

- Login als Admin
- Tab **„TeslaMate-Import"** öffnen (nur sichtbar wenn ENV gesetzt)
- Button **„Verbindung testen"**
- Erwartet: grüner Status + Postgres-Version + Drive/Charge-Counts +
  Liste der TeslaMate-Cars mit Dropdown zur IDMate-Zuordnung

## Troubleshooting

| Problem | Lösung |
| --- | --- |
| `network teslamate-network declared as external but could not be found` | `docker network ls` — wenn Name einen Prefix hat: TeslaMate-Compose `name:` setzen (siehe Schritt 1) |
| Connection-Test rot, „connection refused" | Container-Name oder Port falsch — `docker exec -it triplog ping -c1 TeslaMate-DB` prüft Name-Auflösung |
| Connection-Test rot, „password authentication failed" | Passwort in `.env` matcht nicht TeslaMate's `POSTGRES_PASSWORD` |
| Tab erscheint nicht im Admin | ENV nicht gesetzt, oder Override-File beim Start vergessen (`-f docker-compose.teslamate.yml`) |

## Sicherheit

- TeslaMate-DB bleibt auf dem internen Docker-Netz — kein Host-Port exponiert
- IDMate hat nur Lese-Zugriff (Phase 1 macht nur `SELECT`)
- Postgres-Credentials kommen aus `.env` und werden nicht ins Image gebacken
- Wenn du den Import nicht mehr brauchst: einfach IDMate ohne den
  Override-File neu starten — der Tab verschwindet, das Modul bleibt
  inaktiv

## Was wird (später) importiert

| TeslaMate | IDMate |
| --- | --- |
| `drives` | `trips` (mit `is_manual=0`, `note='TM #id'`) |
| `charging_processes` | `charge_sessions` (`is_external=1`, inkl. `cost`) |
| `positions` (opt-in) | InfluxDB-Bucket `can-scan` |

Details und Spalten-Mapping: siehe Bauplan-Sektion 15.

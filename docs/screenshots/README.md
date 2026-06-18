# Screenshots

These files are referenced from the main [README](../../README.md). Filenames must match exactly (spaces are allowed — they get URL-encoded as `%20`).

| File | README section |
| --- | --- |
| `Dashboard.png` | Vehicle Dashboard |
| `Trip Log.png` | Trip Logbook |
| `Journeys.png` | Journeys |
| `Analysis Overview.png` | Analysis |
| `Charge Log.png` | Charge Tracker |
| `Settings Overview.png` | Settings / Admin |
| `Profile.png` | Profile |

**Tip:** keep widths around 1400–1600 px; PNG for UI, JPG (q≈85) for map-heavy views.

These captures show the dark theme with synthetic demo data (an ID.7 Pro, a few
weeks of trips, home + DC charges, two journeys). They are reproducible: seed a
throwaway SQLite + a local InfluxDB, boot Triplog and drive a headless browser
over the pages — the helper scripts used for this round are not committed since
they only matter when the screenshots are refreshed.

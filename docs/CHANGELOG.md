# Changelog

## 0.1.0

First release of the engagement tool.

- Loopback UI for one authorized engagement: intake, advisory or exploratory checks, review, assessment, remediation handoff, finalize, export, and purge.
- Local Antares-1B inference on a Unix socket, with the official CLI in a `network=none` container.
- `astrolabe setup`, `astrolabe doctor`, and `astrolabe start`.
- `./astrolabe up` installs a checkout, then starts the local server. `down`, `status`, and `logs` go with it.
- `advisories sync` accepts an optional `--engagement`; without it, the sync is recorded at cache level.
- Default data under `~/Astrolabe/` and per-user socket, token, and config directories outside the engagements root.
- CWE catalog, dictionary, and relations shipped in the wheel.

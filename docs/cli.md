# CLI

The console script is `astrolabe`. `python -m astrolabe` is the same program. `--version` and `-V` print `astrolabe 0.1.0`.

Most engagement commands accept `--engagements-root` to override `ASTROLABE_ENGAGEMENTS_DIR` for that invocation.

## Setup and the UI

| Command | Flags |
|---|---|
| `astrolabe setup` | `--model-path` (required) |
| `astrolabe doctor` | `--engagements-root` |
| `astrolabe start` | `--port` (default 8765) |
| `astrolabe ui` | `--port` (default 8765), `--engagements-root` |

`setup` checks the weights, verifies the SHA-256, builds the sandbox image from `<model-path>/antares-cli.zip`, and writes the per-user config. It does not download weights.

`doctor` prints `name`, `status`, `location`, and `fix` for each Status row. Exit status is nonzero when a required check is missing.

`start` starts the inference server, waits for `/health`, then starts the UI. Ctrl-C stops both.

From a git checkout, `./astrolabe` creates `.venv` when it is missing and then runs the same program.

| Command | Flags |
|---|---|
| `./astrolabe up` | `--model-path`, `--port` (default 8765), `--download-weights`, `--foreground` |
| `./astrolabe down` | |
| `./astrolabe status` | |
| `./astrolabe logs` | `--follow` |

`up` checks Docker, resolves weights, runs setup only when the model path or the sandbox image is out of date, runs doctor, and starts the server and the UI in the background. `--foreground` keeps the current `start` behavior: the UI stays in the foreground and Ctrl-C stops both. `down` stops the processes recorded by `up`. `status` prints the running state, the URL, and a doctor summary.

## Engagement

| Command | Flags |
|---|---|
| `astrolabe engagement create` | `--id`, `--customer`, `--scope`, `--start`, `--end`, `--consultant` (repeatable), `--reference`, `--authorized`, `--engagements-root` |
| `astrolabe engagement close` | `--id`, `--actor`, `--end`, `--engagements-root` |
| `astrolabe engagement show` | `--id`, `--engagements-root` |
| `astrolabe attest` | `--engagement`, `--actor`, `--reference`, `--scope`, `--timestamp`, `--engagements-root` |
| `astrolabe intake` | `--engagement`, `--path`, `--include-tests`, `--replace`, `--engagements-root` |

## Checks and verdicts

| Command | Flags |
|---|---|
| `astrolabe investigate` | `--engagement`, `--cwe`, `--actor`, `--advisory-id`, `--advisory-text`, `--exploratory`, `--advisory-cache`, `--engagements-root` |
| `astrolabe rerun` | `--engagement`, `--investigation`, `--actor`, `--engagements-root` |
| `astrolabe verdict` | `--engagement`, `--path`, `--cwe`, `--state`, `--actor`, `--note`, `--confirm-advisory`, `--engagements-root` |
| `astrolabe coverage` | `--engagement`, `--engagements-root` |

Pass one of `--advisory-id`, `--advisory-text`, or `--exploratory` for `investigate`.

## Advisories

| Command | Flags |
|---|---|
| `astrolabe advisories sync` | `--engagement` (optional), `--id` (repeatable), `--from-file`, `--actor`, `--cache`, `--engagements-root` |
| `astrolabe advisories import` | `directory` (positional), `--cache` |

Sync is the network command. Import reads a local directory and does not take `--engagement`.

With `--engagement`, `--actor` must be a consultant on that engagement. The audit line records that engagement id. Without `--engagement`, the sync is cache-level: the actor is recorded as given, the audit line has no engagement id, and its scope is `advisory_cache`. A cache-level sync does not validate the actor, because no consultant list applies.

## Reports

| Command | Flags |
|---|---|
| `astrolabe report assessment` | `--engagement`, `--actor`, `--include-unreviewed`, `--html`, `--pdf`, `--engagements-root` |
| `astrolabe report remediation` | `--engagement`, `--actor`, `--markdown`, `--json`, `--engagements-root` |
| `astrolabe report finalize` | `--engagement`, `--actor`, `--engagements-root` |
| `astrolabe export` | `--engagement`, `--output`, `--actor`, `--allow-draft`, `--report-only`, `--engagements-root` |
| `astrolabe purge` | `--engagement`, `--actor`, `--confirm-exports-handled`, `--engagements-root` |

`--include-unreviewed` is refused. Unreviewed candidates are not included in customer reports.

## Diagnostics

These talk to Docker and the local inference socket. They do not record an attestation or an intake.

| Command | Flags | Purpose |
|---|---|---|
| `astrolabe verify-isolation` | `--engagement` | Runs a probe in the sandbox and checks that the only interface is `lo` and that an outbound connection fails. |
| `astrolabe long-generation` | `--engagement`, `--max-tokens` | Asks the local server for a long completion through the sandbox helper. |

## Known limitations

`query` is not a command. It did not require attestation or intake, so it is not dispatched.

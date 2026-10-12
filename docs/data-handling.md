# Data handling

Everything derived from a customer repository for one engagement lives under that engagement's directory, except the durable audit log, the advisory cache, and exports you have already written.

## Where files live

| Path | Contents |
|---|---|
| `~/Astrolabe/engagements/<id>/` | Engagement record, snapshot, traces, candidates, reports |
| `~/Astrolabe/var/audit.jsonl` | Durable audit log. Survives purge. |
| `~/Astrolabe/var/purge-log.jsonl` | Purge log path. Override with `ASTROLABE_PURGE_LOG`. |
| `~/Astrolabe/advisories/` | Cached advisory JSON. Shared across engagements on this machine. |
| `~/Astrolabe/exports/` | Export archives, mode 0700 when Astrolabe creates the directory. |
| `~/Library/Application Support/Astrolabe/config.toml` | Model path. Mode 0600. |
| `~/Library/Application Support/Astrolabe/run/` | Inference socket directory. Mode 0700. |
| `~/Library/Application Support/Astrolabe/tokens/` | Per-run bearer tokens. Mode 0700. Deleted after each run. |
| The directory you passed to setup | Weights and `antares-cli.zip`. Not managed by Astrolabe. |

Linux uses `$XDG_CONFIG_HOME/astrolabe/config.toml` and `$XDG_RUNTIME_DIR` for the socket and tokens. See [configuration.md](configuration.md).

Set `ASTROLABE_ENGAGEMENTS_DIR` to keep using an existing engagements directory. The audit log then defaults to that directory's parent `var/audit.jsonl`.

## Exports

A report-only export contains the assessment HTML, the assessment status, and the PDF if it was produced.

A full export contains redacted engagement records, reports, and traces. It does not contain the customer source tree.

Check mode refuses an export that does not match the finalized report bytes.

## Retention and purge

Close stops new checks and verdicts. Purge deletes `~/Astrolabe/engagements/<id>/` and appends the audit log. Exports under `~/Astrolabe/exports` remain. The advisory cache remains. The weights remain.

## What never leaves the machine

Customer source, snapshots, traces, notes, and model prompts stay on this host except for the two operator actions that use the network: advisory sync, which sends advisory ids, and git clone, which contacts the git host you named. Inference is the local Unix socket. There is no hosted-model fallback.

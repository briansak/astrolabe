# Security

## Threat model

Astrolabe assumes the operator's account on this machine is the trust boundary. Customer code is untrusted input. Model output is untrusted advice. The consultant is the person who decides what enters a customer report.

The tool does not defend against another process running as the same user.

## Sandbox

Each investigation container is started with:

- `--network none`
- `--read-only`
- `--cap-drop ALL`
- `--security-opt no-new-privileges`
- `--pids-limit 256`
- a memory and CPU limit (`1536m` and `1` unless overridden)
- the snapshot mounted read-only at `/workspace/repo`
- the engagement data directory mounted read-write at `/data`
- a tmpfs on `/tmp`

The container is removed when the run finishes or is cancelled. A relay may publish the host Unix socket to the container runtime when the engine cannot mount a macOS socket. The CLI container itself stays on `network=none`.

## Socket and token directories

Defaults on macOS:

- socket: `~/Library/Application Support/Astrolabe/run/inference.sock`
- tokens: `~/Library/Application Support/Astrolabe/tokens`

On Linux the defaults are under `$XDG_RUNTIME_DIR` (`astrolabe/inference.sock` and `astrolabe-tokens`), or `/run/user/<uid>/...` when that directory already exists. If `XDG_RUNTIME_DIR` is unset and `/run/user/<uid>` is missing, Astrolabe refuses to create it.

Both directories are mode 0700. A path inside the engagements root is refused. If `ANTARES_SOCKET` and `ASTROLABE_INFERENCE_SOCKET` are both set, they must be the same path. The same rule applies to `ANTARES_TOKEN_DIR` and `ASTROLABE_TOKEN_DIR`. The token directory must not sit inside the socket directory.

The per-run bearer token is written in the token directory, passed into the container as `ANTARES_API_KEY`, and deleted when the container exits.

## Browser checks

The UI binds `127.0.0.1` only. POST requests must come from that origin. `Sec-Fetch-Site` is checked when the browser sends it. A cross-site POST is refused.

## Network use

After install and setup, Astrolabe uses the network only for:

- advisory sync (OSV and GitHub)
- git clone or fetch during intake

Sync is refused while an investigation is running. `GITHUB_TOKEN` is read from the environment when GitHub asks for it. It is not written into the tree.

`astrolabe setup` builds the sandbox image before any engagement exists. That build contacts Docker Hub, ghcr.io, Debian, and PyPI. The `uv` image is `ghcr.io/astral-sh/uv:0.9.7@sha256:ba4857bf2a068e9bc0e64eed8563b065908a4cd6bfb66b531a9c424c8e25e142`. Setup, doctor, and start make no other network calls. Doctor and start make none.

## Redaction

Notes, trace text shown in the UI, and export bodies pass through the redactor. Matches include common cloud keys, private-key blocks, passwords in URLs, bearer tokens, and JWTs. A snapshot line that looks like a secret is hidden on the review card. The redactor is the chokepoint. Do not copy customer source into a report field that bypasses it.

## Audit log

The durable log is outside the engagement directory, by default `~/Astrolabe/var/audit.jsonl`. It records engagement creation, attestation, intake, investigations, verdicts, report generation, finalize, export, close, and purge. Purging an engagement removes the engagement directory and leaves this log.

## Purge

Purge deletes the engagement directory. Exports already written under `~/Astrolabe/exports` are not deleted. If any of those files are still on disk, purge stops until you pass the confirmation that they have been handled.

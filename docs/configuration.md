# Configuration

Environment variables override the defaults. Paths expand `~`.

## Operator paths

| Variable | Default | Purpose |
|---|---|---|
| `ASTROLABE_ENGAGEMENTS_DIR` | `~/Astrolabe/engagements` | Engagement root. Set this to keep an existing directory. |
| `ASTROLABE_AUDIT_LOG` | `<parent of the engagements root>/var/audit.jsonl` | Durable audit log. With the default root this is `~/Astrolabe/var/audit.jsonl`. |
| `ASTROLABE_PURGE_LOG` | `~/Astrolabe/var/purge-log.jsonl` | Purge log path. |
| `ASTROLABE_ADVISORY_CACHE` | `~/Astrolabe/advisories` | Advisory JSON cache. |
| `ANTARES_MODEL_PATH` | unset; otherwise `model_path` in the setup config file | Weights directory. Overrides the config file. |
| `XDG_CONFIG_HOME` | `~/.config` on Linux | Base for `astrolabe/config.toml` on Linux. |
| `XDG_RUNTIME_DIR` | unset | Linux base for the default socket and token directories. |

The setup config file is `~/Library/Application Support/Astrolabe/config.toml` on macOS and `$XDG_CONFIG_HOME/astrolabe/config.toml` on Linux. It holds `model_path`. Mode 0600.

## Inference socket and tokens

| Variable | Default | Purpose |
|---|---|---|
| `ANTARES_SOCKET` | `~/Library/Application Support/Astrolabe/run/inference.sock` on macOS | Socket the server listens on. |
| `ASTROLABE_INFERENCE_SOCKET` | the same path as `ANTARES_SOCKET` | Runner side of the socket. Must match when both are set. |
| `ANTARES_TOKEN_DIR` | `~/Library/Application Support/Astrolabe/tokens` on macOS | Directory for per-run bearer tokens. |
| `ASTROLABE_TOKEN_DIR` | the same path as `ANTARES_TOKEN_DIR` | Runner side. Must match when both are set. |
| `ANTARES_LISTEN` | `unix` | `tcp` binds loopback instead of a socket. |
| `ANTARES_BIND_HOST` | `127.0.0.1` | TCP host. Anything other than loopback is refused. |
| `ANTARES_PORT` | `8090` | TCP port when `ANTARES_LISTEN=tcp`. |
| `ANTARES_DEVICE` | `auto` | `mps`, `cuda`, or `cpu`. |
| `ANTARES_SERVED_MODEL_ID` | `fdtn-ai/antares-1b` | Model id the server advertises. |
| `HF_HUB_OFFLINE` | `1` (set by the server if unset) | Hugging Face hub stays offline. |
| `TRANSFORMERS_OFFLINE` | `1` (set by the server if unset) | Transformers stays offline. |
| `HF_HUB_DISABLE_IMPLICIT_TOKEN` | `1` (set by the server if unset) | Do not send a hub token. |

## Sandbox and checks

| Variable | Default | Purpose |
|---|---|---|
| `ASTROLABE_CLI_IMAGE` | `astrolabe-antares-cli:1` | Sandbox image tag. |
| `ANTARES_CLI_ZIP` | unset | Zip path for `scripts/build-cli-image.sh`. Setup reads `<model-path>/antares-cli.zip` instead. |
| `ASTROLABE_SOCKET_BRIDGE` | `auto` | How the host socket is shown to the container runtime. |
| `ASTROLABE_CONTAINER_MEMORY` | `1536m` | Container memory limit. |
| `ASTROLABE_CONTAINER_CPUS` | `1` | Container CPU limit. |
| `ANTARES_REMOTE_TIMEOUT_SECONDS` | `1200` | Timeout passed into the CLI for one completion. |
| `ASTROLABE_ACTIVITY_STALL_SECONDS` | `60` | How long a quiet run is shown as stalled. |
| `ASTROLABE_EVIDENCE_EXCLUSIONS` | built-in list | Extra path fragments dropped from plan evidence text. |
| `ASTROLABE_PRESELECT_LIMIT` | `5` | How many evidence rows are preselected. |
| `ASTROLABE_ESTIMATE_PER_CHECK` | `120` | Seconds used for the queue time estimate. |
| `ASTROLABE_INVESTIGATION_RUN` | unset | Set to `1` while a check runs so advisory sync is refused. |
| `GITHUB_TOKEN` | unset | Sent only by advisory sync when GitHub requires it. |
| `HF_TOKEN` | unset | Read by `scripts/stage-antares-1b.sh`. Not used by setup, doctor, or start. |

## Set inside the sandbox

The runner sets these on the container. They are not operator settings.

| Variable | Value | Purpose |
|---|---|---|
| `ANTARES_DATA_DIR` | `/data` | CLI data directory. Always set. The CLI default is not used. |
| `ANTARES_ENDPOINT` | `http://127.0.0.1:8000/v1/completions` | Loopback proxy inside the container. |
| `ANTARES_MODEL` | `fdtn-ai/antares-1b` | Model id sent by the CLI. |
| `ANTARES_API_KEY` | the per-run token | Bearer token for that run. Removed when the container exits. |
| `HOME` | `/data` | Home directory inside the container. |
| `PYTHONDONTWRITEBYTECODE` | `1` | The container does not write bytecode. |
| `ASTROLABE_LONG_MAX_TOKENS` | `8192` | Token cap for `long-generation`. |
| `ASTROLABE_LONG_MIN_SECONDS` | `300` | Floor used by the long-generation helper. |
| `ASTROLABE_LONG_MAX_FIRST_BYTE` | `30` | First-byte wait used by the long-generation helper. |

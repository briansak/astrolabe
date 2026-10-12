# Install

Astrolabe 0.1.0 installs from a git checkout with `./astrolabe up`. Weights are not in the repository.

## Prerequisites

- Apple Silicon Mac. Linux socket paths exist under `$XDG_RUNTIME_DIR` and are not release-tested. Windows is not an operator host.
- Docker Desktop, with the daemon running.
- Python 3.11 or newer. `./astrolabe` creates `.venv` in the checkout.
- git, for clone intake.
- Pango for PDF rendering. On macOS: `brew install pango`. Without Pango or WeasyPrint, assessment HTML is still written and the report page says the PDF was not produced.
- A Hugging Face account that has accepted the gate for [`fdtn-ai/antares-1b`](https://huggingface.co/fdtn-ai/antares-1b). IBM Granite 4.0 is the Antares-1B base model, and its terms apply. Accept them before you download the weights.

## Checkout

```bash
git clone https://github.com/briansak/astrolabe.git
cd astrolabe
```

Request access at [fdtn-ai/antares-1b](https://huggingface.co/fdtn-ai/antares-1b), download the model, and put it in `./models/1b`. That directory needs `model.safetensors`, `config.json`, and `antares-cli.zip`.

```bash
./astrolabe up
```

`up` does five things:

1. Creates `.venv` if it is missing and installs this checkout and `services/antares-server` when `pyproject.toml` or the server package changed.
2. Checks that Docker is running. If it is not, it says `Start Docker Desktop, then rerun ./astrolabe up.` and exits.
3. Resolves weights in this order: `--model-path`, `ANTARES_MODEL_PATH`, the path saved by setup, then `./models/1b`. A directory counts when it contains `model.safetensors`, `config.json`, and `antares-cli.zip`.
4. Runs setup when the saved path differs or the sandbox image was not built from that zip. The image records the zip SHA-256 in the label `ai.astrolabe.cli-zip-sha256`. A matching image skips the build.
5. Runs doctor. A required check that is missing stops `up` and prints the fix. The inference socket is not present until the server starts, so that one row does not stop `up`. Then it starts the inference server and the UI in the background and prints `http://127.0.0.1:8765/`.

PIDs are written under `~/Astrolabe/var/run`. Logs are written under `~/Astrolabe/var/log`.

```bash
./astrolabe up --port 8765
./astrolabe up --foreground
```

`--foreground` keeps the current `start` behavior: the UI stays in this terminal, and Ctrl-C stops the UI and the inference server.

If Astrolabe is already running, `up` prints the URL and exits 0.

On first run, installation prints that it contacts PyPI. The image build prints the hosts it contacts: Docker Hub, ghcr.io, Debian, and PyPI.

## Download the weights

Request access at [fdtn-ai/antares-1b](https://huggingface.co/fdtn-ai/antares-1b), download the model, and put it in `./models/1b`. `up` also looks at `--model-path`, `ANTARES_MODEL_PATH`, and the path saved by setup before that directory. After access is granted, `up` can download into `./models/1b` instead of a manual copy.

```bash
./astrolabe up --download-weights
```

Without that flag, an interactive terminal asks `Download Antares-1B into ./models/1b? [y/N]`. Anything other than yes leaves the weights unfetched. A non-interactive run without the flag prints the gate URL and the expected directory, and does not download.

The download uses the Hugging Face login already on this machine (`hf auth login`, or `huggingface-cli login`). Astrolabe does not store the token and does not print it. If no login is present, `up` tells you to log in.

`./models/1b` is gitignored. The server also expects the tokenizer files that ship with the model (`tokenizer.json`, `tokenizer_config.json`, `generation_config.json`, and `chat_template.jinja`). A full hub download includes them.

The pinned SHA-256 of `model.safetensors` is `6ba4155a50cd0cede3e10285b0d84b460dcc3caa0175a424e14d3bb606fda675`. Setup checks it.

`scripts/stage-antares-1b.sh` remains an optional helper. It reads `HF_TOKEN` from the environment and does not write the token into the tree. `up` does not use that script.

## Use weights you already have

```bash
./astrolabe up --model-path /path/to/weights
```

`ANTARES_MODEL_PATH` is the next choice. After a successful setup, the path is stored at mode 0600:

- macOS: `~/Library/Application Support/Astrolabe/config.toml`
- Linux: `$XDG_CONFIG_HOME/astrolabe/config.toml`, or `~/.config/astrolabe/config.toml`

The directory must contain `model.safetensors`, `config.json`, and `antares-cli.zip`.

## Preparing advisories offline

On a networked machine, sync the cache without an engagement, then copy that directory to the offline machine and import it. Import does not use the network and does not take `--engagement`.

```bash
astrolabe advisories sync --id CVE-2024-0001 --actor NAME --cache /path/to/advisory-cache
astrolabe advisories import /path/to/advisory-cache --cache ~/Astrolabe/advisories
```

The cache-level sync records the actor as given. Its audit line has no engagement id and scope `advisory_cache`.

## Network use

- Installing the checkout contacts PyPI for Python dependencies, including torch and transformers.
- The sandbox image build contacts Docker Hub (`python:3.12.11-slim-bookworm`), ghcr.io (`ghcr.io/astral-sh/uv:0.9.7@sha256:ba4857bf2a068e9bc0e64eed8563b065908a4cd6bfb66b531a9c424c8e25e142`), Debian, and PyPI.
- A consented weights download contacts Hugging Face.
- After that, runtime network use is advisory sync and git clone.

The Dockerfile is otherwise unchanged. The `uv` image is pinned by that digest.

## status, doctor, logs, down

```bash
./astrolabe status
./astrolabe doctor
./astrolabe logs
./astrolabe logs --follow
./astrolabe down
```

`status` prints `running` or `stopped`, the URL, and the doctor rows. `doctor` prints one row per Status check: name, status, location, and fix. It exits nonzero when a required check is missing. A warn, including an empty advisory cache or PDF rendering, does not by itself fail doctor.

`logs` prints `inference.log` and `ui.log`. `--follow` keeps printing new lines until Ctrl-C.

`down` reads the PID files and signals each process only after checking that it is still an Astrolabe process. A PID that belongs to something else is left alone.

## setup and start

`up` calls the same setup and start steps. You can still run them yourself:

```bash
astrolabe setup --model-path /path/to/weights
astrolabe doctor
astrolabe start
astrolabe start --port 8765
```

Setup checks `model.safetensors` and `config.json`, runs the weight SHA-256 check, and reads `antares-cli.zip` from that same directory. It then creates the per-user socket and token directories at mode 0700 and writes the model path. Setup does not write inside the engagements directory. Running it again is safe. Setup always builds the image. `up` skips that build when the image label matches the zip.

`start` launches the inference server, waits until `GET /health` on the Unix socket returns status ok, then serves the UI on `127.0.0.1`. Ctrl-C stops both. If the port is in use, start refuses and names the process when `lsof` can see it.

`ANTARES_MODEL_PATH` overrides the path stored by setup.

## Existing engagement data

New installs use `~/Astrolabe/engagements`. The audit log is then `~/Astrolabe/var/audit.jsonl`. The advisory cache is `~/Astrolabe/advisories`.

If your engagements already live somewhere else, set `ASTROLABE_ENGAGEMENTS_DIR` to that directory before `doctor` or `start`. The audit log default is the parent of that directory plus `var/audit.jsonl`. Set `ASTROLABE_AUDIT_LOG` when the log should stay at its old path. See [configuration.md](configuration.md).

## Install from a release wheel

Verify `dist/SHA256SUMS`, then install with pipx. A wheel install does not use `./astrolabe`.

```bash
cd dist
shasum -a 256 -c SHA256SUMS
pipx install --pip-args '--find-links ./dist' './dist/astrolabe-0.1.0-py3-none-any.whl[inference]'
astrolabe setup --model-path /path/to/weights
astrolabe doctor
astrolabe start
```

`--find-links` adds `dist/` as a place to find the Astrolabe wheels. It does not pass `--no-index`. pip still downloads torch, transformers, FastAPI, uvicorn, pydantic, WeasyPrint, and their dependencies from PyPI.

The `inference` extra installs `astrolabe-antares-server`, which depends on `astrolabe`. Bring the weights yourself for a wheel install. `astrolabe setup` does not download them.

## Upgrading

For a checkout, pull and run `./astrolabe up` again. For a wheel, install the new wheel the same way. Setup can be run again. Finalized reports stay as they were written. Regenerating a final assessment is refused.

## Uninstalling

`pipx uninstall astrolabe` removes a wheel install and the packages pipx installed for it. A checkout uninstall is deleting the clone. `.venv` is inside the clone.

These stay on disk:

- `~/Astrolabe/engagements` and `~/Astrolabe/var`
- `~/Astrolabe/advisories`
- `~/Astrolabe/exports`
- `~/Library/Application Support/Astrolabe/` (config, socket, tokens) or the Linux XDG directories
- the Docker image `astrolabe-antares-cli:1`
- the weights directory you chose

Delete those yourself when you want them gone. Purge one engagement from the UI or with `astrolabe purge` before you delete the tree by hand, so the audit line is written.

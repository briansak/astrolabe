# Troubleshooting

`astrolabe doctor` prints the same rows as the Status menu: name, status, location, and fix. A required row in `missing` makes doctor exit nonzero. `warn` does not.

## Docker daemon

`missing` means `docker` is not on `PATH` or the daemon did not answer `docker version`. Start Docker Desktop, or the daemon, and run doctor again.

## Sandbox image

`missing` means `astrolabe-antares-cli:1` is not local. Run `astrolabe setup --model-path DIR` so the image is built from `<DIR>/antares-cli.zip`. The build contacts Docker Hub, ghcr.io, Debian, and PyPI.

## Inference socket

`missing` means the socket file is absent or `/health` did not return status ok. Start the server with `astrolabe start`, or start it on its own with `python -m antares_server` after the model path is configured.

If the two socket variables disagree, doctor prints both paths. Set `ANTARES_SOCKET` and `ASTROLABE_INFERENCE_SOCKET` to the same path, or unset both to use the default.

A path inside the engagements directory is refused:

`Socket directory <path> is inside the engagements directory <root>. Use <default> instead.`

The same sentence is used for the token directory, with that label. Point the variables at the per-user defaults, not at an engagement folder.

Other refusals:

- `<directory> is not owned by the current user` or `is group or world accessible`. `chmod 700` that directory, or unset the variable.
- `<path> is not a socket owned by the current user. Refusing to replace it.`
- `Token directory <tokens> is inside the socket directory <run>.`
- `Socket path <path> is <n> bytes and exceeds the <limit>-byte sun_path limit.`
- `<base> does not exist and XDG_RUNTIME_DIR is unset.` Set `XDG_RUNTIME_DIR`, or set both a socket variable and a token variable to paths outside `/run/user`.

## Token directory

`missing` means the directory is absent, too open, or disagrees with the paired variable. `astrolabe setup` and `astrolabe start` create it at mode 0700 when the path is allowed. `chmod 700` an existing directory that is group or world accessible.

## Antares-1B weights

`missing` means the model path is unset or `model.safetensors` / `config.json` are not in that directory. Run `astrolabe setup --model-path DIR`, or export `ANTARES_MODEL_PATH`. Setup also checks the SHA-256. A mismatch stops setup. Doctor only checks that the files are present.

## CWE data

`missing` means the installed package has no readable `cwe-relations.json`. Reinstall the wheel. Do not point this at a checkout path.

## Engagement paths

`missing` means the engagements directory or the audit-log parent is not writable, or the audit log resolves inside the engagements directory. Create the parent, or set `ASTROLABE_ENGAGEMENTS_DIR` and `ASTROLABE_AUDIT_LOG` so the log stays outside the engagements root.

## git

`missing` means `git` is not on `PATH`. Install git. Clone intake needs it. Local folder intake does not.

## Advisory cache

`warn` means the cache directory has no JSON files. Import advisories with `astrolabe advisories import DIR`. An empty cache does not fail doctor. A check that names a missing advisory id fails closed.

## PDF rendering

`warn` means WeasyPrint is not installed or Pango was not found. On macOS, `brew install pango`. Assessment generation still writes HTML. The report page says "The PDF was not produced." This row does not fail doctor and does not mark the UI as not ready.

## Port in use

`astrolabe start` refuses to bind the UI port when something is already listening. It names the process when `lsof` can see it: `Port 8765 is in use by <name> (pid <pid>).` Stop that process or pass `--port` with a free port. The inference socket is not the UI port.

## Docker not running

Image build and every investigation need the daemon. Doctor shows Docker daemon as missing. Start the daemon and run setup again if the image was never built.

## Refused socket or token directory

Read the sentence doctor prints. The usual fix is to unset `ANTARES_SOCKET`, `ASTROLABE_INFERENCE_SOCKET`, `ANTARES_TOKEN_DIR`, and `ASTROLABE_TOKEN_DIR` so the per-user defaults are used, then `chmod 700` those directories if they already exist and are too open. Do not put either directory inside `~/Astrolabe/engagements`.

## Stalled runs

The running check shows a stall when no activity arrives for `ASTROLABE_ACTIVITY_STALL_SECONDS` (default 60). The counters and the last phase stay visible. A stall is not a finished run. Cancel if you want the container removed, then start that check again.

## Export refused

A draft export is refused unless `--allow-draft` is set. Check mode refuses an archive whose assessment bytes do not match the finalized files. The error names the file and the finding. Fix the report and finalize again. Do not edit the finalized HTML by hand and expect the next export to pass.

Purge is refused while export archives for that engagement are still under `~/Astrolabe/exports`, until you confirm they have been handled.

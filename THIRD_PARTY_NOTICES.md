# Third-party notices

Astrolabe is an independent project. It is not a Cisco product, and Cisco has not endorsed it.

Antares-1B is a third-party model published by Cisco Foundation AI at `fdtn-ai/antares-1b`. Foundation-Sec is a separate third-party model from Cisco Foundation AI. Astrolabe does not download, bundle, or run Foundation-Sec.

Antares-1B uses IBM Granite 4.0 as its base model. Granite's own terms apply to that base model. Accept them before you download the weights.

Astrolabe does not redistribute the components below. Operators stage the model and the CLI locally.

## Antares CLI

- Source: the `antares-cli.zip` artifact published with the gated Hugging Face repository `fdtn-ai/antares-1b`
- License: Apache License 2.0
- Use: installed inside the engagement container with `uv`, from the zip. The extracted tree is not committed.

The CLI also ships a derived snapshot of the MITRE CWE taxonomy under MITRE's terms. Those terms apply only to that CWE-derived content and are reproduced in the CLI's own `THIRD_PARTY_NOTICES.md`.

## CWE mitigation dictionary

`astrolabe/data/cwe/cwe-dictionary.json` is a derived snapshot of CWE names and potential mitigations from the Antares CLI's CWE database, kept so assessment reports can cite mitigations without a network lookup. The MITRE copyright designation and license are in `astrolabe/data/cwe/CWE_NOTICE.txt` and apply to that file.

## Antares-1B weights

- Source: `fdtn-ai/antares-1b` (`model.safetensors`)
- License: Apache License 2.0
- Use: staged under `models/1b` or `ANTARES_MODEL_PATH`, verified by SHA256 `6ba4155a50cd0cede3e10285b0d84b460dcc3caa0175a424e14d3bb606fda675`. Weights are gitignored.

## WeasyPrint

- Source: the `weasyprint` package (CourtBouillon)
- License: BSD 3-Clause
- Use: renders the assessment PDF from the assessment HTML so the two share one layout. Installed as a dependency. It is not vendored. It needs Pango, Cairo, and GLib, which are system libraries and are not shipped here.

## Python dependencies

These packages are installed from PyPI and are not vendored. Transitive dependencies are under their own licenses.

- FastAPI: MIT
- uvicorn: BSD-3-Clause
- pydantic: MIT
- torch: Apache-2.0, and also Apache-2.0 WITH LLVM-exception, BSD-2-Clause, BSD-3-Clause, BSL-1.0, and MIT
- transformers: Apache-2.0

The host inference process loads the staged checkpoint with PyTorch and Transformers.

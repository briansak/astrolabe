# Contributing

## Tests

From a checkout, with Python 3.11 or newer:

```bash
python -m pip install -e . pytest
python -m pytest
```

Pytest uses `testpaths = ["tests"]`, so a run from the repository root does not collect anything outside `tests/`. Docker and the model are stubbed in those tests. Do not download weights or start the model to run them.

## What never goes in the tree

Do not commit model weights, engagement data, or internal docs. That includes:

- `models/`
- `engagements/`
- `var/`
- `data/advisories/`
- `docs/HANDOFF.md`
- `validation/`

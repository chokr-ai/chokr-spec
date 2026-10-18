# Contributing

Issues and pull requests are welcome. For a larger change, open an issue first so the design can be discussed.

## Set up

Python 3.14 or newer and [uv](https://docs.astral.sh/uv/).

```bash
uv sync --all-groups
```

## Checks

CI runs these; run them before opening a pull request.

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run lint-imports
uv run python tools/check_spec.py
uv run pytest --cov
uv run chokr-spec check
```

## Pull requests

- Keep a pull request to one change, with tests for new behaviour.
- A change to a schema, registry or vector must keep `tools/check_spec.py` and `chokr-spec check` passing. A published
  code never changes meaning.
- Report security problems privately, as described in [SECURITY.md](SECURITY.md).

By contributing you agree that your contribution is licensed under the Apache License 2.0.

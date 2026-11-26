# Contributing to Metis

We welcome contributions to **Metis** — whether it's fixing bugs, improving documentation or adding new features.

## Getting Started

1. Fork the repo and clone your fork:

```bash
git clone https://github.com/arm/metis.git
cd metis
```

2. Install dependencies:

```bash
uv venv --python 3.12
uv pip install -e '.[dev]'
uv run --no-sync pre-commit install
```

Install the PostgreSQL extra only when working on that backend:

```bash
uv pip install -e '.[postgres]'
```

3. Run tests to ensure everything is working:

```bash
uv run --no-sync pytest
```

`pytest.ini` supplies the standard quiet/reporting options. Real PostgreSQL
integration tests are skipped unless explicitly enabled with `--postgres` and a
local service; mocked backend tests run normally.

## License Headers

Preserve existing SPDX headers. New Python source and test files must include the
standard Apache-2.0 header; copy the format from a neighboring file of the same
type.

## Submitting a PR

- Make sure your branch is up to date with main
- Keep PRs focused and include tests where appropriate
- Use Conventional Commit subjects consistent with repository history, such as
  `feat(scope):`, `fix(scope):`, `refactor(scope):`, or `chore(scope):`


## Testing Strategy

Run the smallest focused test while developing:

```bash
uv run --no-sync pytest tests/test_configuration.py
uv run --no-sync ruff check src/metis/configuration.py tests/test_configuration.py
uv run --no-sync ruff format --check src/metis/configuration.py tests/test_configuration.py
```

Replace those paths with the files for your change. Commit hooks run lint and
hygiene checks only; the full test suite and coverage run explicitly at the
`manual` stage. No `SKIP` setting is needed for normal commits or focused hook
runs.

Before submitting when the worktree contains no unrelated changes, run both
commands below. CI runs these as separate steps:

```bash
uv run --no-sync pre-commit run --all-files --show-diff-on-failure
uv run --no-sync pre-commit run --hook-stage manual 'Test Coverage' --all-files --show-diff-on-failure
```

The configured hooks and CI workflow are the authority for current checks and
supported test environments. Some hooks modify files; inspect the diff and
rerun. CodeQL provides additional security analysis.

Temporary-repository fixtures must clear inherited repository-local Git variables
before running Git or Metis. The `openai_cli` fixture uses
`git rev-parse --local-env-vars` to isolate its repository from enclosing hooks,
including hooks that use a private index. Git stderr remains visible in pytest
failure output.

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
uv pip install -e '.[dev,postgres]'
pre-commit install
```

3.	Run tests to ensure everything is working:

```bash
uv run pytest
```

## License Headers

All files must include the standard Apache 2.0 license header.

## Submitting a PR

- Make sure your branch is up to date with main
- Keep PRs focused and include tests where appropriate
- Use descriptive commit messages


## Testing Strategy

As part of CI, Metis runs automated security and quality checks:
 - Static Analysis: bandit is used to detect common security issues in Python code.
 - Code Style & Formatting: black is used to enforce code quality and consistency.
 - Dependency Checks: Dependabot
 - Contributions must pass all CI checks to be accepted.

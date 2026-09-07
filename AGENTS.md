<!--
SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
SPDX-License-Identifier: Apache-2.0
-->

# AGENTS.md

Repository-wide rules for coding agents; human contributors start with
[CONTRIBUTION.md](CONTRIBUTION.md). Metis is a Python 3.12+ security-review CLI
built around a typed execution graph.

## Working rules

- Read the owning code, callers, focused tests, and routed guide before editing.
  Search for existing contracts and fix shared behavior once at its owner.
- Keep changes focused; do not add speculative abstractions or compatibility
  layers. Preserve published imports, entry points, configuration keys, YAML
  names, ports, and types unless intentionally making a versioned breaking
  change; external callers need not appear in this repository.
- Update the relevant README, guide, and examples in the same change whenever
  user-visible behavior, configuration, CLI, output formats, extension contracts,
  or supported features change. Update this router when an owner moves.
- `MetisEngine` owns composition and lifecycle; stages own typed workflow
  boundaries; nodes own selectable behavior. Generic graph code must not name
  built-in-specific nodes; terminal `result` is a shared graph convention.
- Treat model, tool, extension, repository/file, network, subprocess, SARIF, and
  persisted-data results as untrusted. When adding or changing a boundary,
  validate and bound data before it controls paths, commands, persistence, or
  publication.
- Durable Metis-owned replacement and migration must validate first and preserve
  the prior readable state on failure.
- Use engine-owned scheduling, cancellation, and cleanup for graph work.
  Propagate `concurrent.futures.CancelledError`, use finite network/subprocess
  timeouts, and drain or join owned work before returning.
- Preserve unrelated worktree changes. Do not discard, stash, broadly reformat,
  stage, commit, amend, or force-add ignored output unless the user asks.
- Keep tests and examples offline and credential-free. Installed extensions run
  inside the Metis process; installation and selection are trust decisions.

## Route by task

| Task | Read first |
| --- | --- |
| Built-in node or stage | [Built-in execution components](docs/contributing/adding-execution-component.md) |
| Separately distributed node or stage | [External nodes and stages](docs/execution-graph.md#adding-external-nodes-and-stages) |
| Execution YAML, ports, status, scheduling | [Execution graph](docs/execution-graph.md) |
| Capability | [Capabilities](docs/capabilities/README.md) and [adding a capability](docs/capabilities/adding-capability.md) |
| Model-tool adapter or loop | `src/metis/engine/tools/`, `src/metis/engine/model_tool_runner.py`, `tests/test_model_tool_runner.py`, and the consuming capability's guide |
| Language plugin | [Language plugins](docs/language-plugins.md); for CodeGraph support also read the [provider](docs/execution-graph.md#codegraph-provider-contract) and [semantics](docs/execution-graph.md#codegraph-semantics-contract) contracts |
| Model provider | [Adding a provider](docs/providers/adding-new-provider.md), plus the matching provider guide when present |
| Shared configuration/defaults | [README configuration](README.md#configuration), `src/metis/configuration.py`, `src/metis/metis.yaml`, and `tests/test_configuration.py` |
| CLI flag or interactive command | `src/metis/cli/entry.py`, `src/metis/cli/command_registry.py`, `src/metis/cli/commands.py`, [README CLI](README.md#running-metis), `tests/test_cli_entry.py`, `tests/test_cli_commands.py`, and `tests/test_cli_e2e.py` |
| Export format or SARIF identity | `src/metis/engine/execution/contracts.py`, `src/metis/cli/exporters.py`, `src/metis/cli/utils.py`, `src/metis/cli/entry.py`, `src/metis/json_io.py`, `src/metis/sarif/`, `tests/test_cli_exporters.py`, `tests/test_cli_output_paths.py`, `tests/test_json_io.py`, and `tests/test_sarif.py` |
| Execution facade or entry-point contract | Its extension guide, `tests/test_public_imports.py`, `tests/test_execution_node_api.py`, `tests/test_execution_stage_api.py`, and extension-wheel discovery in `tests/test_execution_e2e.py` |
| Repository memory | [Repository memory](docs/repository-memory.md) |
| Vector backend/indexing | [Index capability](docs/capabilities/index.md), [embedding provider](docs/providers/embedding-provider.md), `src/metis/vector_store/`, `src/metis/cli/entry.py`, and `src/metis/cli/utils.py` |
| Compilation profile | [Compilation profiles](docs/config/compilation_profile.md) |
| Review path selection | [Review paths](docs/config/review_code_paths.md) |
| Triage behavior | [Triage flow](docs/triage-flow.md) |
| Run log | [Run-log format](docs/workflow-log-format.md), `src/metis/runlog/`, and `tests/test_runlog.py` |
| Usage accounting | `src/metis/usage/`, `tests/test_usage.py`, and `tests/test_cli_usage.py` |
| Engine composition or lifecycle | `src/metis/engine/core.py`, `src/metis/engine/nodes/builtins.py`, `tests/test_engine_core.py`, and `tests/test_engine_lifecycle.py` |
| Model invocation or retry policy | `src/metis/engine/llm_runner.py`, `src/metis/chat_model_options.py`, and `tests/test_llm_runner_retry.py` |
| Setup, tests, or contribution workflow | [Contributing](CONTRIBUTION.md) |

## Editing and verification

- Preserve existing SPDX headers; use the nearest same-type file's header format
  for new source files. Keep Python 3.12 compatibility and one import per line.
- Follow the owning API's exception, typing, and validation conventions. Reuse
  Pydantic where that boundary already uses it; validate explicitly otherwise.
- For behavior changes, add the closest observable test and a relevant failure
  case when the changed contract has one. Add cross-boundary tests only for
  contracts the change touches.
- Run focused pytest plus non-mutating Ruff checks first:

```bash
uv run --no-sync pytest tests/test_configuration.py
uv run --no-sync ruff check src/metis/configuration.py tests/test_configuration.py
uv run --no-sync ruff format --check src/metis/configuration.py tests/test_configuration.py
```

Replace those paths with task-owned files. `--no-sync` assumes the environment
already reflects `pyproject.toml`; reinstall or build before checking dependency
or entry-point changes. Pre-commit includes mutating hooks, so run it only on
task-owned files:

```bash
SKIP='Test Coverage' uv run --no-sync pre-commit run --files src/metis/configuration.py tests/test_configuration.py
```

Use [CONTRIBUTION.md](CONTRIBUTION.md) for the full repository check. Inspect
changes made by hooks and rerun. Report checks that could not be run.
Do not commit unless asked; when asked, follow the repository's Conventional
Commit style.

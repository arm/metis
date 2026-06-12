# Adding a Metis Tool

This guide shows the files to add or update when introducing a new Metis tool.

## 1. Choose the Enablement Name

Pick the name users will pass to `--tools`.

Examples:

- `navigation`
- `index`
- `tree_sitter`
- `testname`

Use lowercase letters, numbers, and underscores. Keep the name stable; command
scripts and configs may depend on it.

## 2. Add a Manifest

Create `src/metis/engine/tools/manifests/<tool-name>.yaml`.

Minimal shape:

```yaml
schema_version: 1
name: testname
title: Example Tool
description: Example analysis tool.
implementation: metis.engine.tools.example:ExampleTool
visibility: private
status: active
default_enabled: false
contracts:
  model: ./tools/testname/contract.md
config:
  timeout_seconds: 30
capabilities:
  - id: testname.analyze
    name: testname_analyze
    title: Analyze input
    description: Run bounded analysis for a file or symbol.
    surfaces: [orchestration]
    domains: [triage_evidence]
    provider: testname
    operation: analyze
    status: active
```

Required fields:

- `name`: the `--tools` enablement name.
- `status`: `active` tools are accepted by `--tools`; `planned` tools are not.
- `default_enabled`: whether the tool is enabled when `--tools` is omitted.
- `contracts.model`: model-facing usage and output interpretation guidance.
- `capabilities`: operations exposed by the tool.

Use `config` for tool-owned runtime defaults. Do not put these constants in
Python unless they are true code fallbacks.

For model-callable tools, put model-loop settings under `config.model_tool`.
For example, `max_rounds` controls how many tool-call turns the model may take
before it must produce a final answer, and `max_contract_chars` controls how
much of the model-facing contract is injected into the system prompt.

## 3. Add the Contract

For built-in tools, add `src/metis/engine/tools/contracts/<tool-name>.md` and
package it through `pyproject.toml`.

```toml
package-data."metis.engine.tools.contracts" = [ "*.md" ]
```

Contract contents should cover:

- what each capability does;
- when the model or orchestrator should use it;
- input fields and limits;
- output sections and how to interpret them;
- security boundaries and failure behavior.

For repo-local private tools, `contracts.model` can point to a local path instead
of `package://...`.

## 4. Implement the Runtime Tool

Place built-in runtime code under `src/metis/engine/tools/`.

For model-callable tools, expose LangChain tools from the runtime wrapper:

```python
from langchain_core.tools import StructuredTool


class ExampleTool:
    name = "testname"

    def langchain_tools(self) -> tuple[StructuredTool, ...]:
        return (
            StructuredTool.from_function(
                func=self.analyze,
                name="testname_analyze",
                description="Run bounded example analysis.",
                args_schema=ExampleAnalyzeInput,
            ),
        )
```

For orchestration-only tools, expose methods that services or graph nodes can
call directly. Keep filesystem, timeout, and output clipping inside the tool
implementation.

## 5. Register Engine Access

Add the tool to `EngineTools` in `src/metis/engine/tools/engine.py`.

For a tool that follows the `IndexTool` pattern:

1. Add a `build_<tool>_tool(...)` factory.
2. Return a disabled `ToolHandle` when `tool_enabled(config.enabled_tools, name)`
   is false.
3. Include the enabled tool in `EngineTools.langchain_tools()` if it exposes
   model-callable capabilities.
4. Close any owned resources in `EngineTools.close()`.

Do not initialize heavy resources just because the tool is enabled. Defer work
until a command or model call actually uses the capability.

## 6. Wire Command or Graph Usage

Choose the smallest surface that needs the tool:

- CLI command gate: add `required_tools=(TOOL_NAME,)` in
  `src/metis/cli/command_registry.py`.
- Optional command context: add `optional_tools=(TOOL_NAME,)`.
- Deterministic graph step: inject the tool into the graph/service constructor.
- Model-callable use: pass `engine.tools.langchain_tools()` into the graph's
  `JsonPromptRunner` request.

If disabling the tool would make a command misleading, fail fast with a clear
required-tool error instead of silently producing weak output.

## 7. Add Tests

Add or update tests for:

- manifest discovery and `--tools` enablement;
- active vs planned status;
- contract loading from `contracts.model`;
- disabled-tool behavior;
- runtime method behavior and output clipping;
- LangChain tool exposure if `surfaces` includes `model_tool`;
- graph or command wiring.

Useful existing test files:

- `tests/test_engine_tools_selection.py`
- `tests/test_tool_registry.py`
- `tests/test_engine_core.py`
- `tests/test_llm_runner.py`
- `tests/test_cli_entry.py`

## 8. Verify

Run at least:

```bash
uv run ruff check src/metis tests
uv run pytest -q tests/test_engine_tools_selection.py tests/test_tool_registry.py
```

Then run the focused tests for the command or graph you touched.

Do not mark a tool `active` until its manifest, contract, runtime wiring, and
tests are all present.

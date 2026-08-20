# Adding a Metis Capability

This guide covers built-in and separately distributed shared capabilities.
Model-callable operations use the separate `metis.engine.tools` infrastructure;
granting a capability does not automatically give an agent new model tools.

## 1. Choose the Capability Name

Pick the stable name used by node declarations, execution YAML, configuration,
and the capability registration.

Examples:

- `navigation`
- `index`
- `private_analysis`

Use a valid lowercase Python identifier and keep it stable.

## 2. Define the Registration

Each capability entry point exposes one `CapabilityRegistration`. A package
may publish several capabilities through separate entry points. Each
registration's Pydantic model owns the configuration under
`metis_engine.capabilities.<name>`, and its factory constructs the shared
runtime object:

```python
from typing import cast

from pydantic import BaseModel, ConfigDict, Field

from metis.capabilities import CapabilityContext
from metis.capabilities import CapabilityManifest
from metis.capabilities import CapabilityRegistration


class Configuration(BaseModel):
    timeout_seconds: int = Field(gt=0)

    model_config = ConfigDict(extra="forbid", frozen=True)


class PrivateAnalysis:
    def __init__(self, context: CapabilityContext, timeout_seconds: int) -> None:
        self.codebase_path = context.codebase_path
        self.timeout_seconds = timeout_seconds

    def lookup(self, symbol: str) -> str:
        return f"Evidence for {symbol}"

    def close(self) -> None:
        ...


def create(context: CapabilityContext, raw: BaseModel) -> PrivateAnalysis:
    configuration = cast(Configuration, raw)
    return PrivateAnalysis(context, configuration.timeout_seconds)


def close(capability: object) -> None:
    if isinstance(capability, PrivateAnalysis):
        capability.close()


registration = CapabilityRegistration(
    manifest=CapabilityManifest(name="private_analysis"),
    configuration=Configuration,
    factory=create,
    close=close,
)
```

Omit `close` when the capability owns no resource. Otherwise, the callback
receives the constructed capability and must release its files, clients, or
processes. Metis calls registered callbacks in reverse construction order.

The factory context deliberately contains only the codebase path, read-only
repository lookups, and shared worker/token limits. It does not expose model
providers, memory, secrets, or Metis's internal engine configuration.

Register the object from the package metadata:

```toml
[project.entry-points."metis.capabilities"]
private_analysis = "external_metis_capabilities.analysis:registration"
```

The entry-point name must match the registration and manifest name. A package
may contain both external nodes and external capabilities.

## 3. Describe Operations When Needed

The minimal manifest needs only the stable name. When a node exposes capability
operations through a model-tool adapter, replace that minimal manifest with
operation metadata and a packaged model contract:

```python
from metis.capabilities import CapabilityManifest
from metis.capabilities import CapabilityOperationManifest


CapabilityManifest(
    name="private_analysis",
    contracts={"model": "package://external_metis_capabilities/analysis.md"},
    operations=(
        CapabilityOperationManifest(
            id="private_analysis.lookup",
            name="private_analysis_lookup",
            description="Look up deterministic private-analysis evidence.",
            surfaces=("model_tool",),
            operation="lookup",
            input_schema={
                "type": "object",
                "properties": {
                    "symbol": {
                        "type": "string",
                        "description": "Exact symbol to look up.",
                    }
                },
                "required": ["symbol"],
                "additionalProperties": False,
            },
        ),
    ),
)
```

Operation metadata describes:

- what each operation does;
- which orchestration or model-tool surfaces expose it;
- its model-visible input schema.

Put input limits in that schema and put behavioral, security, and failure rules
in the packaged model contract.

For model-callable operations, define the model-visible JSON Schema in the
operation's `input_schema` mapping. This keeps field names, descriptions,
limits, and examples reviewable separately from the runtime implementation.

Operation metadata is descriptive; it does not create a Tool. Metis currently
provides engine-owned model-tool adapters for the built-in Index and Navigation
capabilities. A separately distributed capability can be used directly by its
node for deterministic orchestration. If its package also exposes the operation
to a model, that package owns the adapter and its LangChain dependency; Metis
does not yet expose a generic public adapter factory.

Runtime settings belong in the selected `metis.yaml`, separate from execution
topology. Add the new capability alongside the existing configured capability
sections:

```yaml
metis_engine:
  model_tools:
    max_rounds: 6
    max_contract_chars: 6000
  capabilities:
    private_analysis:
      timeout_seconds: 30
```

Shared model-tool policy belongs under `model_tools`; capability-specific
settings belong under `capabilities.<name>`. The execution graph only selects
nodes, connects their inputs and outputs, and grants capabilities.

Memory is the one built-in exception: its existing storage configuration stays
in the top-level `memory` section and `metis_engine.capabilities.memory` is
rejected.

Keep the capability implementation independent of LangChain. For
orchestration-only operations, the node calls the granted object directly.
Keep filesystem, timeout, and output clipping inside the capability
implementation.

## 4. Grant the Capability

Choose the smallest surface that needs the capability:

- Declare the capability as required or optional in the node registration.
- Add the capability name to that node's YAML `capabilities` allowlist when it
  should be granted.
- Resolve deterministic and model-callable operations from the granted object
  in `invocation.context.capabilities`.

```yaml
metis_engine:
  capabilities:
    private_analysis:
      timeout_seconds: 30
  execution:
    stages:
      review:
        nodes:
          external_review:
            capabilities:
              - private_analysis
```

Configuration alone does not activate the capability. Metis imports, validates,
and constructs it only after a selected node has declared and been granted it.
Direct commands may explicitly request their built-in capability. Invalid
selected configuration or construction fails startup. Registered close
callbacks run in reverse construction order when the engine closes.

For a built-in capability, place its implementation and registration under
`src/metis/engine/capabilities/` and add its registration to the built-in list.
External capabilities require no changes to Metis source.

## 5. Add Tests

Add or update tests for:

- the entry point is not imported when ungranted;
- configuration validation and construction when granted;
- node access through `invocation.context.capabilities`;
- lifecycle cleanup for owned resources;
- model-tool exposure when the node intentionally provides it.

Useful existing test files:

- `tests/test_navigation_capability.py`
- `tests/test_engine_core.py`
- `tests/test_model_tool_runner.py`
- `tests/test_cli_entry.py`

## 6. Verify

Run at least:

```bash
uv run ruff check src/metis tests
uv run pytest -q tests/test_navigation_capability.py tests/test_engine_core.py
```

Then run the focused tests for the command or graph you touched.

Publish an active registration only after its manifest, runtime wiring,
contracts, and tests are present.

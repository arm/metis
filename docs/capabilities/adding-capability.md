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

## 2. Define an External Registration

Built-in capabilities use the in-tree checklist under [Grant the capability](#4-grant-the-capability).

Each capability entry point exposes one `CapabilityRegistration`. A package
may publish several capabilities through separate entry points. Each
registration's Pydantic model owns the configuration under
`metis_engine.capabilities.<name>`, and its factory constructs the shared
runtime object:

```python
from typing import cast

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field

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
    assert isinstance(capability, PrivateAnalysis)
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
If a factory acquires a resource and then raises before returning, the factory
must clean it up itself; the registered closer is recorded only after successful
construction.

The public typed factory context exposes only the codebase path, read-only
repository lookups, and shared worker/token limits. It does not expose model
providers, memory, secrets, or Metis's internal engine configuration through
that API. Installed capabilities still execute in-process and are trusted, not
sandboxed.

Register the object from the package metadata:

```toml
[project.entry-points."metis.capabilities"]
private_analysis = "external_metis_capabilities.analysis:registration"
```

The entry-point name must match the registration and manifest name. A package
may contain both external nodes and external capabilities.

## Thread safety and lifetime

One engine shares a constructed capability across its nodes and job workers,
including concurrent graph executions. Factory construction is synchronized;
method calls are not. Make operations safe for concurrent use: protect mutable
state with an instance lock, use a thread-safe client, or serialize access to a
client that requires it. Read-only data may be shared. Keep invocation-specific
state in the caller and never mutate borrowed node inputs.

Do not hold a state lock while invoking caller callbacks or waiting for engine
work that may need the same lock. Use finite I/O and subprocess timeouts, and
cooperate with the calling node's cancellation signal. Background work must be
joined before the operation returns; a returned operation must not keep using a
capability that the engine can then close.

Engine shutdown drains its active nodes and jobs before invoking capability
closers, once, in reverse construction order. External callers using a capability
directly must stop accepting calls and finish in-flight operations before engine
shutdown, or implement equivalent operation tracking inside the capability.
Closing the owner or starting a nested graph from its active node, job or
execution callback is rejected.
See the [execution concurrency contract](../execution-graph.md) for the three
engine limits and callback guarantees.

## 3. Describe Operations When Needed

The minimal manifest needs only the stable name. When a node exposes capability
operations through a model-tool adapter, replace that minimal manifest with
operation metadata and a packaged model contract:

```python
from metis.capabilities import CapabilityManifest
from metis.capabilities import CapabilityOperationManifest


manifest = CapabilityManifest(
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

registration = CapabilityRegistration(
    manifest=manifest,
    configuration=Configuration,
    factory=create,
    close=close,
)
```

Operation metadata describes:

- what each operation does;
- which orchestration or model-tool surfaces expose it;
- its model-visible input schema.

Put input limits in that schema and put behavioral, security, and failure rules
in the packaged model contract.
Include that contract in the owning distribution's package-data metadata and
verify `importlib.resources` can read it from the built wheel.

For model-callable operations, define the model-visible JSON Schema in the
operation's `input_schema` mapping. This keeps field names, descriptions,
limits, and examples reviewable separately from the runtime implementation.

Operation metadata is descriptive; it does not create a Tool. Metis currently
provides engine-owned model-tool adapters for the built-in Index and Navigation
capabilities. A separately distributed capability can be used directly by its
node for deterministic orchestration. If its package also exposes the operation
to a model, that package owns the adapter and its LangChain dependency; Metis
does not yet expose a generic public adapter factory.
The public node runtime exposes the shared model-tool round limit, but not the
internal contract loader or contract-character budget. An external adapter must
own and validate those pieces explicitly—put its contract budget in the external
capability or adapter configuration rather than importing internal tool modules.

For built-in adapters, shared runtime settings belong in the selected
`metis.yaml`, separate from execution topology. This is a configuration
fragment; merge it with the rest of the selected document:

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

This is an execution fragment; retain the other desired stages in the complete
graph:

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

Configuration alone does not activate the capability. External capability entry
points load, validate, and construct only when a selected node declares and is
granted that capability. Built-in registration modules and manifests load during
engine composition, but their instances are still constructed on demand. Direct
commands may explicitly request a built-in capability. Invalid selected
configuration or construction fails startup. Registered close callbacks run in
reverse construction order when the engine closes.

For a built-in capability:

1. Put its implementation under `src/metis/engine/capabilities/`.
2. Add `src/metis/engine/capabilities/manifests/<name>.yaml`.
3. When a node exposes it to a model, add
   `src/metis/engine/tools/contracts/<name>.md`, reference its `package://` URI
   from the manifest, implement `src/metis/engine/tools/<name>.py`, and compose
   the adapter in the consuming node.
4. Register it in `src/metis/engine/capabilities/builtins.py`.
5. Declare it on each consuming node, configure it under
   `metis_engine.capabilities.<name>`, and grant it in the complete packaged
   graph when enabled by default.
6. Update `docs/capabilities/README.md` for a user-visible capability.

Existing package-data globs cover standard capability manifests and tool
contracts. Update `pyproject.toml` for other locations and verify changed assets
from the built Metis wheel.

External capabilities require no Metis source change.

## 5. Add Tests

Add or update tests for the contracts the change touches:

- an external entry point is not loaded when ungranted;
- configuration validation and construction when granted;
- node access through `invocation.context.capabilities`;
- factory rollback and lifecycle cleanup for owned resources;
- model-tool exposure when the node intentionally provides it.

Useful existing test files:

- `tests/test_navigation_capability.py`
- `tests/test_capability_registry.py`
- `tests/test_engine_core.py`
- `tests/test_engine_lifecycle.py`
- `tests/test_model_tool_runner.py`
- `tests/test_execution_e2e.py` for external discovery and packaging

## 6. Verify

Built-in changes use the repository checks from
[CONTRIBUTION.md](../../CONTRIBUTION.md). External packages
run their own lint/tests and build a wheel; test that wheel in an isolated
subprocess so entry-point metadata and runtime resources are exercised.

For a focused built-in check, run:

```bash
uv run --no-sync pytest tests/test_capability_registry.py tests/test_engine_core.py
```

Then run the focused tests for the command or graph you touched.

Publish an active registration only after its manifest, runtime wiring,
contracts, and tests are present.

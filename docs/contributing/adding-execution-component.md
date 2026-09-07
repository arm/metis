<!--
SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
SPDX-License-Identifier: Apache-2.0
-->

# Adding built-in execution nodes and stages

This guide owns Metis-internal registration, composition, and packaged-default
steps. [Execution Graph](../execution-graph.md) owns topology, ports, status,
concurrency, lifecycle, and the public external-extension contract.

For a separately distributed component, start at
[Adding external nodes and stages](../execution-graph.md#adding-external-nodes-and-stages).

## Choose the smallest component

- Add a node when an existing stage contract fits.
- Add a stage only for a new top-level typed workflow boundary.
- Keep private or independently shipped work external. Make it built-in only
  when Metis must package and support it.

Before writing code, identify the owning stage, canonical input/output types,
producers and consumers, whether binding inference is unambiguous, and any
capability or engine-lifetime resource the component needs.

## Add a built-in node

### Define the registration and behavior

Place the node under `src/metis/engine/nodes/<node>/` and follow the closest
sibling. Use `index/registration.py` for a module-level registration and
`simple_llm_review/registration.py` for a dependency-injected `create_node(...)`.

The `NodeRegistration` owns the stable stage/name, configuration model, typed
ports, handler, capability requirements, and optional `required_when_bound`
ports. Use `required_when_bound` when a nullable bound input still requires its
selected producer to succeed. Reuse `EmptyNodeConfiguration` when no settings
exist; otherwise use a frozen Pydantic model that forbids extra fields.

Inputs and non-error outputs are strictly validated. Return actual declared
model/value types, not coercible mappings or strings. For `OK` and
`INCONCLUSIVE`, return exactly the registered output keys. For `ERROR`, normally
return `{}` with diagnostics; error-result outputs are discarded.

Registrations have no close hook. Close per-invocation resources in the handler.
Put external engine-lifetime resources behind a capability with a close callback.
If a built-in service must own a closeable resource, extend `BuiltinExecution`,
`MetisEngine.close()`, and construction-failure cleanup explicitly.
Constructors that acquire resources and then raise must roll back their own
partial acquisition before ownership can transfer to the engine.

### Compose only required services

Wire the selected registration in `build_builtin_execution()` in
`src/metis/engine/nodes/builtins.py`. Built-in registration modules are imported
eagerly, so optional dependency imports must remain lazy. Selection guards
prevent unnecessary service construction and execution; a selected node may
still construct an explicitly shared or fallback service.

Do not add node-specific branches to stage orchestration, the compiler, or the
runner.

### Select and document it

If the node belongs in the packaged graph, add it under its stage in
`src/metis/metis.yaml`; otherwise select it only in focused examples/tests.
Configuration under `metis_engine.execution` is a complete graph replacement.
Stage inputs/outputs and dependencies, node selection/bindings, grants,
model/max-concurrency overrides, formats, and filenames are topology;
registration-owned settings belong under
`metis_engine.execution.node_configuration.<stage>.<node>`. Existing shared
built-in settings such as `codegraph`, `reachability`, and `threat_model` remain
in their documented top-level engine sections.

Update [Execution Graph](../execution-graph.md) when a shipped node changes the
public graph or its behavior.

### Test what changed

Always add the closest behavior test and one relevant failure case. Add:

- node configuration tests only when it has fields;
- graph compilation tests when ports, inference, bindings, or grants change;
- composition tests when construction/selection changes;
- lifecycle tests when the component owns work or resources;
- packaged-configuration tests only when `src/metis/metis.yaml` changes.

Use `tests/test_engine_review.py` or a new focused file for review behavior,
`tests/test_execution_graph.py` for inference/topology/status contracts,
`tests/test_execution_port_validation.py` for strict port values,
`tests/test_execution_node_api.py` for shared registration fields,
`tests/test_engine_core.py` for composition, `tests/test_engine_lifecycle.py`
for owned resources, and `tests/test_configuration.py` for packaged defaults.

## Add a built-in stage

A built-in stage changes the supported Metis workflow. Confirm first that an
external `StageRegistration` cannot satisfy the requirement.

### Define the boundary

1. Insert the stable name at its intended tie-break position in
   `BUILTIN_STAGE_NAMES` in `src/metis/engine/execution/contracts.py`. Data and
   control dependencies remain authoritative; tuple order breaks otherwise-ready
   built-in ties. A new built-in name reserves that external-stage entry-point
   name, so make an explicit compatibility/release decision and test collision
   behavior.
2. Add the same key to `BUILTIN_STAGE_CONTRACTS` in
   `src/metis/engine/stages/configuration.py` and keep both key sets synchronized.
3. Put stage-owned models and transformations under
   `src/metis/engine/stages/<stage>/`.

In `_ResolvedStageContract`:

- `stage_inputs` lists YAML-bindable inputs that are validated at runtime;
- `initial_inputs` describes values supplied internally or by a direct stage
  call so the compiler can type node inputs;
- `required_execution_inputs` names graph-root values that must exist whenever
  the stage is configured;
- `required_outputs` lists outputs every successful stage run must publish.

Add a nullable field to `ExecutionInputs` only when YAML may bind
`$inputs.<field>`. Add its value and binding to each graph that consumes it;
update `src/metis/metis.yaml` only when the default graph does. External stages
cannot introduce arbitrary graph-root fields without this core change.

When stage `outputs` is omitted, a terminal node named `result` implicitly
publishes all its outputs and may not have dependants. Otherwise configure an
explicit output mapping. Ensure each required output has a compatible binding;
failed stages may omit failed-producer outputs while retaining other declared,
validated outputs.

### Compose and expose it

4. Implement the stage's nodes under `src/metis/engine/nodes/` and compose only
   selected registrations in `src/metis/engine/nodes/builtins.py`.
5. Extend `BuiltinExecution` and `MetisEngine` ownership for closeable services,
   including cleanup when later construction fails.
6. Add the stage to `src/metis/metis.yaml` only when it belongs in the default
   graph.
7. If direct invocation is required, add a typed `execute_<stage>()` to
   `ExecutionGraphService` and a matching public `MetisEngine` wrapper following
   the nearest span/error/value-conversion conventions. Otherwise
   `execute_graph()` is sufficient.
8. Add CLI handling only for a user-facing command or artifact. Current graph
   export and optional-filename routing know Review and Triage. For another
   artifact, define its payload/exporter, generalize filename validation and CLI
   routing, preserve explicit/generated path precedence and N-way collision
   checks, and cover partial `ERROR` output behavior.

Do not add a stage-name branch to generic execution solely to recognize the new
stage. Search source, tests, progress/run-log explanations, and docs for
hard-coded built-in stage lists or name-specific behavior.

Treat published names, ports, types, and facade exports as compatibility
boundaries. Adding a required port/capability, narrowing a type, or introducing
ambiguous inference is breaking even if the new symbol itself is additive.
Re-export a stage-owned type only when an external node or public engine method
needs it, then update the appropriate `metis.execution_nodes` or `metis.engine`
facade and public API/import tests.

### Test what changed

Cover registration/configuration, actual ordering and bindings, required
outputs, observable behavior, and one important failure. Add direct API/CLI,
cancellation/lifecycle, partial-output, public-facade, or packaged-default tests
only when the stage changes those contracts.
Assert `tuple(BUILTIN_STAGE_CONTRACTS) == BUILTIN_STAGE_NAMES` and test the new
stage's tie position with otherwise-ready stages.

## Runtime checklist

- Keep per-invocation state local to the handler or in objects created for that
  invocation; registrations, captured services, globals, and capabilities may be
  shared across executions.
- Use `invocation.context.jobs`, propagate
  `concurrent.futures.CancelledError`, check cancellation, use finite
  network/subprocess timeouts, and join owned work before returning.
- Do not start another graph on, or close, the same engine from an active
  handler, job, or callback.
- Callbacks run inline. Only progress delivery is serialized within one
  execution; other callbacks may overlap and must protect shared state.
- Validate untrusted results before publication or mutation. Model-derived
  findings are review/SARIF data, never structural CodeGraph facts.
- Installed extensions execute in-process; distribution does not imply
  sandboxing.

Use the runtime, failure, and concurrency sections of
[Execution Graph](../execution-graph.md#execution) as the authority when these
contracts change.

## Before sending

- Stable stage/node names, ports, configuration, capabilities, and YAML agree.
- New runtime assets are covered by `pyproject.toml` package-data metadata and
  loaded with wheel-safe resource APIs. Add or extend a built-Metis-wheel test
  when metadata or assets change; the external fixture wheel does not cover
  Metis package data.
- Focused behavior/failure tests pass; cross-boundary tests match only the
  affected contracts.
- Public documentation describes shipped behavior.
- Repository checks from [CONTRIBUTION.md](../../CONTRIBUTION.md) pass or unrun
  checks are reported.

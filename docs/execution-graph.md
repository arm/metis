# Execution Graph

Metis executes the graph under `metis_engine.execution` in the selected YAML
file. The packaged graph runs `initialize`, `review`, and `triage`. A
project-provided execution section replaces that graph as a whole. Every node
listed in the selected graph executes; an omitted node is not part of that
graph.

Read [Terminology](#terminology), [Default graph](#default-graph), and
[Stage contracts](#stage-contracts) to configure a run. Contributors adding a
separately distributed node can start at
[Adding public or private nodes](#adding-public-or-private-nodes).

## Terminology

- **Execution graph**: the complete configured workflow
- **Stage**: a stable workflow boundary such as `initialize`, `review`, or
  `triage`
- **Node**: executable work inside a stage, such as `codegraph`,
  `simple_llm_review`, `reachability`, `finding_dedup`, `triage`, or `result`
- **Execution Node API**: the public Python contracts used to implement and
  register Nodes; its exported types are not YAML-selectable Nodes
- **CodeGraph**: the language-neutral representation of code symbols, calls,
  source locations, and language-derived facts
- **CodeGraph provider**: a language-owned implementation that builds a
  validated `CodeGraph`
- **Capability**: an engine service a node may use when its YAML allowlist
  grants access, such as `index`, `memory`, or `navigation`
- **Tool**: a model-callable operation that a node deliberately creates from a
  granted capability; a capability grant does not expose tools automatically
- **Data dependency**: an input bound to another node's output
- **Control dependency**: ordering declared with `depends_on` when no value is
  transferred

YAML names product behavior. It does not contain Python implementation paths or
`uses` fields.

## Default graph

```yaml
metis_engine:
  execution:
    inputs:
      review_request:
        mode: code
    stages:
      initialize:
        outputs:
          - threat_model
        nodes:
          threat_model:
            capabilities:
              - memory
      review:
        depends_on:
          - initialize
        nodes:
          codegraph: {}
          simple_llm_review:
            capabilities:
              - memory
          reachability:
            capabilities:
              - memory
          finding_dedup: {}
          result:
            formats:
              - sarif
      triage:
        inputs:
          sarif: review.sarif
          codegraph: review.codegraph
        nodes:
          triage:
            capabilities:
              - memory
              - navigation
          result:
            formats:
              - sarif

  codegraph:
    source_functions: []
    security_functions: []
  reachability:
    max_path_length: 25
    domain_profiles: []
    domain_hints: []
```

Execution topology describes what runs and how values flow. Deterministic graph
annotations live under `metis_engine.codegraph`; reachability tuning lives under
`metis_engine.reachability`. Model and reasoning settings come from the shared
provider and query configuration. Reachability first covers selected function
source with the language plugin's normal security-review prompt, batching
nearby functions from the same file in source order. The prompt includes
deterministic CodeGraph evidence and syntax-derived direct-callee return
contracts. Findings identify every necessary-condition alternative for the
reported operation. Code rejects a finding only when deterministic evidence
contradicts every alternative; incomplete or ambiguous evidence remains
fail-open.

A same-file review batch is split in source order when its fixed context exceeds
the global input limit or its returned structured analysis is invalid; provider
failures are not subdivided. Reachability findings are combined with every
other Review-node output and deduplicated by `finding_dedup`.
`max_path_length` must be positive; it bounds reported reachability paths.

Capability runtime settings live under `metis_engine.capabilities`. A node's
`capabilities` list is only an access grant; it does not configure the
capability.

Unknown stages, nodes, inputs, formats, and configuration fields are rejected
when the YAML is loaded.

## Stage contracts

### Initialize

- `threat_model` updates threat-model memory and returns its initialization
  status.

- `index` builds the configured repository index when explicitly included in
  the graph. The packaged graph omits it.

Enable index construction by adding it to `initialize`. The example below is
an Initialize fragment; because a project execution section replaces the
packaged graph, keep the desired Review and Triage stages in the complete
configuration.

```yaml
metis_engine:
  execution:
    stages:
      initialize:
        outputs:
          - threat_model
          - index
        nodes:
          threat_model:
            capabilities:
              - memory
          index:
            capabilities:
              - index
```

Initialize lists the nodes whose status values it publishes. Each listed node
must have one output. A graph that replaces its nodes must list the
corresponding stage outputs explicitly.

The `capabilities` list is the complete allowlist for a node. Required and
optional capabilities are declared by the node registration. Omitting an
optional capability keeps it unavailable to that node; omitting a required
capability or naming one the node did not declare is a configuration error.

| Node | Required capabilities | Optional capabilities |
| --- | --- | --- |
| `threat_model` | `memory` | — |
| `index` | [`index`](capabilities/index.md) | — |
| `simple_llm_review` | — | `index`, `memory` |
| `reachability` | — | `index`, `memory` |
| `triage` | [`navigation`](capabilities/navigation.md) | `memory` |

Nodes without a row do not declare engine capabilities.

### Review

The review request supports `code`, `dir`, `file`, and `patch` modes.

`codegraph` groups the selected source files by language manifest, invokes the
corresponding providers, validates exact file coverage, composes their outputs
into one `CodeGraph`, and adds deterministic entrypoint, source, and sink
annotations. File review selects only the requested file; other review modes
select the project's supported source files.
It persists fingerprinted canonical graphs at
`<codebase>/.metis/codegraph.sqlite3` and publishes a typed reference to the
selected revision. An unchanged source set, language mapping, annotation
configuration, and Metis version reuse that revision.

`simple_llm_review` is the generic review node. It reviews every file in the
selected scope with the language plugin's prompts and does not require a
CodeGraph.

`reachability` resolves the declared CodeGraph reference and reviews selected
function source with the normal language security-review prompt. The evidence
includes deterministic function, call, control-flow, assignment, loop, return,
and direct-callee contract facts. The model must identify every
necessary-condition alternative for each finding. Deterministic admission may
reject a finding only when every alternative is contradicted by supported
source facts; missing, ambiguous, or incomplete evidence remains fail-open.

Same-file functions are batched in source order. Invalid or output-limited
multi-function batches are split immediately and their children are reviewed
in the same run. Batch results and split decisions are not persisted. The
language plugin supplies deterministic CodeGraph semantics during
materialization.
Directory review derives an in-memory analysis scope from the persisted project
graph. File review materializes and persists a graph for the requested file
only. Neither mode replaces or mutates another fingerprinted graph revision.
Patch review is supported by `simple_llm_review`. If `reachability` is selected
for a patch request, it publishes an inconclusive warning rather than silently
running another node. For code, directory, and file review, Reachability sends
files without CodeGraph and semantics support to the simple LLM fallback. When
`simple_llm_review` is explicitly selected alongside `reachability`, it owns
that generic review pass so unsupported files are not reviewed twice.

The CodeGraph service returns an independent in-memory graph to each consumer.
Nodes do not mutate the persisted graph. Model-derived findings remain review
or SARIF data; they are not written back as structural CodeGraph facts.

`finding_dedup` gathers every selected node output that uses the stable
`ReviewRun` contract. It combines those runs, removes exact duplicates, and
resolves semantic duplicates once for the whole review. Its distinct output
contract makes it the only valid input to `result`. Patch results pass through
unchanged.

`result` validates and publishes the finalized review before generating SARIF.
Its `formats` list declares
the representations written for that execution. Every listed format is saved.
Review publishes canonical `findings` for JSON, HTML, and CSV renderers and
always publishes `sarif` in memory for downstream stages. It also publishes a
CodeGraph reference when the selected stage has one compatible CodeGraph
output.
Omitting `sarif` from `formats` prevents a SARIF file from being written; it
does not remove the in-memory SARIF contract.

The execution graph planner binds an omitted singular node input only when
exactly one selected output is compatible. Collection inputs gather all
compatible outputs in declaration order and require at least one successful
producer; one failed producer does not suppress the consumer. Explicit
bindings resolve singular ambiguities and may select or order collection
sources. Same-named stage inputs, such as the Review request, retain precedence.
Cross-stage values remain explicit under the stage's `inputs` mapping.

An explicit source written as `node_name` selects that node's only output. Use
`node_name.output_name` when the producer has multiple outputs. Cross-stage
bindings use `stage_name.output_name`. In a stage's `inputs` mapping,
`$inputs.name` selects a top-level execution input. In a node's `inputs`
mapping, it selects an input already bound on that stage.

When a stage omits `outputs`, the complete output contract of its terminal
`result` node becomes the stage contract. Stages without a `result` node, such
as Initialize, list the same-named single-output nodes they publish.

`filename` optionally sets an extensionless output base on a result node:

```yaml
result:
  formats: [sarif, json]
  filename: results/review
```

This writes `results/review.sarif` and `results/review.json`.

Any explicit `--output-file` path makes the CLI authoritative for that run.
The `.sarif`, `.html`, `.csv`, or `.json` extension selects its format. Each
explicit path is preserved; the first path assigned to a stage supplies the
basename for that stage's requested formats that have no explicit path. If
Review and Triage both request an explicitly named format, its paths apply to
the later Triage result; Review uses a timestamped `graph_review` path to keep
the files distinct. A result node's YAML `filename` is used only when the CLI
does not supply an output path. When neither CLI nor YAML supplies a filename,
a graph run writes
`results/graph_review_<timestamp>.<format>` and
`results/graph_triage_<timestamp>.<format>` for the formats requested by each
stage. Supported formats are SARIF, JSON, HTML, and CSV.

### Triage

`metis_engine.triage.include_triaged` controls whether findings already
annotated by Metis are processed again. It defaults to `false` when omitted and
is therefore absent from the packaged YAML. It is Triage configuration, not an
execution-graph input. The `--include-triaged` flag enables it for one run.

`triage` classifies each SARIF finding with navigation evidence. When its
optional CodeGraph input covers the reported file, deterministic function and
call relationships are included in that evidence. The same node handles
unsupported files and standalone triage runs without a CodeGraph. Triage never
materializes a graph itself.

Normal review-to-triage execution does not deduplicate twice: `triage` receives
SARIF generated from the `FinalReviewRun` already produced by `finding_dedup`.

The stage bindings `sarif: review.sarif` and `codegraph: review.codegraph`
transfer those values and make Review a
data dependency. Do not repeat that relationship in `depends_on`.

Triage has its own `result` node because its SARIF represents a later state.

`depends_on` is reserved for ordering without a value transfer, such as
waiting for initialization to update memory or an index.

A graph may instead triage third-party SARIF:

```yaml
metis_engine:
  execution:
    inputs:
      sarif:
        version: "2.1.0"
        runs:
          - results: []
    stages:
      triage:
        inputs:
          sarif: $inputs.sarif
        nodes:
          triage:
            capabilities:
              - memory
              - navigation
          result:
            formats:
              - sarif
```

The optional CodeGraph input remains unset for third-party SARIF.

## Execution

Metis runs the selected graph when invoked with no arguments or with
`--non-interactive` and no `--command`. Passing `--non-interactive --command`
runs that command instead. Interactive commands enter the corresponding stage
contract directly:

| Command | Stage |
| --- | --- |
| `init` | `initialize` |
| `review_code`, `review_dir`, `review_file`, `review_patch` | `review` |
| `triage` | `triage` |

Direct commands do not rewrite YAML topology. The graph stops after a failed
stage. An inconclusive review may publish valid partial findings and SARIF so
triage can continue.

## Built-in implementation layout

Fixed workflow behavior is grouped by Stage. Reusable graph Nodes own a
directory containing their registration, contracts, configuration, and
implementation:

```text
engine/stages/
  initialize/
  review/
    models.py
    scope.py
  triage/
    models.py
    service.py
  configuration.py
  service.py
engine/nodes/
  codegraph/
  finding_dedup/
  reachability/
  simple_llm_review/
  triage/
  threat_model/
  index/
  result/
```

Stages own stable workflow contracts and orchestration. Nodes own executable
behavior and may be selected, omitted, or supplied by another package. Built-in
Nodes import Stage contracts; Stages do not import Node implementations.

Stages do not enumerate or construct their nodes. The built-in Node composition
module constructs the selected registrations and their services, while
`MetisEngine` owns the engine lifecycle and invokes that module. The lower-level
execution runner remains unaware of built-in Stage behavior. Adding a built-in
Node therefore changes its Node package, the built-in composition module, and
YAML topology; it does not change Stage execution code. Separately distributed
public or private Nodes require no Metis change and register through the
stage-qualified entry point described below.

## Adding public or private nodes

Stages are fixed product boundaries. Packages may add nodes within those stages
without modifying Metis.

The `metis.execution_nodes` Python module is the Execution Node API. It exports
registration, invocation, context, result, and Stage value contracts for Node
authors. Its `__all__` list defines those Python exports; it is not a catalog of
Nodes available to the YAML graph. `EXECUTION_NODE_API_VERSION` identifies the
breaking-change version of that surface. An installed registration must declare
the API version it targets; Metis rejects omitted or unsupported versions before
execution.

A Node becomes selectable in YAML only when Metis has a `NodeRegistration` for
its name and Stage. Built-in registrations come from Metis. A separately
distributed package supplies registrations through the stage-qualified
`metis.execution_nodes` Python packaging entry-point group:

### Private package template

A private repository can start with this layout and add one registration
module per node:

```text
private-metis-nodes/
  pyproject.toml
  src/
    company_metis_nodes/
      __init__.py
      policy.py
```

The package metadata registers each node independently, so Metis loads only
the nodes selected by YAML:

```toml
[build-system]
build-backend = "setuptools.build_meta"
requires = ["setuptools>=82"]

[project]
name = "company-metis-nodes"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = ["metis"]

[project.entry-points."metis.execution_nodes"]
"review.private_policy" = "company_metis_nodes.policy:registration"
```

Install that package in the same environment as Metis. Adding another private
node means adding its module, one entry-point line, and its YAML selection; no
Metis source change is required.

Custom nodes from any private Python repository can be added without changing
Metis. For example, the repository may be cloned independently or included as
a Git submodule. A checkout alone is not discoverable: install the package into
the Metis environment so Python registers its entry points. For an editable
submodule checkout:

```bash
uv pip install -e ./private-metis-nodes
uv run metis --config internal-metis.yaml --codebase-path ../project \
  --non-interactive
```

### Private analysis with a bundled implementation

A Review node may package a deterministic analyzer, library, or executable in
the same private distribution. This node-internal implementation is not a Tool
in the execution-graph terminology and does not need a Metis capability
registration. The node converts its output to the stable `ReviewRun` contract
so `finding_dedup` can combine it with other analyses before `result` generates
SARIF.

For example, an independently registered `new_analysis` node can run alongside
Reachability. This is a Review-stage fragment; retain the other desired stages
and execution inputs in the complete graph:

```yaml
metis_engine:
  execution:
    stages:
      review:
        nodes:
          codegraph: {}
          reachability: {}
          new_analysis: {}
          finding_dedup: {}
          result:
            formats:
              - sarif
```

The execution graph planner infers the CodeGraph input, gathers every compatible
Review output for `finding_dedup`, and routes its finalized output to `result`.

Its entry point and essential ports are:

```toml
[project.entry-points."metis.execution_nodes"]
"review.new_analysis" = "company_metis_nodes.new_analysis:registration"
```

```python
registration = NodeRegistration(
    name="new_analysis",
    stage="review",
    configuration=NewAnalysisConfiguration,
    inputs={"request": ReviewCommand},
    outputs={"review": ReviewRun},
    execute=execute,
    api_version=1,
)
```

The runner supplies the Review request because the input uses the canonical
`request` name and type. To replace Reachability, omit `reachability`; the
deduplication node then gathers only `new_analysis`. To consume an existing
CodeGraph, declare a `CodeGraphReference` input. The planner can infer its
unique producer, or YAML can bind it explicitly.

Engine capabilities such as `memory`, `index`, and `navigation` are declared by
the node and granted through YAML. Separately distributed shared capabilities
use the `metis.capabilities` entry-point group described in
[Adding a Metis Capability](capabilities/adding-capability.md). Metis discovers
entry-point names at startup but imports and constructs a shared capability only
after a selected node has declared and been granted it. Direct commands may
request their own built-in capability. Model-tool adapters remain explicit node
behavior; granting a capability does not automatically expose its operations to
a model.

### Registration template

The entry-point name is always `<stage>.<node>`. Its target returns the
registration used by the bare node name in YAML. In this example,
`company_metis_nodes/policy.py` contains:

```python
from typing import cast

from pydantic import BaseModel, ConfigDict

from metis.execution_nodes import CapabilityRequirement
from metis.execution_nodes import EXECUTION_NODE_API_VERSION
from metis.execution_nodes import NodeInvocation, NodeRegistration, NodeResult
from metis.execution_nodes import ReviewRun


class PolicyConfiguration(BaseModel):
    policy: str

    model_config = ConfigDict(extra="forbid", frozen=True)


def execute(invocation: NodeInvocation) -> NodeResult:
    configuration = cast(PolicyConfiguration, invocation.configuration)
    review = cast(ReviewRun, invocation.inputs["review"])
    # Apply the private policy and return the same canonical review contract.
    return NodeResult({"review": review})


registration = NodeRegistration(
    name="private_policy",
    stage="review",
    configuration=PolicyConfiguration,
    inputs={"review": ReviewRun},
    outputs={"review": ReviewRun},
    execute=execute,
    capabilities={
        "memory": CapabilityRequirement.OPTIONAL,
    },
    api_version=EXECUTION_NODE_API_VERSION,
)
```

The registration declares its stable name, owning stage, Pydantic
configuration model, typed input and output ports, capability requirements,
and handler. The node key in YAML selects that registration; YAML never
contains its Python import path.
Extension packages import these contracts from `metis.execution_nodes`; they
do not import the execution service or capability implementations.
Only selected entry points are loaded. Missing registrations, duplicate names,
wrong-stage registrations, invalid configuration, and incompatible port
connections fail before execution.

Node-specific tuning is separate from topology. This fragment shows only the
Review stage:

```yaml
metis_engine:
  execution:
    stages:
      review:
        nodes:
          simple_llm_review:
            capabilities:
              - index
              - memory
          private_policy:
            max_concurrency: 50
            inputs:
              review: simple_llm_review
          finding_dedup:
            inputs:
              reviews:
                - private_policy
          result:
            formats: [sarif, json]
            filename: results/review
    node_configuration:
      review:
        private_policy:
          policy: strict
```

A handler receives validated inputs and a small context containing its granted
capabilities together with the repository lookup contract, CodeGraph
materialize/load API, model runner, runtime limits, shared job scheduler, and
callbacks. `max_concurrency` limits that node's active jobs without reserving
threads; omitted values use the global `metis_engine.max_workers` limit. All
nodes on one engine share that worker pool, so their combined active work never
exceeds the global limit; larger node values are capped by it. A node submits
bounded work through `invocation.context.jobs.run(...)`; it does not construct
its own executor. A node
accesses only the names in `invocation.context.capabilities`. A node declares
`request: ReviewCommand` when it needs the review-stage request; the runner
supplies that typed stage input without extra YAML. The context does not expose
internal engine services or `EngineConfig`. Installed node code runs in the
Metis process; private distribution does not imply sandboxing.

The runner passes typed values between nodes using explicit bindings or the
inferred typed contracts described above. Nodes do not receive or invoke other
executable nodes: keeping execution in the runner preserves dependency
validation, ordering, diagnostics, and replacement by another registration
such as `reachability_v2`.

Registrations are scoped by stage, so Review and Triage may both define a
`result` node. Built-in names cannot be silently replaced. A private
replacement uses its own name and the selected YAML routes the terminal value
to it. A node that is omitted from YAML is neither loaded nor executed.

Progress callbacks receive lifecycle events for stage and node starts
and ends, dependency-skipped nodes, final status, and elapsed duration. Node
exceptions and invalid outputs produce an `execution.node_failed` diagnostic;
dependants with required inputs are reported as skipped while independent
nodes continue.

## CodeGraph provider contract

Adding language support does not change the execution graph. A language
package must:

1. Implement `CodeGraphProvider.build_graph()`.
2. Return `CodeGraphResult` whose disjoint `processed_files` and `failed_files`
   cover the exact requested file set. Error diagnostics must cover exactly
   the failed files, allowing valid partial results to remain usable.
3. Expose its factory through the `metis.codegraph_providers` entry-point
   group.
4. Name the entry point after the language manifest.
5. Declare `codegraph: true` in the language manifest.
6. Register a same-named CodeGraph-semantics implementation when the language
   supports advanced review.

Providers receive only the repository root, their exact files, a progress
callback, and `CodeGraphProviderContext` language/file-role lookup functions.
They must use globally unique symbol IDs, resolve their internal calls, and
return nodes only for requested files. Metis validates each provider result and
the composed graph.

C and C++ are internally routed through one shared build so calls across the
language boundary can be resolved. Their built-in implementation uses
tree-sitter. Tree-sitter is a C-family implementation dependency, not a
requirement of reachability or `CodeGraph`. A Python provider may use Python
ASTs, a type checker, or another implementation as long as it returns the same
contract.

Provider construction is lazy. Provider failures are isolated at the provider
boundary. For files without a configured provider, Reachability reports the
missing support and uses the simple LLM review fallback.

## CodeGraph semantics contract

A language with advanced review support declares the CodeGraph support flag in
its language manifest:

```yaml
capabilities:
  codegraph: true
```

The package registers semantics independently of its CodeGraph builder. The
entry-point name must match the language manifest name:

```toml
[project.entry-points."metis.codegraph_semantics"]
python = "company_metis_python.semantics:PythonSemantics"
```

The provider consumes immutable per-node facts and returns validated
annotations. It cannot mutate the shared CodeGraph:

```python
from metis.codegraph_semantics import CodeGraphAnnotations
from metis.codegraph_semantics import CodeGraphNodeFacts


class PythonSemantics:
    def analyze_node(
        self,
        facts: CodeGraphNodeFacts,
    ) -> CodeGraphAnnotations:
        if "eval" in facts.unresolved_calls:
            return CodeGraphAnnotations(
                is_sink=True,
                sink_type="code_injection",
                sink_reason="calls Python eval",
            )
        return CodeGraphAnnotations()
```

Semantics providers may also attach open-ended `Tag` values to a node under
namespaced keys. Tags are persisted with the canonical CodeGraph and passed
through unchanged to consuming nodes:

```python
from metis.codegraph_semantics import CodeGraphAnnotations, Tag


class PythonSemantics:
    def analyze_node(self, facts):
        return CodeGraphAnnotations(
            tags={
                "trust.domain": Tag(value="user", reason="handles request body"),
            },
        )
```

Metis resolves semantics providers lazily and serializes calls to each provider
instance; implementations do not need to be thread-safe. Their deterministic
annotations are persisted in the canonical CodeGraph. For a language without
configured semantics, Reachability reports the missing support and uses the
simple LLM review fallback.

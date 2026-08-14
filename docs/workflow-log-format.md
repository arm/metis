# Workflow run-log format v1

Metis can write a local, append-only trace of a CLI session or programmatic
engine run. The trace records execution topology, stages, nodes, parallel tasks,
inner workflows, prompts, physical model calls, tool calls, decisions, usage,
and produced artifacts.

Run logging is opt-in because full traces can contain source code, prompts,
model responses, tool output, file paths, and findings.

## CLI

```bash
metis --log-workflow-debug [--log-workflow-debug-path PATH] ...
```

`--log-workflow-debug-path` implies `--log-workflow-debug`. `PATH` may be:

- a directory, under which Metis creates a timestamped run directory; or
- a new path ending in `.ndjson`, which Metis uses exactly.

Metis never appends a new run to an existing NDJSON file. An existing exact
path is an error.

Without a path override, bundles are written below `./metis-runlog/`.

## Programmatic API

```python
from metis.engine import MetisEngine
from metis.runlog import RunLogConfig, build_run_metadata, open_runlog

config = RunLogConfig(path="traces", content="full")
metadata = build_run_metadata(
    metis_version="1.5.0",
    codebase_path="/path/to/repository",
)

with open_runlog(config, metadata=metadata) as session:
    engine = MetisEngine(
        codebase_path="/path/to/repository",
        runlog=session,
        # normal engine configuration follows
    )
    result = engine.execute_graph()
```

A session can contain multiple command or execution spans. Context is
propagated into Metis worker pools through the existing context-copying worker
helper.

Complete bundles can be checked before consumption:

```python
from metis.runlog import validate_runlog

summary = validate_runlog(session.ndjson_path)
```

Validation checks required envelope fields, ordering and identity, root and child
span lifecycle, event containment, metadata completion/status, and the byte
count and SHA-256 digest of every referenced blob.

## Bundle layout

Directory output uses:

```text
<run-directory>/
  run.ndjson
  meta.json
  blobs/
```

For an exact `trace.ndjson` path, metadata is stored in
`trace.ndjson.meta.json` and blobs in `trace.blobs/`.

`meta.json` is initially written with `complete: false` and is atomically
updated when the session closes. A process crash can leave it incomplete while
`run.ndjson` remains readable through its last complete line.

Trace directories use private directory permissions and trace/blob files use
private file permissions.

## Record envelope

Every NDJSON line is one JSON object with these fields:

| Field | Meaning |
| --- | --- |
| `v` | Schema version, currently `1` |
| `record` | `span.start`, `span.end`, or `event` |
| `record_id` | Unique identity for this line |
| `ts` | UTC wall-clock timestamp |
| `mono_ns` | Process monotonic timestamp |
| `seq` | Contiguous, authoritative line ordering within the run |
| `run_id` | Identity shared by every record in the bundle |
| `span_id` | Span being started/ended, or containing span for an event |
| `name` | Stable operation or event name |
| `explanation` | Stable human-readable description of what the span or event does |
| `thread`, `thread_id` | Emitting thread identity |
| `attributes` | Type-specific JSON payload |

Span records additionally contain `kind` and `parent_span_id`. Span end records
contain `status` and `duration_ms`, and may contain `error`.

Point events are not spans. They have their own `record_id`, refer to their
containing `span_id`, and do not contain `parent_span_id`. This prevents cycles
in the visualized span tree.

Sequence allocation and line writing happen under one lock. Therefore line
number and `seq` order agree even when worker threads emit concurrently.

### Explanations

Every record has a non-empty top-level `explanation`. It is written from the
perspective of someone reading the completed trace: what the record represents
or what was done. The visualizer can display it directly without translating
implementation-oriented recorder language. Span start and end records carry
the same explanation.

Metis resolves default explanations from the span `kind` and `name`, or from the
event name. Progress events additionally use `attributes.event`, so a generic
`progress` record can explain a specific marker such as
`reachability_frontier_review_start`. Unknown extension names receive a generic
explanation instead of omitting the field.

Instrumentation may override the catalogue text when a call site needs more
specific help:

```python
with runlog.span(
    "task",
    "custom_policy_check",
    explanation="One finding checked against the installed policy rules.",
):
    ...
```

`explanation` describes the operation or observed action. Dynamic state,
counts, inputs, and outputs remain under `attributes`.

## Span hierarchy

A complete configured run normally has this shape:

```text
run
└─ command
   └─ execution
      └─ stage
         └─ node
            └─ task
               └─ workflow
                  └─ step
                     └─ prompt
                        └─ attempt
                           ├─ llm.call
                           └─ model_loop
                              └─ tool
```

Not every operation requires every level. For example, a deterministic node
may have no tasks or prompts.

### Stable span kinds

- `run`: one bundle lifecycle
- `command`: one interactive, non-interactive, or default graph command
- `execution`: a configured graph, standalone stage, or ask execution
- `stage`: initialize, review, or triage
- `node`: one selected `NodeRegistration`
- `task`: one parallel file, finding, or reachability job
- `workflow`: an inner LangGraph invocation
- `step`: one inner-workflow node
- `prompt`: one logical prompt and parsing contract
- `attempt`: one retry-policy attempt
- `llm.call`: one physical provider invocation
- `model_loop`: a model/tool interaction loop
- `tool`: one model-requested tool invocation
- `retrieval`: one vector retrieval operation
- `memory`: one semantic repository-memory operation
- `threat_context`: threat-model policy retrieval and application

Logical prompts and physical model calls are deliberately separate. Structured
output fallback, retries, and model/tool rounds may cause more than one
`llm.call` under one `prompt`.

## Point events

Metis currently emits these stable event names:

- `execution.topology`: configured stage and node graph
- `progress`: engine/node progress callback payload
- `debug`: node debug callback payload
- `checkpoint`: triage checkpoint metadata
- `diagnostic`: execution or node diagnostic
- `retry`: retry reason and backoff
- `model.round`: one response in a model/tool loop
- `usage`: token usage for one physical model call
- `decision`: deterministic or policy-driven decision
- `artifact`: in-memory review, triage, or threat-model result
- `artifact.written`: output path, format, byte count, and SHA-256 digest

Consumers must ignore unknown event names, span kinds, and attributes.

## Content and blobs

The default explicit debug mode is `full`. Large strings and JSON values are
replaced with a content-addressed reference:

```json
{
  "$ref": "blobs/<sha256>.json",
  "bytes": 12345,
  "sha256": "<sha256>",
  "media_type": "application/json",
  "preview": "..."
}
```

Blob writes use a temporary file and atomic replacement. Identical content is
stored once per bundle.

`RunLogConfig(content="metadata")` records hashes and previews but omits blob
content. It is available to programmatic callers even though the CLI debug flag
selects full content.

Serialization is bounded by configured recursion and collection limits. Cycles
and truncated values are represented explicitly instead of failing the run.

## Redaction and security

Known configuration keys such as API keys, tokens, passwords, authorization,
credentials, and secrets are replaced with:

```json
{"$redacted": true, "sha256": "<sha256>"}
```

Sensitive command-line flag values are also redacted. Redaction cannot infer
secrets embedded in source code, prompts, responses, or tool output. Treat full
bundles as sensitive project data and apply the same retention and access policy
as the reviewed source repository.

## Failure behavior

Failure to create an explicitly requested trace is fatal before analysis starts.
After the run starts, a trace serialization or write failure disables further
telemetry and emits one warning; it does not change execution results. The
metadata file remains incomplete when possible.

Span context managers record uncaught exceptions with type, message, and
traceback. Keyboard interruption records a cancelled outcome. Caught execution
failures are recorded from their returned status or diagnostic before the run
closes.

## External execution nodes

The Execution Node API remains version 1. Separately distributed nodes appear
as opaque `node` spans. Metis automatically records:

- the node boundary and validated inputs/outputs;
- calls made through `invocation.context.prompts`;
- progress, debug, checkpoint, and diagnostic callbacks.

External nodes do not receive the internal span authoring API. A future public
trace sink would require a versioned Execution Node API change.

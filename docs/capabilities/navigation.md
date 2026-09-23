# Navigation Capability

The `navigation` capability owns read-only source navigation under the codebase
root. It exposes focused model-callable tools to nodes that need source
evidence.

Current operations:

- `grep(pattern, path)`
- `find_name(name, max_results)`
- `cat(path)`
- `sed(path, start_line, end_line)`

`grep` results retain matching source and line numbers but use paths relative to
the codebase root, including when the input path is absolute. Native grep may
prefix relative paths with `./`.

The packaged graph grants navigation to `simple_llm_review`, `reachability`, and
`triage`. Discovery uses it to resolve missing evidence in callers, definitions,
shared state, and lifecycle paths. Supporting evidence may come from other files;
findings remain anchored in the assigned review scope. Reachability's generic
fallback receives the same grant. A custom execution graph must explicitly grant
`navigation` to each review node that should use it.

Triage uses these operations only to validate the reported finding:

- Start from the reported file and line with `sed`.
- Follow only concrete symbols, imports, wrappers, guards, or call sites that
  affect the finding.
- Use `grep` for exact identifiers and `find_name` for exact basenames.
- Prefer narrow `sed` windows to whole-file or repository-wide searches.
- Treat tool output as evidence to interpret, not semantic proof.
- Return an inconclusive decision when a critical hop cannot be resolved.

The model-facing contract contains the detailed search and evidence rules. It
is packaged at `src/metis/engine/tools/contracts/navigation.md` and supplied to
the model once for all tools that share it.

Execution boundaries:

- Paths must remain inside the codebase root.
- Recursive searches do not follow symlinks. Direct paths may resolve symlinks
  only within the codebase root.
- Subprocess calls use the configured timeout and returned text is clipped to
  the configured output limit.
- Tool failures remain visible as errors; they are not converted into evidence.
- Navigation returns original source. Retrieved text does not establish that a
  branch is active in the selected compilation profile.
- Tool use retains the configured round limit and conversation history.
  For OpenAI-compatible chat models, the final response after that limit retains
  the tool definitions with `tool_choice: none` to preserve prompt-cache reuse
  without allowing further tool calls. Other adapters retain their existing
  tool-free final response.
  Discovery sizes source chunks using their rendered prompts and actual line
  numbers, and checks inputs against `max_token_length`. Input overflow during
  simple review fails without retrying the same request; no navigation headroom
  is reserved. Graph review splits overflowing multi-function batches using its
  existing batch splitter; an overflowing single function remains incomplete.

Patch review retains unified-diff hunk offsets and surrounding unchanged lines.
When a tool-assisted patch prompt cannot fit the whole original file, it omits
that full-file context and uses the diff and navigation instead. Finding anchors
still resolve against the full original source.

Tool-assisted discovery bypasses persisted review-answer checkpoints because
retrieved source is not part of the packet's stable identity. It still records
model/tool activity in the run log when workflow tracing is enabled.

## Configuration

The selected `metis.yaml` owns navigation execution limits and shared
model-tool prompt limits. This is the navigation-related fragment; retain the
other configured capability sections:

```yaml
metis_engine:
  model_tools:
    max_rounds: 6
    max_contract_chars: 6000
  capabilities:
    navigation:
      timeout_seconds: 8
      max_chars: 16000
```

These settings configure navigation wherever it is used. An execution node's
`capabilities` list only controls whether that node receives navigation access.
An explicit `execution` mapping replaces the packaged graph; start from the
[complete example](../execution-graph.md#default-graph).

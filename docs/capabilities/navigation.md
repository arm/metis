# Navigation Capability

The `navigation` capability owns read-only source navigation under the codebase
root. It exposes focused model-callable tools to nodes that need source
evidence.

Current operations:

- `grep(pattern, path)`
- `find_name(name, max_results)`
- `cat(path)`
- `sed(path, start_line, end_line)`

Triage uses these operations to validate a reported finding:

- Start from the reported file and line with `sed`.
- Follow only concrete symbols, imports, wrappers, guards, or call sites that
  affect the finding.
- Use `grep` for exact identifiers and `find_name` for exact basenames.
- Prefer narrow `sed` windows to whole-file or repository-wide searches.
- Treat tool output as evidence to interpret, not semantic proof.
- Return an inconclusive decision when a critical hop cannot be resolved.

The model-facing contract contains the detailed search and evidence rules. It
is packaged at `src/metis/engine/tools/contracts/navigation.md` and supplied to
the model with the tools.

Execution boundaries:

- Paths must remain inside the codebase root.
- Calls have configured time and output limits.
- Tool failures remain visible as errors; they are not converted into evidence.

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

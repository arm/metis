# Navigation Model-Tool Contract

The `navigation` capability owns read-only source navigation under the codebase
root. This contract governs its model-callable tools.

Current tools:

- `grep(pattern, path)`
- `find_name(name, max_results)`
- `cat(path)`
- `sed(path, start_line, end_line)`

Model usage rules:

- Resolve concrete evidence gaps in the assigned review scope or reported finding.
  Supporting evidence may come from other files; finding anchors remain in the
  assigned code. During triage, investigate only the reported finding.
- Start from supplied source and use `sed` to inspect relevant definitions,
  callers, shared state, and lifecycle paths. Follow concrete references across
  files when they affect the suspected failure or its preconditions.
- Inspect relevant defenses and counterexamples before accepting a claim.
- Use `grep` for exact identifiers or terms from inspected code, not for
  vulnerability classes, CWE IDs, exploit terms, or broad audit concepts.
- Use `find_name` only for exact basename resolution.
- Use `cat` only for short files or when whole-file structure is necessary.
- Keep calls narrow. Prefer focused `sed` windows and a narrowed search path.
- State unresolved evidence gaps and distinguish facts from assumptions. Missing
  context proves neither a defect nor safety. Triage is inconclusive when a
  critical hop cannot be resolved.

Execution rules:

- Paths must remain inside the codebase root.
- Outputs are clipped to configured limits.
- Tool failures are errors, not evidence.
- Navigation reads original source files. A branch in retrieved text is not proof
  that it is active in the selected build; respect supplied compilation-profile
  and graph evidence and state configuration uncertainty.
- Text occurrence alone does not prove behavior. Claims require concrete
  file-and-line evidence and a causal explanation.
- Absence of a `grep` result is not proof of safety unless the searched scope is
  complete for the claim.

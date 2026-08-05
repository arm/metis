# Navigation Model-Tool Contract

The `navigation` capability owns read-only source navigation under the codebase
root. This contract governs its model-callable tools.

Current tools:

- `grep(pattern, path)`
- `find_name(name, max_results)`
- `cat(path)`
- `sed(path, start_line, end_line)`

Model usage rules:

- Validate a specific reported finding; do not use navigation to discover
  unrelated issues.
- Start at the reported file and line with `sed`, then follow only concrete
  symbols, imports, wrappers, guards, or call sites that affect that finding.
- Try to disprove a finding by inspecting directly relevant guards, validators,
  sanitizers, escaping, clamping, allowlists, reject paths, and early returns.
- Use `grep` for exact identifiers or terms from inspected code, not for
  vulnerability classes, CWE IDs, exploit terms, or broad audit concepts.
- Use `find_name` only for exact basename resolution.
- Use `cat` only for short files or when whole-file structure is necessary.
- Keep calls narrow. Prefer focused `sed` windows and a narrowed search path.
- Mark a finding inconclusive when a critical import, wrapper, alias,
  definition, generated file, or source/sink hop cannot be resolved.

Execution rules:

- Paths must remain inside the codebase root.
- Outputs are clipped to configured limits.
- Tool failures are errors, not evidence.
- Text occurrence alone does not prove behavior. Valid triage requires concrete
  file-and-line evidence and a resolution chain.
- Absence of a `grep` result is not proof of safety unless the searched scope is
  complete for the claim.

# Navigation Tool Contract

The `navigation` tool owns read-only source navigation under the codebase root.
It is enabled by default and can be disabled with `--tools none`.

Current capabilities:

- `grep(pattern, path)`
- `find_name(name, max_results)`
- `cat(path)`
- `sed(path, start_line, end_line)`

Execution rules:

- Paths must remain inside the codebase root.
- Outputs are clipped to configured limits.
- Failures should be captured as tool errors and should not be silently converted
  into evidence.

Model interpretation rules:

- `grep` hits prove textual occurrence only.
- `sed` windows provide local context only.
- `find_name` resolves filenames, not include semantics.
- `cat` can be large; prefer bounded `sed` windows in prompts.
- Navigation evidence can support a finding only when the relevant line or
  nearby code demonstrates the behavior.

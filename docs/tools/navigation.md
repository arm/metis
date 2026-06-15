# Navigation Tool Contract

The `navigation` tool owns read-only source navigation under the codebase root.
It is enabled by default and can be disabled with `--tools none`.

Current capabilities:

- `grep(pattern, path)`
- `find_name(name, max_results)`
- `cat(path)`
- `sed(path, start_line, end_line)`

Triage use:

- Use navigation tools to validate a specific reported finding, not to discover new
  issues.
- Start from the reported file and line with `sed`, then follow only concrete
  symbols, imports, wrappers, guards, or call sites that affect that finding.
- Before marking a finding valid, try to disprove the reported condition with
  directly relevant guards, validators, sanitizers, escaping, clamping,
  canonicalization, allowlists, reject paths, or early returns.
- Use `grep` for exact identifiers, call names, constants, imports, decorators,
  config keys, or guard terms from the reported code. Do not grep for
  vulnerability classes, CWE IDs, exploit terms, or broad audit concepts.
- Use `find_name` only for exact basename resolution.
- Use `cat` only for short files or when whole-file structure is necessary.
- Use at most four narrow navigation calls before deciding. Prefer inconclusive
  over broad repository searches or whole-file dumps when the missing evidence
  cannot be resolved within that budget.
- Keep each call narrow. Prefer multiple small `sed` windows over one large
  file dump. Avoid repository-root `grep` unless the pattern is an exact
  identifier and no narrower package, file, or directory is available.
- If a finding depends on imported, wrapped, generated, configured, or
  platform-gated behavior, resolve only the next concrete hop needed for the
  decision. Mark the finding inconclusive when the hop cannot be resolved with
  focused navigation.
- Use tests, fixtures, build files, config files, or runtime artifacts only when
  they are directly named by the finding or by code already inspected.

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
- Valid triage requires concrete file:line evidence and a resolution chain from
  the reported finding to the cited code.
- Mark a finding invalid when navigation evidence directly contradicts the
  reported condition or shows the claimed source/sink/guard is absent.
- Do not mark a finding valid while a directly relevant validation, escaping,
  clamping, allowlist, reject path, or early return remains uninspected.
- Mark a finding inconclusive when critical imports, wrappers, aliases,
  definitions, generated code, or source/sink hops cannot be resolved.
- Do not treat absence of grep results as proof of safety unless the searched
  scope is complete for the claim and the reason explains that scope.

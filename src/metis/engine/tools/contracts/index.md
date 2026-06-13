# Index Tool Contract

The `index` tool owns vector-index-backed retrieval over code and
documentation. When `--tools index` is enabled, it exposes the model-callable
LangChain tool `index_search`.

Model-callable input:

- `query`: short human-readable context question. State what you need to
  understand, include important symbols, APIs, files, or architecture terms as
  anchors, and do not submit a keyword-only search string.
- `top_k`: optional nearest-neighbor count, capped by the index tool manifest.
- `max_chars`: optional output budget, capped by the index tool manifest.
- `source`: optional retrieval source: `docs`, `code`, or `both`.

Model usage rules:

- When `index_search` is available during `review_code`, use it as an evidence
  calibration aid, not as a recall booster or finding filter.
- Do not apply a numeric reporting threshold from this contract. The index tool
  should improve confidence by supplying relevant project facts, not by changing
  reporting thresholds.
- Prefer fewer, better-supported findings. For each candidate, ask whether the
  security impact depends on a project-level trust boundary or caller
  responsibility not visible in the file.
- When it does, use indexed docs to infer the intended consumer, whether inputs
  are trusted or caller-validated, who owns size/bounds checks, and what
  behavior is out of scope for the component.
- Lower confidence for candidates that only describe invalid use outside
  documented responsibilities. Keep confidence high for concrete defects under
  valid use, violations of documented contracts, or cases where docs show data
  comes from an untrusted boundary.
- Cite the retrieved project fact whenever it changes confidence.
- Use `index_search` sparingly, only when a current-file decision depends on
  broader project context not present in the immediate snippet.
- Use `source: "docs"` for threat model, trust boundary, deployment,
  documented assumptions, and non-goal questions. Use `source: "code"` for
  related definitions or API behavior.
- First form a concrete candidate finding from the reviewed code. Then call
  `index_search` only if confidence depends on one exact missing project fact.
  Do not use the index before the current-file evidence has produced a
  candidate.
- Before calling `index_search`, identify the exact non-local assumption that
  affects confidence, such as input control, API contract, lifecycle invariant,
  configuration source, or documented trust boundary.
- Ask neutral factual questions only. Do not ask the index to produce audit
  conclusions, classify bugs, find bug instances, or search by vulnerability
  class, exploit technique, CWE ID, or issue type.
- If a candidate involves a recognizable issue class, do not include that issue
  class name in the index query. Translate the uncertainty into neutral project
  facts such as input origin, trust boundary, lifecycle, parser behavior,
  prompt/data separation, path confinement, API contract, or configuration
  source.
- Do not use `index_search` as a routine preflight step for every file or every
  generic bug pattern. Most review decisions should be made from the
  current review input without calling the index.
- Do not use `index_search` as a broad source scan or as a way to discover
  unrelated additional issues during review. Use it to confirm, contradict, or
  calibrate a specific factual uncertainty.
- Prefer at most one index call for a candidate. If the result does not answer
  the factual assumption, leave confidence based on deterministic evidence
  rather than asking broader follow-up questions.
- During `review_code`, the current reviewed file remains the only primary
  report target. Do not report a new finding whose primary evidence is only in
  retrieved context.
- Retrieved context may increase confidence only when it directly confirms a
  precondition that the current-file evidence already suggests.
- If retrieved context is generic, only loosely related, or about a neighboring
  subsystem rather than the exact assumption, do not use it to increase
  confidence.
- If retrieved context contradicts a required assumption, lower confidence or
  revise the finding according to the normal review instructions. Do not force a
  result merely to satisfy a desired confidence value.
- Do not raise severity or confidence solely because retrieved context mentions
  a broader subsystem, threat model, or related implementation.
- Avoid implementation lookup queries during `review_code`. If exact source
  content is needed, rely on deterministic navigation rather than vector search.
- Write queries as human-readable questions that state the decision, then add
  important identifiers or architecture terms as anchors.
- Usually omit `top_k`; runtime source-specific defaults retrieve more
  documentation than code.
- Usually omit `max_chars` so the tested runtime profile controls retrieval
  budget. If you set it, choose the smallest budget that can answer the factual
  question.
- Do not use `index_search` for facts already visible in the prompt.
- Treat retrieved passages as context candidates, not proof by themselves.
- Cite concrete files, lines, and snippets from retrieved context when available.
- If retrieval returns no useful matches, continue with deterministic evidence
  rather than assuming the behavior is absent.

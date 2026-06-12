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

Model usage rules:

- When `index_search` is available during `review_code`, use it as an evidence
  calibration aid, not as a recall booster or finding filter.
- Do not apply a numeric reporting threshold from this contract. The index tool
  should improve confidence by supplying relevant project facts, not by changing
  reporting thresholds.
- Use `index_search` sparingly, only when a current-file decision depends on
  broader project context, related definitions, APIs, design intent, threat
  model, documented assumptions, or documentation that is not present in the
  immediate snippet.
- First form a concrete candidate finding from the reviewed code. Then call
  `index_search` only if confidence depends on one exact missing project fact.
  Do not use the index before the current-file evidence has produced a
  candidate.
- Before calling `index_search`, identify the exact non-local assumption that
  affects confidence, such as who controls an input, what an API contract
  guarantees, what lifecycle invariant applies, how a configuration value is
  sourced, or what trust boundary the documentation defines.
- Ask neutral factual questions only. Do not ask the index to produce audit
  conclusions, classify bugs, find bug instances, or search by vulnerability
  class, exploit technique, CWE ID, or issue type. The model performs analysis
  from the current review input and deterministic evidence; the index retrieves
  project facts.
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
  report target. Retrieved context may explain or invalidate a finding in that
  file, but do not report a new finding whose primary evidence is only in a
  retrieved file or document.
- Retrieved context may increase confidence only when it directly confirms a
  precondition that the current-file evidence already suggests: data origin,
  trust boundary, lifecycle, invariant, API behavior, configuration source, or
  documented deployment assumption.
- If retrieved context is generic, only loosely related, or about a neighboring
  subsystem rather than the exact assumption, do not use it to increase
  confidence.
- If retrieved context contradicts a required assumption, lower confidence or
  revise the finding according to the normal review instructions. Do not force a
  result merely to satisfy a desired confidence value.
- Do not raise severity or confidence solely because retrieved context mentions
  a broader subsystem, threat model, or related implementation. Raise confidence
  only when the current file already contains concrete behavior and the
  retrieved context directly confirms the relevant assumption.
- Avoid implementation lookup queries during `review_code`. If exact source
  content is needed, rely on the current review input or deterministic
  navigation surfaces rather than the vector index.
- Write queries as human-readable questions that state the decision you are
  trying to make, then include the most important identifiers or architecture
  terms as anchors. For example: "How does this project define trust boundaries
  for configuration files loaded by the CLI?"
- Prefer small retrieval requests: `top_k` 1 and `max_chars` 1000-1500 are
  usually enough. Ask for more only when the current-file decision truly needs
  several related definitions or documents.
- Use indexed documentation to understand the codebase's threat model,
  deployment assumptions, trust boundaries, and non-goals when those facts
  affect the current-file decision.
- For findings informed by index context, explain the specific fact retrieved
  and how it changes confidence. For example, cite that documentation confirms a
  file is user-controlled, an API returns normalized paths, or a config file is
  trusted local input.
- Do not use `index_search` for facts already visible in the prompt.
- Treat retrieved passages as context candidates, not proof by themselves.
- Cite concrete files, lines, and snippets from retrieved context when available.
- If retrieval returns no useful matches, continue with deterministic evidence
  rather than assuming the behavior is absent.

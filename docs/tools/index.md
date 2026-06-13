# Index Tool Contract

The `index` tool owns vector-index-backed retrieval over code and documentation.

Current active capabilities:

- `index.build`: build the index.
- `index.update`: update the index from a patch.
- `index.retrieve`: retrieve context for deterministic index-backed orchestration
  surfaces such as Metis `ask`.
- `index.search`: expose bounded retrieval as the model-callable LangChain tool
  `index_search` when `--tools index` is enabled.

Model-callable input:

- `query`: short human-readable context question. State what you need to
  understand, include important symbols, APIs, files, or architecture terms as
  anchors, and do not submit a keyword-only search string.
- `top_k`: optional nearest-neighbor count, capped by the index tool manifest.
- `max_chars`: optional output budget, capped by the index tool manifest.
- `source`: optional retrieval source: `docs`, `code`, or `both`.

Manifest configuration:

```yaml
config:
  model_tool:
    max_contract_chars: 6000
  search:
    max_top_k: 4
    code_top_k: 1
    docs_top_k: 4
    docs_char_ratio: 1.0
    default_max_chars: 5000
    max_chars: 7000
```

`max_contract_chars` is per-tool prompt-budget metadata. The model tool-call
round budget is shared across all model-callable tools in one model call and is
configured in `metis.yaml`:

```yaml
metis_engine:
  model_tools:
    max_rounds: 6
```

Search retrieval defaults can be overridden from `metis.yaml` without editing
the tool manifest:

```yaml
metis_engine:
  index_search:
    code_top_k: 1
    docs_top_k: 4
    docs_char_ratio: 1.0
    default_max_chars: 5000
    max_chars: 7000
```

Model-callable output:

- `[INDEX_SEARCH]`: query metadata.
- `[CODE_CONTEXT]`: indexed source-code context candidates.
- `[DOC_CONTEXT]`: indexed documentation context candidates.
- `[INDEX_RETRIEVAL_ERROR]`: retrieval failed for one side of the index.

Model interpretation rules:

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
- Use `source: "docs"` for threat model, trust boundary, deployment,
  configuration ownership, documented assumptions, and non-goal questions. Use
  `source: "code"` for related definitions or API behavior. Use `source: "both"`
  only when the same factual assumption needs source and documentation context.
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
  unrelated additional issues during review. Use it to confirm, reject, or
  calibrate a specific uncertainty.
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
- Usually omit `top_k`; runtime source-specific defaults retrieve more
  documentation than code.
- Usually omit `max_chars` so the tested runtime profile controls retrieval
  budget. If you set it, choose the smallest budget that can answer the factual
  question.
- If retrieved documentation changes whether an issue is relevant, cite the
  documented assumption or boundary alongside the source-code evidence.
- For findings informed by index context, explain the specific fact retrieved
  and how it changes confidence. For example, cite that documentation confirms a
  file is user-controlled, an API returns normalized paths, or a config file is
  trusted local input.
- Treat retrieved passages as context candidates, not proof by themselves.
- Prefer source-local evidence from navigation or structural analysis when
  validating a finding.
- Cite concrete files, lines, and snippets from retrieved context when available.
- If retrieval returns no useful matches, continue with deterministic evidence
  rather than assuming the behavior is absent.

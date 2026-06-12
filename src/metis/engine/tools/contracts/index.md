# Index Tool Contract

The `index` tool owns vector-index-backed retrieval over code and documentation.

Active capabilities:

- `index.build`: build the index.
- `index.update`: update the index from a patch.
- `index.retrieve`: retrieve context for Metis `ask`, review, and triage flows.
- `index.search`: expose bounded retrieval as the model-callable LangChain tool
  `index_search` when `--tools index` is enabled.

Model-callable input:

- `query`: natural-language context question.
- `top_k`: optional nearest-neighbor count, capped by the index tool manifest.
- `max_chars`: optional output budget, capped by the index tool manifest.

Model-callable output:

- `[INDEX_SEARCH]`: query metadata.
- `[CODE_CONTEXT]`: indexed source-code context candidates.
- `[DOC_CONTEXT]`: indexed documentation context candidates.
- `[INDEX_RETRIEVAL_ERROR]`: retrieval failed for one side of the index.

Model usage rules:

- Use `index_search` when the prompt needs broader project context, related
  files, definitions, APIs, design intent, threat model, security assumptions,
  or documentation that is not present in the immediate snippet.
- For security review, use indexed documentation to understand the codebase's
  threat model, deployment assumptions, trust boundaries, and non-goals before
  deciding whether a generic issue is relevant to this project.
- If retrieved documentation changes whether an issue is relevant, cite the
  documented assumption or boundary alongside the source-code evidence.
- Do not use `index_search` for facts already visible in the prompt.
- Treat retrieved passages as context candidates, not proof by themselves.
- Prefer source-local evidence from navigation or structural analysis when
  validating a finding.
- Cite concrete files, lines, and snippets from retrieved context when available.
- If retrieval returns no relevant context, continue with deterministic evidence
  rather than assuming the behavior is absent.

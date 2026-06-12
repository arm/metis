# Index Tool Contract

The `index` tool owns vector-index-backed retrieval over code and documentation.

Current active capabilities:

- `index.build`: build the index.
- `index.update`: update the index from a patch.
- `index.retrieve`: retrieve context for Metis `ask`, review, and triage flows.
- `index.search`: expose bounded retrieval as the model-callable LangChain tool
  `index_search` when `--tools index` is enabled.

Model-callable input:

- `query`: short human-readable context question. State what you need to
  understand, include important symbols, APIs, files, or architecture terms as
  anchors, and do not submit a keyword-only search string.
- `top_k`: optional nearest-neighbor count, capped by the index tool manifest.
- `max_chars`: optional output budget, capped by the index tool manifest.

Manifest configuration:

```yaml
config:
  model_tool:
    max_contract_chars: 6000
  search:
    max_top_k: 20
    default_max_chars: 12000
    max_chars: 24000
```

`max_contract_chars` is per-tool prompt-budget metadata. The model tool-call
round budget is shared across all model-callable tools in one model call and is
configured in `metis.yaml`:

```yaml
metis_engine:
  model_tools:
    max_rounds: 6
```

Model-callable output:

- `[INDEX_SEARCH]`: query metadata.
- `[CODE_CONTEXT]`: indexed source-code context candidates.
- `[DOC_CONTEXT]`: indexed documentation context candidates.
- `[INDEX_RETRIEVAL_ERROR]`: retrieval failed for one side of the index.

Model interpretation rules:

- Use indexed documentation to understand the codebase's threat model,
  deployment assumptions, trust boundaries, and non-goals before deciding
  whether a generic security issue is relevant to this project.
- Write queries as human-readable questions that state the intent, then include
  the most important identifiers or domain terms as anchors. For example:
  "How does the kleidiai SME2 depthwise convolution kernel manage SMSTART/SMSTOP
  and ZA preservation under AAPCS64?"
- If retrieved documentation changes whether an issue is relevant, cite the
  documented assumption or boundary alongside the source-code evidence.
- Treat retrieved passages as context candidates, not proof by themselves.
- Prefer source-local evidence from navigation or structural analysis when
  validating a finding.
- Cite concrete files, lines, and snippets from retrieved context when available.
- If retrieval returns no relevant context, continue with deterministic evidence
  rather than assuming the behavior is absent.

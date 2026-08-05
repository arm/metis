# Index Capability

The `index` capability owns vector-index-backed retrieval over code and
documentation. The engine exposes it through `IndexCapability` and creates
embedding/index resources when an index operation first needs them.

Current operations:

- `index.build`: build the index.
- `index.update`: update the index from a patch.
- `index.retrieve`: retrieve context for orchestration surfaces such as `ask`.
- `index.search`: expose bounded retrieval as the model-callable
  `index_search` tool.

The packaged execution graph does not build an index. Add the `index` node to
the `initialize` stage when a run should build or refresh it; see
[Execution graph](../execution-graph.md#initialize).

`index_search` accepts:

- `query`: a short human-readable context question.
- `top_k`: an optional nearest-neighbor count capped by runtime configuration.
- `max_chars`: an optional output budget capped by runtime configuration.
- `source`: `docs`, `code`, or `both`.

It returns labelled query metadata, code/document context candidates, and
retrieval errors. Retrieved passages are context candidates rather than proof;
review remains grounded in the current source and concrete file-and-line
evidence.

## Configuration

The selected `metis.yaml` owns model-tool and retrieval limits. This is the
index-related fragment; retain the other configured capability sections:

```yaml
metis_engine:
  model_tools:
    max_rounds: 6
    max_contract_chars: 6000
  capabilities:
    index:
      search:
        max_top_k: 4
        code_top_k: 1
        docs_top_k: 4
        docs_char_ratio: 1.0
        default_max_chars: 5000
        max_chars: 7000
```

The `model_tools` section configures model-tool adapters. The
`capabilities.index` section configures the index service. The `capabilities`
list on an execution node only grants that node access to the configured
capability.

The canonical model-facing rules are packaged at
`src/metis/engine/tools/contracts/index.md` and injected into prompts from the
index manifest. Keep those rules in that single file.

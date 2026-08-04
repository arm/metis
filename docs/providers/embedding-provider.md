# Embedding provider

Embedding configuration is required when the selected execution graph contains
the `index` node or a command uses the Index capability. Direct review and
triage commands can run without embeddings when their selected nodes do not use
that capability.

Embeddings are configured explicitly under a top-level `embedding_provider`
block. This keeps chat-only providers such as Anthropic, Gemini, and Bedrock
Mantle from needing embedding credentials or embedding model settings.

```yaml
llm_provider:
  name: "anthropic"
  model: "<claude-model-id>"

embedding_provider:
  name: "openai"
  code_embedding_model: "text-embedding-3-large"
  docs_embedding_model: "text-embedding-3-large"

metis_engine:
  embed_dim: 3072
```

For the PostgreSQL backend, `pgvector_use_halfvec` defaults to `auto`. This
uses pgvector `halfvec` storage when `embed_dim` is above the normal-vector
HNSW limit, for example 3072-dimensional embeddings. Set it to `true` or
`false` to force a specific behavior.

The `embedding_provider` block uses the embedding provider's own config keys.
For OpenAI-compatible providers (`openai`, `ollama`, `llamacpp`, `vllm`) use
`code_embedding_model` and `docs_embedding_model`. Azure OpenAI also requires
`code_deployment` and `docs_deployment`. Bedrock requires `region` and any
AWS credential settings needed by your environment.

Index operations require `code_embedding_model`, `docs_embedding_model`, and
the provider-specific connection settings. Review and triage nodes that do not
use the Index capability do not require an embedding model.

Keep live credentials out of committed config. For local smoke tests, put
provider YAMLs and any `.env` file under ignored local paths such as
`local-tests/` and `.env`.

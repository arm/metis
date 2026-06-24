# Embedding provider

Indexing and index-backed retrieval are **off by default** (the `index`
engine tool must be opted into via `--tools index` or
`metis_engine.tools: [index]`). Embedding configuration is therefore
optional unless you enable indexing.

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
  tools: [index]
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

When the `index` tool is enabled, Metis validates the embedding
configuration at startup and fails fast if `code_embedding_model` / `docs_embedding_model`
or any provider-specific keys are missing. When the tool is disabled, the
check is skipped and chat/review/triage run without an embedding model.

Keep live credentials out of committed config. For local smoke tests, put
provider YAMLs and any `.env` file under ignored local paths such as
`local-tests/` and `.env`.

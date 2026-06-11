# Embedding provider

Indexing and index-backed retrieval are **off by default** (the `index`
engine tool must be opted into via `--tools index` or
`metis_engine.tools: [index]`). Embedding configuration is therefore
optional unless you enable indexing.

By default Metis uses the `llm_provider` for both chat and embeddings.
To mix providers — e.g. Anthropic Claude for chat and OpenAI for
embeddings — add a separate `embedding_provider` block:

```yaml
llm_provider:
  name: "anthropic"
  model: "opus"

embedding_provider:
  name: "openai"
  code_embedding_model: "text-embedding-3-large"
  docs_embedding_model: "text-embedding-3-large"

metis_engine:
  embed_dim: 3072
  tools: [index]
```

The `embedding_provider` block accepts the same keys as `llm_provider`
for the chosen `name` (API key, base URL, region, etc.); only the
embedding-related keys are required. If `embedding_provider` is omitted,
embedding settings are read from `llm_provider` for backwards
compatibility.

When the `index` tool is enabled, Metis validates the embedding
configuration at startup and fails fast if `code_embedding_model` /
`docs_embedding_model` (and any provider-specific keys such as
`region` for Bedrock or deployments for Azure) are missing. When the
tool is disabled, the check is skipped and chat/review/triage run
without an embedding model.

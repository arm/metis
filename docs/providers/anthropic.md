# Anthropic Provider

Metis can use Anthropic Claude models, including Claude Opus, for chat, review,
and triage. Indexing still requires a separate `embedding_provider` because
Anthropic does not provide the embedding interface Metis uses.

## Install

```bash
pip install "metis[anthropic]"
```

## Configuration

Add or adjust the `llm_provider` block in your `metis.yaml`:

```yaml
llm_provider:
  name: "anthropic"
  model: "<claude-model-id>"
  api_key_env: "ANTHROPIC_API_KEY"

# Optional — only needed when the index tool is enabled.
embedding_provider:
  name: "openai"
  code_embedding_model: "text-embedding-3-large"
  docs_embedding_model: "text-embedding-3-large"

metis_engine:
  embed_dim: 3072
  pgvector_use_halfvec: auto

query:
  max_tokens: 5000
  temperature: 0.0
```

- `model` must be a Claude model ID accepted by the Anthropic API.
- The Anthropic API key is resolved from `llm_provider.api_key`, then
  `llm_provider.api_key_env`, then `ANTHROPIC_API_KEY`.
- Embeddings can be supplied via a separate `embedding_provider` block (any
  supported embedding provider).
- Embedding configuration is only required when the `index` tool is enabled
  (`--tools index`). It can be omitted entirely for chat/review/triage
  without retrieval.
- `metis_engine.embed_dim` must match the configured embedding model output
  dimension.
- For the PostgreSQL backend, `metis_engine.pgvector_use_halfvec: auto` uses
  pgvector `halfvec` storage for 3072-dimensional embeddings so HNSW indexing
  remains available.

Run Metis normally after the service credentials are available:

```bash
uv run metis --codebase-path <path>
```

# Gemini Provider

Metis can use Google Gemini models for chat, review, and triage. Gemini is
currently a chat-only provider in Metis; use a separate `embedding_provider`
when enabling the `index` tool.

## Install

```bash
pip install "metis[gemini]"
```

## Configuration

Add or adjust the `llm_provider` block in your `metis.yaml`:

```yaml
llm_provider:
  name: "gemini"
  model: "gemini-2.5-flash"
  api_key_env: "GOOGLE_API_KEY"

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

- `model` is passed directly to the Gemini API. Use an exact Gemini model ID.
- The Gemini API key is resolved from `llm_provider.api_key`, then
  `llm_provider.api_key_env`, then `GOOGLE_API_KEY`, then `GEMINI_API_KEY`.
- Configure embeddings separately through `embedding_provider` if you enable
  the `index` tool.
- `metis_engine.embed_dim` must match the configured embedding provider output
  dimension.
- For the PostgreSQL backend, `metis_engine.pgvector_use_halfvec: auto` uses
  pgvector `halfvec` storage for 3072-dimensional embeddings so HNSW indexing
  remains available.
- `query.reasoning_effort` values `minimal`, `low`, `medium`, and `high` are
  forwarded as Gemini `thinking_level`.

Optional backend fields are forwarded to `langchain-google-genai` when present:

```yaml
llm_provider:
  name: "gemini"
  model: "gemini-2.5-flash"
  api_key_env: "GOOGLE_API_KEY"
  base_url: "https://example.test/gemini"
  additional_headers:
    X-Custom-Header: "value"
  project: "my-gcp-project"
  location: "us-central1"
  vertexai: false
  client_args:
    timeout: 30
```

Run Metis normally after the service credentials are available:

```bash
uv run metis --codebase-path <path>
```

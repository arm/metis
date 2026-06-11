# Gemini Provider

Metis can use Google Gemini models for chat, review, and triage, with native
Gemini embeddings for indexing.

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
  code_embedding_model: "gemini-embedding-001"
  docs_embedding_model: "gemini-embedding-001"

metis_engine:
  embed_dim: 3072

query:
  max_tokens: 5000
  temperature: 0.0
```

- `model` is passed directly to the Gemini API. Use an exact Gemini model ID.
- The Gemini API key is resolved from `llm_provider.api_key`, then
  `llm_provider.api_key_env`, then `GOOGLE_API_KEY`, then `GEMINI_API_KEY`.
- The same API key is used for Gemini chat and Gemini embeddings.
- `code_embedding_model` and `docs_embedding_model` are native Gemini embedding
  model names.
- `metis_engine.embed_dim` must match the configured embedding model output
  dimension. You can set `output_dimensionality` through
  `code_embedding_extra_kwargs` and `docs_embedding_extra_kwargs` when using a
  reduced embedding size.
- `query.reasoning_effort` values `minimal`, `low`, `medium`, and `high` are
  forwarded as Gemini `thinking_level`.

Optional backend fields are forwarded to `langchain-google-genai` when present:

```yaml
llm_provider:
  name: "gemini"
  model: "gemini-2.5-flash"
  api_key_env: "GOOGLE_API_KEY"
  code_embedding_model: "gemini-embedding-001"
  docs_embedding_model: "gemini-embedding-001"
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

# Anthropic Provider

Metis can use Anthropic Claude models, including Claude Opus, for chat, review,
and triage. Indexing still requires an OpenAI-compatible embedding model because
Anthropic does not provide the embedding interface Metis uses.

## Configuration

Add or adjust the `llm_provider` block in your `metis.yaml`:

```yaml
llm_provider:
  name: "anthropic"
  model: "claude-opus-4-1-20250805"
  api_key_env: "ANTHROPIC_API_KEY"
  code_embedding_model: "text-embedding-3-large"
  docs_embedding_model: "text-embedding-3-large"
  embedding_api_key_env: "OPENAI_API_KEY"

metis_engine:
  embed_dim: 3072

query:
  max_tokens: 5000
  temperature: 0.0
```

- `model` must be an exact Claude model ID, such as
  `claude-opus-4-1-20250805`.
  Short aliases such as `opus` are not mapped by Metis.
- The Anthropic API key is resolved from `llm_provider.api_key`, then
  `llm_provider.api_key_env`, then `ANTHROPIC_API_KEY`.
- The embedding API key is resolved from `llm_provider.embedding_api_key`, then
  `llm_provider.embedding_api_key_env`, then `OPENAI_API_KEY`.
- `metis_engine.embed_dim` must match the configured embedding model output
  dimension.

Run Metis normally after the service credentials are available:

```bash
uv run metis --codebase-path <path>
```

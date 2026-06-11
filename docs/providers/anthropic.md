# Anthropic Provider

Metis can use Anthropic Claude models, including Claude Opus, for chat, review,
and triage. Indexing still requires an OpenAI-compatible embedding model because
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
  model: "opus"
  api_key_env: "ANTHROPIC_API_KEY"

# Optional — only needed when the index tool is enabled.
embedding_provider:
  name: "openai"
  code_embedding_model: "text-embedding-3-large"
  docs_embedding_model: "text-embedding-3-large"

metis_engine:
  embed_dim: 3072

query:
  max_tokens: 5000
  temperature: 0.0
```

- `model` can be an exact Claude model ID or one of Metis' short aliases.
- Short aliases map to Claude API model aliases as follows:
  - `opus` -> `claude-opus-4-8`
  - `sonnet` -> `claude-sonnet-4-6`
  - `haiku` -> `claude-haiku-4-5`
  - `fable` -> `claude-fable-5`
  - `mythos` -> `claude-mythos-5`
- You can still use an exact Claude model ID when you need stricter version
  control.
- The Anthropic API key is resolved from `llm_provider.api_key`, then
  `llm_provider.api_key_env`, then `ANTHROPIC_API_KEY`.
- Embeddings can be supplied via a separate `embedding_provider` block (any
  supported provider). The legacy `llm_provider.embedding_api_key` /
  `embedding_api_key_env` keys still work for OpenAI-compatible embeddings.
- Embedding configuration is only required when the `index` tool is enabled
  (`--tools index`). It can be omitted entirely for chat/review/triage
  without retrieval.
- `metis_engine.embed_dim` must match the configured embedding model output
  dimension.

Run Metis normally after the service credentials are available:

```bash
uv run metis --codebase-path <path>
```

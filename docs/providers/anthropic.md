# Anthropic Provider

Metis can use Anthropic Claude models, including Claude Opus, for chat, review,
and triage. Indexing still requires an OpenAI-compatible embedding model because
Anthropic does not provide the embedding interface Metis uses.

## Configuration

Add or adjust the `llm_provider` block in your `metis.yaml`:

```yaml
llm_provider:
  name: "anthropic"
  model: "opus"
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

- `model` can be an exact Claude model ID or one of Metis' short aliases.
- Short aliases map to Claude API model aliases as follows:
  - `opus` -> `claude-opus-4-8`
  - `sonnet` -> `claude-sonnet-4-6`
  - `haiku` -> `claude-haiku-4-5`
- You can still use an exact Claude model ID when you need stricter version
  control.
- The Anthropic API key is resolved from `llm_provider.api_key`, then
  `llm_provider.api_key_env`, then `ANTHROPIC_API_KEY`.
- The embedding API key is resolved from `llm_provider.embedding_api_key`, then
  `llm_provider.embedding_api_key_env`, then `OPENAI_API_KEY`.
- `metis_engine.embed_dim` must match the configured embedding model output
  dimension.

Embedding settings are only required when Metis needs indexes: `index`, `update`,
`ask`, or review/triage commands that use retrieval. You can omit the embedding
model and embedding API key for index-free scans, for example
`review_file <path> --ignore-index`, `review_code --ignore-index`,
`review_patch <path> --ignore-index`, or `triage <path.sarif> --ignore-index`.

Run Metis normally after the service credentials are available:

```bash
uv run metis --codebase-path <path>
```

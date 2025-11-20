# Ollama Provider

Metis can talk directly to [Ollama](https://github.com/ollama/ollama) through its OpenAI-compatible API, letting you run chat and embedding models locally with minimal configuration. Ollama listens on `http://localhost:11434` by default, accepts OpenAI-format requests, and supports the `/v1/chat/completions`, `/v1/completions`, `/v1/models`, and `/v1/embeddings` endpoints.

## Prerequisites

1. Install Ollama on the machine that will host the models.
2. Pull at least one chat model (for example `ollama pull llama3.2`) and one embedding model (for example `ollama pull all-minilm`).
3. Ensure the Ollama service is running. On macOS it auto-starts; on Linux run `ollama serve`. If the service runs on a different host, set `OLLAMA_HOST` (e.g. `0.0.0.0:11434`) so Metis can reach it over the network.

## Configuration

Add or adjust the `llm_provider` block in your `metis.yaml`:

```yaml
llm_provider:
  name: "ollama"
  base_url: "http://localhost:11434/v1"
  model: "llama3.2"
  code_embedding_model: "all-minilm"
  docs_embedding_model: "all-minilm"
```

- `base_url` can point to a remote host.
- Use the embedded model ids exposed by `ollama list` or `ollama show <model>`. The OpenAI-compatible `embeddings.create` call works with models such as `all-minilm`.
- `metis_engine.max_token_length` should not exceed the model’s context window. Adjust it (and optionally `query.max_tokens`) to match the model you are using.

## Metis usage

Once the service responds, run `uv run metis --codebase-path <path>` (or `metis` inside your virtual environment) and use the usual `index`, `review_code`, or `review_file` commands. Metis will route chat and embedding requests to Ollama using the OpenAI-compatible client APIs.

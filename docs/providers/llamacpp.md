# llama.cpp Provider

Metis can talk directly to [llama.cpp](https://github.com/ggml-org/llama.cpp)'s HTTP server, letting you run chat and embedding models locally without any cloud dependency.

The llama.cpp server can be used as a drop-in replacement for OpenAI-compatible providers and exposes the following endpoints:
- `/v1/chat/completions`
- `/v1/completions`
- `/v1/embeddings`
- `/v1/models`
- `/v1/responses`

## Prerequisites

1. Install the [llama.cpp](https://github.com/ggml-org/llama.cpp) server.
2. Pull at least one chat model and one embedding model (GGUF format).
   - Chat model examples
     - e.g. for 8GB system, `Llama3.1-8B`
     - e.g. for 16GB system, `Qwen3.5-9B`
     - e.g. for 24GB system, `Qwen3.6-35B-A3B`
   - Embedding model example
     - e.g. `nomic-embed-text-v1.5`
3. Start the llama.cpp server with both the chat and embedding models. The server can serve multiple models simultaneously.

   ```bash
   llama-server \
     --model /path/to/model.gguf \
     --ctx-size 128000 \
     --embedding
   ```

   > The `--embedding` flag enables the embeddings endpoint. Without it, Metis cannot build the vector store.
   > The `--ctx-size` should match or exceed `metis_engine.max_token_length`.

## Configuration

Add or adjust the `llm_provider` block in your `metis.yaml`:

```yaml
llm_provider:
  name: "llamacpp"
  base_url: "http://localhost:8080/v1"
  model: "Llama3.1-8B"
  code_embedding_model: "nomic-embed-text-v1.5"
  docs_embedding_model: "nomic-embed-text-v1.5"
```

- `base_url` defaults to `http://localhost:8080/v1` if not configured.
- `name` must be `"llamacpp"` (case-insensitive).
- `model` is required. `code_embedding_model` / `docs_embedding_model` are only required when the `index` tool is enabled.
- An API key is **not required** by the llama.cpp server; Metis uses a placeholder by default.

## Metis usage

Once the server responds, run `uv run metis --codebase-path <path>` (or `metis` inside your virtual environment) and use the usual `index`, `review_code`, or `review_file` commands. Metis will route model requests through the OpenAI Responses API and embedding requests through the OpenAI-compatible embeddings API.

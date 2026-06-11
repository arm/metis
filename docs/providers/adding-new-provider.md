# Adding a New LLM Provider

Metis discovers providers through `src/metis/providers/registry.py`. Each provider module registers itself via `register_provider()` so the CLI can instantiate it based on `llm_provider.name` (and optionally `embedding_provider.name`) in `metis.yaml`.

## Provider Types

### Option 1: `OpenAICompatibleProvider` (recommended)

For backends exposing OpenAI-compatible endpoints (`/v1/chat/completions`, `/v1/embeddings`), inherit from `OpenAICompatibleProvider` in `src/metis/providers/openai_compatible.py`. It handles chat models, embeddings, and reasoning effort.

**Examples:** [ollama.py](../../src/metis/providers/ollama.py), [vllm.py](../../src/metis/providers/vllm.py), [llamacpp.py](../../src/metis/providers/llamacpp.py)

```python
from metis.providers.openai_compatible import OpenAICompatibleProvider
from metis.providers.registry import register_provider

class MyProvider(OpenAICompatibleProvider):
    def __init__(self, config):
        super().__init__(
            config,
            default_base_url="http://localhost:9000/v1",
            default_api_key="sk-placeholder",
        )

register_provider("my_provider", MyProvider)
```

### Option 2: `LLMProvider` (for non-OpenAI backends)

For backends with a different API, inherit directly from `LLMProvider` (abstract base in `src/metis/providers/base.py`). Implement three methods:

| Method | Returns | Purpose |
|--------|---------|---------|
| `get_chat_model()` | `BaseChatModel` | LangChain chat model |
| `get_embed_model_code()` | `BaseEmbedding` | Code embeddings for vector store |
| `get_embed_model_docs()` | `BaseEmbedding` | Docs embeddings for vector store |

Defer validation to the method that needs it: check chat-model config in `get_chat_model()`, embedding config in `get_embed_model_*()`. The same provider class may be instantiated for chat only (via `llm_provider`) or embeddings only (via `embedding_provider`), so `__init__` should not require both. Wrap your LangChain `Embeddings` client in `LangChainEmbeddingAdapter` to satisfy the LlamaIndex `BaseEmbedding` return type.

If the backend's models may reject `temperature`, gate it behind a `supports_temperature` config flag (default `False`) and drop the kwarg when unset.

**Examples:** [azure_openai.py](../../src/metis/providers/azure_openai.py), [bedrock.py](../../src/metis/providers/bedrock.py), [gemini.py](../../src/metis/providers/gemini.py)

## Required Registration

You must update **three locations**:

### 1. `registry.py` — lazy loader

Add at the bottom of `src/metis/providers/registry.py`:

```python
register_provider_loader("my_provider", "metis.providers.my_provider:MyProvider")
```

### 2. `configuration.py` — config validation + runtime wiring

Add entries to these dicts:

```python
_LLM_PROVIDER_DISPLAY_NAMES["my_provider"] = "My Provider"

# Chat-side keys (validated at config load)
_LLM_PROVIDER_REQUIRED_KEYS["my_provider"] = ("model",)

# Embedding-side keys (validated only when the index tool is enabled)
_EMBEDDING_PROVIDER_REQUIRED_KEYS["my_provider"] = (
    "code_embedding_model",
    "docs_embedding_model",
)

_LLM_PROVIDER_API_KEY_SOURCES["my_provider"] = {
    "required": True,
    "config_keys": (),
    "config_env_keys": (),
    "env_vars": ("MY_PROVIDER_API_KEY",),
}
```

Then add a branch in `_build_provider_runtime()` — the trailing `else` raises `ValueError` for unknown providers:

```python
elif provider_name == "my_provider":
    runtime["llm_api_key"] = api_key
    runtime["openai_api_base"] = cfg.get("base_url", "")
    runtime["openai_default_headers"] = cfg.get("default_headers", {})
    runtime["model"] = cfg.get("model", "")
```

This branch is called for both `llm_provider` and `embedding_provider` blocks, so it must tolerate either set of keys being absent.

### 3. Your provider module — `register_provider()` call

Your module **must** call `register_provider()` at module level (the lazy loader imports the module, which triggers this registration).

## Dependencies

If the provider needs packages outside the base install, add an `optional-dependencies.<provider>` extra in `pyproject.toml` and list it in `optional-dependencies.all-providers`. The lazy loader converts `ModuleNotFoundError` into a clear "required dependencies are missing" error. Guard the provider's tests with `pytest.importorskip("<package>")` so a base-only CI run skips them.

## Configuration

Provider-specific config keys go under `llm_provider:` (and/or `embedding_provider:`) in `metis.yaml`. Common keys used by `OpenAICompatibleProvider`:

| Key | Example |
|-----|---------|
| `name` | `"my_provider"` |
| `model` | `"llama3.1:8b"` |
| `base_url` | `"http://localhost:9000/v1"` |
| `code_embedding_model` | `"nomic-embed-text"` |
| `docs_embedding_model` | `"nomic-embed-text"` |
| `default_headers` | `{"X-Custom": "value"}` |

Query-level settings (`model`, `temperature`, `max_tokens`, `reasoning_effort`) go under `query:` in `metis.yaml` and override `llm_provider:` values.

## Testing

Cover these in `tests/test_<provider>.py`:

- Instantiation with valid config
- `get_chat_model()` raises on missing chat config; `get_embed_model_*()` raises on missing embedding config
- Chat model construction (class type, base_url, reasoning_effort)
- `supports_temperature` gates the `temperature` kwarg
- Embedding model construction
- Lazy loader registration (verify `_LOADERS` entry and `get_provider()` resolution)

See `tests/test_bedrock_provider.py` and `tests/test_configuration.py` for examples.

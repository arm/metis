# Adding a New LLM Provider

Metis discovers providers through `src/metis/providers/registry.py`. Each provider module registers itself via `register_provider()` so the CLI can instantiate it based on `llm_provider.name` in `metis.yaml`.

## Provider Types

### Option 1: `OpenAICompatibleProvider` (recommended)

For backends exposing OpenAI-compatible endpoints (`/v1/chat/completions`, `/v1/embeddings`), inherit from `OpenAICompatibleProvider` in `src/metis/providers/openai_compatible.py`. It handles chat models, embeddings, query engines, reasoning effort, and context window resolution.

**Examples:** [ollama.py](../../src/metis/providers/ollama.py), [vllm.py](../../src/metis/providers/vllm.py)

```python
from metis.providers.openai_compatible import OpenAICompatibleProvider
from metis.providers.registry import register_provider

class MyProvider(OpenAICompatibleProvider):
    def __init__(self, config):
        super().__init__(
            config,
            default_base_url="http://localhost:9000/v1",
            default_api_key="sk-placeholder",
            # force_openai_like=True,  # uncomment if the API diverges from OpenAI's
        )

register_provider("my_provider", MyProvider)
```

### Option 2: `LLMProvider` (for non-OpenAI backends)

For backends with a different API, inherit directly from `LLMProvider` (abstract base in `src/metis/providers/base.py`). You must implement 5 methods:

| Method | Returns | Purpose |
|--------|---------|---------|
| `get_embed_model_code()` | `BaseEmbedding` | Code embeddings for vector store |
| `get_embed_model_docs()` | `BaseEmbedding` | Docs embeddings for vector store |
| `get_chat_model()` | `BaseChatModel` | LangChain chat model |
| `get_query_engine_class()` | `type[object]` | LlamaIndex LLM class |
| `get_query_model_kwargs()` | `QueryModelKwargs` | Kwargs for query engine LLM |

**Example:** [azure_openai.py](../../src/metis/providers/azure_openai.py)

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

_LLM_PROVIDER_REQUIRED_KEYS["my_provider"] = (
    "model",
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

Then add a branch in `load_runtime_config()` — the `else` clause raises `ValueError` for unknown providers:

```python
elif llm_provider_name == "my_provider":
    runtime["llm_api_key"] = llm_api_key
    runtime["openai_api_base"] = llm_cfg.get("base_url", "")
    runtime["openai_default_headers"] = llm_cfg.get("default_headers", {})
    runtime["model"] = llm_cfg.get("model", "")
```

### 3. Your provider module — `register_provider()` call

Your module **must** call `register_provider()` at module level (the lazy loader imports the module, which triggers this registration).

## Configuration

Provider-specific config keys go under `llm_provider:` in `metis.yaml`. Common keys used by `OpenAICompatibleProvider`:

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
- Missing required config raises `ValueError`
- Chat model construction (class type, base_url, reasoning_effort)
- Query engine class identity
- Embedding model construction
- Lazy loader registration (verify `get_provider` doesn't import early)

See `tests/test_openai_compatible_provider.py` and `tests/test_configuration.py` for examples.

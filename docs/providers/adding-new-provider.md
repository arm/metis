# Adding a New Provider

Metis has separate provider surfaces for chat and embeddings. Chat providers
implement `ChatProvider`; embedding providers implement `EmbeddingProvider`.
A backend can support one or both, but each surface has its own entry point
and configuration spec.

## Provider Types

### OpenAI-Compatible Providers

For backends exposing OpenAI-compatible endpoints, reuse the shared base
classes in `src/metis/providers/openai_compatible.py`:

```python
from metis.providers.config import ApiKeySources, ProviderConfigSpec
from metis.providers.openai_compatible import OpenAICompatibleChatProvider
from metis.providers.openai_compatible import OpenAICompatibleEmbeddingProvider


class MyProvider(OpenAICompatibleChatProvider):
    CONFIG_SPEC = ProviderConfigSpec(
        display_name="My Provider",
        required_keys=("base_url", "model"),
        api_key=ApiKeySources(required=True, env_vars=("MY_PROVIDER_API_KEY",)),
        copy_keys=("base_url", "default_headers", "model"),
    )


class MyEmbeddingProvider(OpenAICompatibleEmbeddingProvider):
    CONFIG_SPEC = ProviderConfigSpec(
        display_name="My Provider embeddings",
        required_keys=("base_url", "code_embedding_model", "docs_embedding_model"),
        api_key=ApiKeySources(required=True, env_vars=("MY_PROVIDER_API_KEY",)),
        copy_keys=(
            "base_url",
            "default_headers",
            "code_embedding_model",
            "docs_embedding_model",
            "code_extra_kwargs",
            "docs_extra_kwargs",
        ),
    )

```

Examples: `openai.py`, `ollama.py`, `vllm.py`, `llamacpp.py`.

### Provider-Specific APIs

For non-OpenAI APIs, implement the relevant interface directly:

| Interface | Required method | Purpose |
| --- | --- | --- |
| `ChatProvider` | `get_chat_model()` | Return a LangChain chat model. |
| `EmbeddingProvider` | `get_embed_model_code()` / `get_embed_model_docs()` | Return LlamaIndex-compatible embeddings. |

Wrap LangChain `Embeddings` clients with `LangChainEmbeddingAdapter` so they
match the LlamaIndex `BaseEmbedding` API used by the vector store.

Examples: `azure_openai.py`, `bedrock.py`, `gemini.py`, `bedrock_mantle.py`.

## Configuration Specs

Each provider class owns its config contract through `CONFIG_SPEC`.
`configuration.py` reads that spec, resolves API keys, validates required
keys, and returns the provider-specific runtime config.

Use `ProviderConfigSpec` for:

- `display_name`: provider name used in error messages.
- `required_keys`: keys required in the relevant config block.
- `api_key`: where credentials can be read from.
- `copy_keys`: config keys copied into the provider runtime config. Use a tuple
  for direct copies, or a mapping only when a runtime key needs alternate
  source keys.

Do not add provider-specific branches to `configuration.py` unless the config
shape cannot be expressed with `ProviderConfigSpec`.

## Discovery

Providers are discovered from the `metis.providers` entry point group. Built-in
providers declare those entry points in `pyproject.toml`; third-party provider
packages can expose the same group.

Entry point names use `<provider>.<surface>`, where `<surface>` is `chat` or
`embedding`:

```toml
entry-points."metis.providers"."my_provider.chat" = "my_package.providers:MyProvider"
entry-points."metis.providers"."my_provider.embedding" = "my_package.providers:MyEmbeddingProvider"
```

Only register the surfaces the backend actually supports. Chat-only providers
must not declare an embedding entry point. Provider modules should not register
themselves at import time; the registry discovers entry point values without
importing provider modules and caches the class when the provider is first
requested.

## User Configuration

Chat config goes under `llm_provider`; embedding config goes under the
top-level `embedding_provider` block:

```yaml
llm_provider:
  name: "my_provider"
  base_url: "https://example.test/v1"
  model: "chat-model"
  api_key_env: "MY_PROVIDER_API_KEY"

embedding_provider:
  name: "my_provider"
  base_url: "https://example.test/v1"
  code_embedding_model: "embedding-model"
  docs_embedding_model: "embedding-model"
  api_key_env: "MY_PROVIDER_API_KEY"
```

Embedding config is only required when the `index` tool is enabled.

## Dependencies

If the provider needs packages outside the base install, add an
`optional-dependencies.<provider>` extra in `pyproject.toml` and include it in
`optional-dependencies.all-providers`. Guard provider tests with
`pytest.importorskip("<package>")` when a base-only CI run should skip them.

## Testing

Cover these in `tests/test_<provider>.py`:

- Valid config builds the expected LangChain/LlamaIndex objects.
- Missing required chat keys fail through config validation.
- Missing required embedding keys fail when `build_embedding_provider_config()`
  is called.
- API key precedence works for explicit `api_key`, `api_key_env`, and provider
  default env vars.
- Entry point discovery resolves the provider class.

Keep private live-provider smoke tests local under ignored paths such as
`local-tests/`. Store credentials in ignored `.env` files or environment
variables, never in committed YAML.

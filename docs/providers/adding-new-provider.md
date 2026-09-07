# Adding a New Provider

Metis has separate provider surfaces for chat and embeddings. Chat providers
implement `ChatProvider`; embedding providers implement `EmbeddingProvider`.
A backend can support one or both, but each surface has its own entry point
and configuration spec.

The paths below are the current in-tree provider extension surface. Third-party
providers importing `metis.providers.*` must pin and test a compatible Metis
range because there is not yet a top-level stable provider facade.

## Provider Types

### OpenAI-Compatible Providers

For backends exposing the compatible Responses API, reuse the shared base
classes in `src/metis/providers/openai_compatible.py`. A backend that supports
only Chat Completions needs its own chat implementation because the shared base
forces `use_responses_api=True`:

```python
from metis.providers.config import ApiKeySources
from metis.providers.config import ProviderConfigSpec
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

`ProviderConfigSpec` is a required-key, credential, and copy/filter contract; it
does not generally type-check copied values or reject unknown provider keys.
Validate provider-specific types and relationships in the provider constructor
before creating an SDK client. Optional-auth OpenAI-compatible backends must
also set a provider-safe, non-secret `DEFAULT_API_KEY` for chat and embeddings
to prevent accidental fallback to `OPENAI_API_KEY`; test with that environment
variable set. Providers whose models are not tiktoken-compatible may need their
own `count_tokens()`.

## Discovery

Providers are discovered from the `metis.providers` entry point group. Built-in
providers declare those entry points in `pyproject.toml`; third-party provider
packages can expose the same group.

Entry point names use `<provider>.<surface>`, where `<surface>` is `chat` or
`embedding`:

```toml
[project.entry-points."metis.providers"]
"my_provider.chat" = "my_package.providers:MyProvider"
"my_provider.embedding" = "my_package.providers:MyEmbeddingProvider"
```

Only register the surfaces the backend actually supports. Chat-only providers
must not declare an embedding entry point. Provider modules should not register
themselves at import time; the registry discovers entry point values without
importing provider modules and caches the class when the provider is first
requested.

Keep optional SDK imports inside the method that constructs the selected client,
or guard them so loading the selected provider class produces an actionable
missing-extra error. Verify that base-package configuration and unrelated
providers still load without the optional dependency.

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

Index operations require `embedding_provider` only when the vector backend does
not already supply both embedding models. This includes the `index`, `ask`, and
`update` commands and an explicitly selected `initialize.index` node.

## Dependencies

For a built-in provider, add any non-base SDK to an optional extra in
`pyproject.toml` and include that extra in `optional-dependencies.all-providers`.
The extra's package-facing name need not equal the provider id. An external
provider instead owns its dependencies and extras; it does not edit Metis
metadata or documentation.

Guard SDK-backed tests with `pytest.importorskip("<package>")`, but retain a
base-only subprocess check that explicitly resolves the provider without its
SDK, then verifies client construction gives the actionable install-extra error.

## Testing

Cover the supported surfaces only:

- `tests/test_<provider>.py`: client construction, argument forwarding, and
  provider-specific validation.
- `tests/test_configuration.py`: required keys, copied values, and API-key
  precedence.
- `tests/test_provider_registry.py`: entry-point discovery and rejection of an
  unsupported chat or embedding surface.
- `tests/test_provider_token_count.py` when token counting differs.
- A base-only subprocess: resolving the provider does not import the optional
  SDK before client construction.

When a selected node uses model tools, verify the returned chat model's
`bind_tools` and structured-output behavior.

Every new provider changes entry-point metadata. Build its distribution and
exercise discovery/resource loading from the built artifact.

For a built-in provider, add a guide covering installation, supported surfaces,
exact YAML keys, credentials, and limitations; link it from the README matrix.
Dual-surface built-ins also belong in `docs/providers/embedding-provider.md`.
External providers own equivalent documentation in their package.

Keep private live-provider smoke tests local under ignored paths such as
`local-tests/`. Store credentials in ignored `.env` files or environment
variables, never in committed YAML.

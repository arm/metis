# Adding a New LLM Provider

Metis discovers providers through the registry in `src/metis/providers/registry.py`.
Each provider module calls `register_provider("<name>", ProviderClass)` so the CLI can
instantiate it based on the `llm_provider.name` value in `metis.yaml`.

To add a provider:

1. Create a module under `src/metis/providers/` (for example `my_provider.py`).
2. Implement a class inheriting from `metis.providers.base.LLMProvider`. The class must
   implement `get_chat_model`, `get_embed_model_code`, and `get_embed_model_docs`.
3. Import any SDKs you need and wire configuration values from the `config` dictionary
   passed to the constructor.
4. Either register a lazy loader or register on import:
   - **Lazy loader (preferred for built-ins):**
     ```python
     from metis.providers.registry import register_provider_loader

     register_provider_loader("my_provider", "metis.providers.my_provider:MyProvider")
     ```
     The registry will import your module the first time someone selects
     `llm_provider.name = "my_provider"`.
   - **Immediate registration (useful for third-party plugins):**
   ```python
   from metis.providers.registry import register_provider

   register_provider("my_provider", MyProviderClass)
   ```
5. Document any new configuration keys and update `metis.yaml` defaults or example
   configs if necessary.

With the provider registered, users can enable it by setting:
```yaml
llm_provider:
  name: "my_provider"
  # additional provider-specific fields...
```

Tests should cover provider configuration parsing and smoke tests for chat and
embedding calls using the new backend or suitable mocks.

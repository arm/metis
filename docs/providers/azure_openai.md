# Azure OpenAI Provider

Metis uses LangChain's Azure integrations for Azure OpenAI chat and
embeddings. Chat and embeddings are configured separately so a chat deployment
does not need to carry embedding settings.

## Configuration

```yaml
llm_provider:
  name: "azure_openai"
  azure_endpoint: "https://<resource>.openai.azure.com/"
  azure_api_version: "2024-12-01-preview"
  engine: "<chat-deployment-name>"
  chat_deployment_model: "<chat-model-name>"

embedding_provider:
  name: "azure_openai"
  azure_endpoint: "https://<resource>.openai.azure.com/"
  azure_api_version: "2024-02-01"
  code_embedding_model: "text-embedding-3-small"
  docs_embedding_model: "text-embedding-3-small"
  code_deployment: "<embedding-deployment-name>"
  docs_deployment: "<embedding-deployment-name>"

metis_engine:
  embed_dim: 1536
```

The Azure OpenAI API key is resolved from `api_key`, then `api_key_env`, then
`AZURE_OPENAI_API_KEY`.

## Chat APIs

By default Metis uses `AzureChatOpenAI` through the chat completions surface.
If a deployment should use Azure's Responses API, opt in explicitly:

```yaml
llm_provider:
  name: "azure_openai"
  azure_endpoint: "https://<resource>.openai.azure.com/"
  azure_api_version: "2025-04-01-preview"
  engine: "<chat-deployment-name>"
  chat_deployment_model: "<chat-model-name>"
  use_responses_api: true
```

Keep the `azure_api_version` aligned with the API surface your Azure
deployment supports.

## Embeddings

Azure embeddings use `AzureOpenAIEmbeddings`. Azure needs both the model name
and deployment name; deployments can be named differently from the underlying
model. Set `metis_engine.embed_dim` to the vector size returned by the
embedding deployment.

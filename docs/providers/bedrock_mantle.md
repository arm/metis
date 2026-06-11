# Amazon Bedrock Mantle provider

Use this provider for Anthropic Claude models exposed through Amazon Bedrock
Mantle with AWS SigV4 authentication.

## Install

```bash
pip install "metis[bedrock-mantle]"
```

First configure and log in to an AWS profile with access to Bedrock Mantle:

```bash
aws configure sso --profile <aws-profile>
aws sso login --profile <aws-profile>
aws sts get-caller-identity --profile <aws-profile>
```

Then add or adjust the `llm_provider` block in your `metis.yaml`:

```yaml
llm_provider:
  name: "bedrock_mantle"
  model: "anthropic.<claude-model-id>"
  aws_profile: "<aws-profile>"
  aws_region: "<aws-region>"
  code_embedding_model: "text-embedding-3-large"
  docs_embedding_model: "text-embedding-3-large"
  embedding_api_key_env: "OPENAI_API_KEY"
```

Notes:

- `aws_profile` is optional if your standard AWS credential chain is already
  configured through environment variables, an assumed role, ECS, or IMDS.
- `aws_region` is optional if `AWS_REGION` or `AWS_DEFAULT_REGION` is set in
  the environment, but setting it explicitly in `metis.yaml` is recommended.
- `temperature` is not sent by default. If your target model supports
  temperature, set `supports_temperature: true` under `llm_provider`.
- Metis still needs an embedding provider. The example above uses OpenAI
  embeddings via `OPENAI_API_KEY`.

# Amazon Bedrock Mantle provider

Use this provider for Anthropic Claude models exposed through Amazon Bedrock
Mantle with AWS SigV4 authentication, using LangChain's `ChatAnthropicMantle`.

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

Then add or adjust the `llm_provider` block in your trusted configuration file
and select it when running Metis with `--config PATH`:

```yaml
llm_provider:
  name: "bedrock_mantle"
  model: "anthropic.<claude-model-id>"
  aws_profile: "<aws-profile>"
  aws_region: "<aws-region>"
  # Optional; use an effort supported by the selected model:
  # reasoning_effort: "high"
```

Notes:

- `aws_profile` is optional if your standard AWS credential chain is already
  configured through environment variables, an assumed role, ECS, or IMDS.
- `aws_region` is optional if `AWS_REGION` or `AWS_DEFAULT_REGION` is set in
  the environment, but setting it explicitly in `metis.yaml` is recommended.
- `temperature` is not sent by default. If your target model supports
  temperature, set `supports_temperature: true` under `llm_provider`.
- Set `llm_provider.reasoning_effort`, or override it with
  `query.reasoning_effort`, to control Claude's `output_config.effort`. Metis
  forwards the value to the native SDK, which handles adaptive thinking for
  supported models. Use a level supported by the selected model (`low`, `medium`,
  `high`, `xhigh`, or `max`); omit the setting to leave model defaults unchanged.
- Mantle is chat-only. If you enable the `index` tool, configure a separate
  [`embedding_provider`](embedding-provider.md) (e.g. `bedrock` for Titan
  embeddings using the same AWS credentials, or `openai`).

# AWS Bedrock provider

Use this provider to run Metis against models hosted on Amazon Bedrock —
Anthropic Claude for chat, and Titan or Cohere for embeddings — via the
Bedrock Converse API.

## Install

```bash
pip install "metis[bedrock]"
```

## Configure

Save this configuration in a trusted file and select it with `--config PATH`;
Metis does not automatically load repository-local configuration.

```yaml
llm_provider:
  name: "bedrock"
  region: "us-east-1"
  model: "us.anthropic.claude-opus-4-8"
  # Optional; use an effort supported by the selected model:
  # reasoning_effort: "high"

embedding_provider:
  name: "bedrock"
  region: "us-east-1"
  code_embedding_model: "amazon.titan-embed-text-v2:0"
  docs_embedding_model: "amazon.titan-embed-text-v2:0"
```

| Key                     | Required | Notes                                                              |
| ----------------------- | -------- | ------------------------------------------------------------------ |
| `region`                | yes      | Bedrock region (e.g. `us-east-1`).                                 |
| `model`                 | yes²     | Bedrock chat model or inference-profile ID.                        |
| `code_embedding_model`  | yes¹     | Bedrock embedding model ID for code indexing.                      |
| `docs_embedding_model`  | yes¹     | Bedrock embedding model ID for docs indexing.                      |
| `aws_profile`           | no       | Named profile from `~/.aws/credentials`.                           |
| `aws_access_key_id`     | no       | Explicit credential (paired with `aws_secret_access_key`).         |
| `aws_secret_access_key` | no       | Explicit credential.                                               |
| `aws_session_token`     | no       | Optional session token for temporary credentials.                  |
| `endpoint_url`          | no       | Override Bedrock endpoint (e.g. VPC interface endpoint).           |
| `supports_temperature`  | no       | Set `true` only if the target model accepts `temperature`.         |
| `reasoning_effort`       | no       | Model-supported effort level; `query.reasoning_effort` overrides. |

¹ Required under `embedding_provider` only when the Index capability cannot
reuse embedding models supplied by the vector backend.
² Only required under `llm_provider`.

Reasoning effort is forwarded to `ChatBedrockConverse`, which validates the level
and translates it into the model's native request fields. For supported Claude
models, this sets `output_config.effort` and enables adaptive thinking through
`additionalModelRequestFields`. Omit the setting to leave model defaults unchanged.
Support follows the installed `langchain-aws` model catalog: an unsupported or
unrecognized model emits an SDK warning and ignores the effort. Use the exact
model or inference-profile ID; Opus 4.8 IDs do not have a `-v1:0` suffix.

## Credentials

Credential precedence is: explicit `aws_access_key_id`/`aws_secret_access_key`
in `metis.yaml` → `aws_profile` → boto3's default credential chain
(`AWS_PROFILE` / `AWS_ACCESS_KEY_ID` env vars, `~/.aws/credentials`, IAM role).

## Embeddings

Set `metis_engine.embed_dim` to match your embedding model's output dimension
(`1024` for `amazon.titan-embed-text-v2:0`, `1024` for `cohere.embed-english-v3`).

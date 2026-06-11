# AWS Bedrock provider

Use this provider to run Metis against models hosted on Amazon Bedrock —
Anthropic Claude for chat, and Titan or Cohere for embeddings — via the
Bedrock Converse API.

## Install

```bash
pip install "metis[bedrock]"
```

## Configure

```yaml
llm_provider:
  name: "bedrock"
  region: "us-east-1"
  model: "us.anthropic.claude-opus-4-8-v1:0"
  code_embedding_model: "amazon.titan-embed-text-v2:0"
  docs_embedding_model: "amazon.titan-embed-text-v2:0"
```

| Key                     | Required | Notes                                                              |
| ----------------------- | -------- | ------------------------------------------------------------------ |
| `region`                | yes      | Bedrock region (e.g. `us-east-1`).                                 |
| `model`                 | yes      | Bedrock model or inference-profile ID.                             |
| `code_embedding_model`  | yes¹     | Bedrock embedding model ID for code indexing.                      |
| `docs_embedding_model`  | yes¹     | Bedrock embedding model ID for docs indexing.                      |
| `aws_profile`           | no       | Named profile from `~/.aws/credentials`.                           |
| `aws_access_key_id`     | no       | Explicit credential (paired with `aws_secret_access_key`).         |
| `aws_secret_access_key` | no       | Explicit credential.                                               |
| `aws_session_token`     | no       | Optional session token for temporary credentials.                  |
| `endpoint_url`          | no       | Override Bedrock endpoint (e.g. VPC interface endpoint).           |
| `supports_temperature`  | no       | Set `true` only if the target model accepts `temperature`.         |

¹ Only required when the `index` engine tool is enabled.

## Credentials

Credential precedence is: explicit `aws_access_key_id`/`aws_secret_access_key`
in `metis.yaml` → `aws_profile` → boto3's default credential chain
(`AWS_PROFILE` / `AWS_ACCESS_KEY_ID` env vars, `~/.aws/credentials`, IAM role).

## Embeddings

Set `metis_engine.embed_dim` to match your embedding model's output dimension
(`1024` for `amazon.titan-embed-text-v2:0`, `1024` for `cohere.embed-english-v3`).

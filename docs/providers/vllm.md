# vLLM Provider (OpenAI-Compatible)

We recommend fronting your vLLM deployments with a LiteLLM proxy so Metis only
ever speaks OpenAI-compatible JSON over a single `/v1` endpoint. The proxy
handles routing, retries, and API keys; Metis stays unaware of however many
backends you run.

This walkthrough launches:

- One vLLM instance serving your preferred chat/completions model.
- A second vLLM instance serving an embedding model.
- A LiteLLM router that joins them behind a single `/v1` endpoint.

## Requirements

- An NVIDIA GPU with a recent driver, CUDA runtime, and the NVIDIA Container Toolkit.
- A container runtime that can access your GPUs (for example, Docker with NVIDIA support).
- Hugging Face Hub access if the models you choose are gated.

## Environment

Set common variables:

```bash
export HF_TOKEN="hf_xxx"            # optional for public repos
export VLLM_API_KEY="token-abc123"  # shared secret for Metis client
export LLM_HOST_IP="<router-host-ip>"  # address reachable by Metis
```

## 1. Launch the chat model

```bash
sudo docker run --gpus all --rm --shm-size 32g \
  -p 8000:8000 \
  -e HF_TOKEN=$HF_TOKEN \
  nvcr.io/nvidia/vllm:25.09-py3 \
  vllm serve <chat-model-id> \
    --host 0.0.0.0 \
    --tensor-parallel-size <chat-tp-size>\
    --max-model-len <chat-context-length> \
    --api-key $VLLM_API_KEY
```

## 2. Launch the embedding model

```bash
sudo docker run --gpus all --rm --shm-size 16g \
  -p 8001:8000 \
  -e HF_TOKEN=$HF_TOKEN \
  nvcr.io/nvidia/vllm:25.09-py3 \
  vllm serve <embedding-model-id> \
    --host 0.0.0.0 \
    --task embed \
    --max-model-len <embed-context-length> \
    --gpu-memory-utilization <embed-gpu-util> \
    --api-key $VLLM_API_KEY
```

> Pick `--max-model-len` equal to the embedding model’s documented context
> window. For models limited to 512 tokens, keep your Metis chunk sizes under
> that threshold (see Troubleshooting).

## 3. Combine endpoints with LiteLLM

Create `litellm-config.yaml`:

```yaml
router_settings:
  host: 0.0.0.0
  port: 8888
  general_settings:
    api_key: "${VLLM_API_KEY}"

model_list:
  - model_name: <chat-model-id>
    litellm_params:
      model: openai/<chat-model-id>
      api_base: "http://${LLM_HOST_IP}:8000/v1"
      api_key: "${VLLM_API_KEY}"

  - model_name: <embedding-model-id>
    litellm_params:
      model: openai/<embedding-model-id>
      task: embed
      api_base: "http://${LLM_HOST_IP}:8001/v1"
      api_key: "${VLLM_API_KEY}"
```

Launch LiteLLM:

```bash
sudo docker run --rm \
  -p 8888:8888 \
  -e VLLM_API_KEY=$VLLM_API_KEY \
  -e LLM_HOST_IP=$LLM_HOST_IP \
  -v $(pwd)/litellm-config.yaml:/app/config.yaml \
  ghcr.io/berriai/litellm:main \
  litellm --config /app/config.yaml
```

Clients now send chat and embedding calls to `http://$LLM_HOST_IP:8888/v1`
with `Authorization: Bearer $VLLM_API_KEY`.

## 4. Configure Metis

Point Metis at the LiteLLM proxy by updating `metis.yaml`:

```yaml
llm_provider:
  name: "vllm"
  base_url: "http://${LLM_HOST_IP}:8888/v1"
  model: "<chat-model-id>"
  code_embedding_model: "<embedding-model-id>"
  docs_embedding_model: "<embedding-model-id>"

metis_engine:
  embed_dim: <embedding-dimension>  # must match embedding model output

query:
  model: "<chat-model-id>"
  temperature: 0.0
  max_tokens: 1024
```

Then run Metis:

```bash
uv run metis <options>
```

## Troubleshooting

- `ContextWindowExceededError` during indexing: keep Metis chunk sizes below the embedding model’s context window. For a 512-token embedding model, set these knobs in `metis.yaml`:

  ```yaml
  metis_engine:
    doc_chunk_size: 448
    doc_chunk_overlap: 96
  ```

  Adjust the `doc_chunk_size` for larger context windows, leaving enough headroom for overlap and metadata.

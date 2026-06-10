# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.configuration import load_metis_config
from metis.configuration import load_runtime_config

import pytest


def test_load_metis_config_uses_yml_when_yaml_missing(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "metis.yml").write_text("selected: yml\n", encoding="utf-8")

    config = load_metis_config()

    assert config == {"selected": "yml"}


def test_load_metis_config_prefers_yaml_over_yml(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "metis.yaml").write_text("selected: yaml\n", encoding="utf-8")
    (tmp_path / "metis.yml").write_text("selected: yml\n", encoding="utf-8")

    config = load_metis_config()

    assert config == {"selected": "yaml"}


def test_load_runtime_config_reads_query_reasoning_effort(tmp_path, monkeypatch):
    config_path = tmp_path / "metis.yaml"
    config_path.write_text(
        """
llm_provider:
  name: openai
  model: gpt-test
  code_embedding_model: text-embedding-3-large
  docs_embedding_model: text-embedding-3-large
metis_engine:
  max_workers: 2
query:
  reasoning_effort: high
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    runtime = load_runtime_config(config_path)

    assert runtime["llama_query_reasoning_effort"] == "high"
    assert runtime["llama_query_max_tokens"] == 3072


def test_load_runtime_config_accepts_query_reasoning_level_alias(tmp_path, monkeypatch):
    config_path = tmp_path / "metis.yaml"
    config_path.write_text(
        """
llm_provider:
  name: openai
  model: gpt-test
  code_embedding_model: text-embedding-3-large
  docs_embedding_model: text-embedding-3-large
query:
  reasoning_level: low
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    runtime = load_runtime_config(config_path)

    assert runtime["llama_query_reasoning_effort"] == "low"


def test_load_runtime_config_reads_openai_base_url_and_headers(tmp_path, monkeypatch):
    config_path = tmp_path / "metis.yaml"
    base_url = "https://example.test/openai/v1"
    config_path.write_text(
        f"""
llm_provider:
  name: openai
  base_url: {base_url}
  default_headers:
    X-Test-Header: test
  model: gpt-test
  code_embedding_model: text-embedding-3-large
  docs_embedding_model: text-embedding-3-large
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    runtime = load_runtime_config(config_path)

    assert runtime["openai_api_base"] == base_url
    assert runtime["openai_default_headers"] == {"X-Test-Header": "test"}


def test_load_runtime_config_reads_provider_reasoning_effort(tmp_path, monkeypatch):
    config_path = tmp_path / "metis.yaml"
    config_path.write_text(
        """
llm_provider:
  name: openai
  model: gpt-test
  reasoning_effort: xhigh
  code_embedding_model: text-embedding-3-large
  docs_embedding_model: text-embedding-3-large
query:
  max_tokens: 1000
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    runtime = load_runtime_config(config_path)

    assert runtime["llama_query_reasoning_effort"] == "xhigh"


def test_load_runtime_config_query_reasoning_overrides_provider(tmp_path, monkeypatch):
    config_path = tmp_path / "metis.yaml"
    config_path.write_text(
        """
llm_provider:
  name: openai
  model: gpt-test
  reasoning_effort: low
  code_embedding_model: text-embedding-3-large
  docs_embedding_model: text-embedding-3-large
query:
  reasoning_effort: high
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    runtime = load_runtime_config(config_path)

    assert runtime["llama_query_reasoning_effort"] == "high"


def test_load_runtime_config_reports_missing_openai_provider_keys(
    tmp_path, monkeypatch
):
    config_path = tmp_path / "metis.yaml"
    config_path.write_text(
        """
llm_provider:
  name: openai
  model: ""
  code_embedding_model: text-embedding-3-large
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    with pytest.raises(ValueError) as exc_info:
        load_runtime_config(config_path)

    message = str(exc_info.value)
    assert "OpenAI provider requires additional metis.yaml configuration" in message
    assert "Missing: llm_provider.model" in message
    assert "llm_provider.docs_embedding_model" in message
    assert "Required keys:" in message


def test_load_runtime_config_reports_missing_openai_api_key(tmp_path, monkeypatch):
    config_path = tmp_path / "metis.yaml"
    config_path.write_text(
        """
llm_provider:
  name: openai
  model: gpt-test
  code_embedding_model: text-embedding-3-large
  docs_embedding_model: text-embedding-3-large
""",
        encoding="utf-8",
    )
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    with pytest.raises(RuntimeError) as exc_info:
        load_runtime_config(config_path)

    assert "OPENAI_API_KEY environment variable is required for OpenAI provider" in str(
        exc_info.value
    )


def test_load_runtime_config_reports_missing_azure_openai_provider_keys(
    tmp_path, monkeypatch
):
    config_path = tmp_path / "metis.yaml"
    config_path.write_text(
        """
llm_provider:
  name: azure_openai
  azure_endpoint: https://example.openai.azure.com/
  azure_api_version: ""
  code_embedding_model: text-embedding-3-large
  docs_embedding_model: text-embedding-3-large
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "test-key")

    with pytest.raises(ValueError) as exc_info:
        load_runtime_config(config_path)

    message = str(exc_info.value)
    assert (
        "Azure OpenAI provider requires additional metis.yaml configuration" in message
    )
    assert "Missing: llm_provider.azure_api_version" in message
    assert "llm_provider.engine" in message
    assert "llm_provider.chat_deployment_model" in message
    assert "llm_provider.code_embedding_deployment" in message
    assert "llm_provider.docs_embedding_deployment" in message
    assert "Required keys:" in message


def test_load_runtime_config_reports_missing_azure_openai_api_key(
    tmp_path, monkeypatch
):
    config_path = tmp_path / "metis.yaml"
    config_path.write_text(
        """
llm_provider:
  name: azure_openai
  azure_endpoint: https://example.openai.azure.com/
  azure_api_version: "2024-02-01"
  engine: chat-deployment
  chat_deployment_model: gpt-4o-mini
  code_embedding_model: text-embedding-3-large
  docs_embedding_model: text-embedding-3-large
  code_embedding_deployment: code-embedding-deployment
  docs_embedding_deployment: docs-embedding-deployment
""",
        encoding="utf-8",
    )
    monkeypatch.delenv("AZURE_OPENAI_API_KEY", raising=False)

    with pytest.raises(RuntimeError) as exc_info:
        load_runtime_config(config_path)

    assert (
        "AZURE_OPENAI_API_KEY environment variable is required for Azure OpenAI provider"
        in str(exc_info.value)
    )


def test_load_runtime_config_reports_missing_vllm_provider_keys(tmp_path):
    config_path = tmp_path / "metis.yaml"
    config_path.write_text(
        """
llm_provider:
  name: vllm
  model: test-model
  docs_embedding_model: text-embedding-3-large
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError) as exc_info:
        load_runtime_config(config_path)

    message = str(exc_info.value)
    assert "vLLM provider requires additional metis.yaml configuration" in message
    assert "Missing: llm_provider.base_url" in message
    assert "llm_provider.code_embedding_model" in message
    assert "Required keys:" in message


def test_load_runtime_config_resolves_vllm_api_key_from_configured_env(
    tmp_path, monkeypatch
):
    config_path = tmp_path / "metis.yaml"
    config_path.write_text(
        """
llm_provider:
  name: vllm
  base_url: http://localhost:8000/v1
  api_key_env: CUSTOM_VLLM_KEY
  model: test-model
  code_embedding_model: text-embedding-3-large
  docs_embedding_model: text-embedding-3-large
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("CUSTOM_VLLM_KEY", "vllm-key")
    monkeypatch.delenv("VLLM_API_KEY", raising=False)

    runtime = load_runtime_config(config_path)

    assert runtime["llm_api_key"] == "vllm-key"


def test_load_runtime_config_reports_missing_ollama_provider_keys(tmp_path):
    config_path = tmp_path / "metis.yaml"
    config_path.write_text(
        """
llm_provider:
  name: ollama
  model: llama3.1:8b
  code_embedding_model: ""
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError) as exc_info:
        load_runtime_config(config_path)

    message = str(exc_info.value)
    assert "Ollama provider requires additional metis.yaml configuration" in message
    assert "Missing: llm_provider.code_embedding_model" in message
    assert "llm_provider.docs_embedding_model" in message
    assert "Required keys:" in message


def test_load_runtime_config_keeps_ollama_api_key_optional(tmp_path):
    config_path = tmp_path / "metis.yaml"
    config_path.write_text(
        """
llm_provider:
  name: ollama
  model: llama3.1:8b
  code_embedding_model: nomic-embed-text:v1.5
  docs_embedding_model: nomic-embed-text:v1.5
""",
        encoding="utf-8",
    )

    runtime = load_runtime_config(config_path)

    assert runtime["llm_api_key"] == ""


def test_load_runtime_config_accepts_complete_gemini_provider_config(
    tmp_path, monkeypatch
):
    config_path = tmp_path / "metis.yaml"
    config_path.write_text(
        """
llm_provider:
  name: gemini
  model: gemini-2.5-flash
  api_key_env: CUSTOM_GOOGLE_KEY
  code_embedding_model: gemini-embedding-001
  docs_embedding_model: gemini-embedding-001
  base_url: https://example.test/gemini
  additional_headers:
    X-Test-Header: test
  project: test-project
  location: europe-west2
  vertexai: false
  client_args:
    timeout: 30
metis_engine:
  embed_dim: 3072
query:
  model: gemini-2.5-pro
  max_tokens: 5000
  temperature: 0.0
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("CUSTOM_GOOGLE_KEY", "google-key")
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    runtime = load_runtime_config(config_path)

    assert runtime["llm_provider_name"] == "gemini"
    assert runtime["llm_api_key"] == "google-key"
    assert runtime["model"] == "gemini-2.5-flash"
    assert runtime["llama_query_model"] == "gemini-2.5-pro"
    assert runtime["code_embedding_model"] == "gemini-embedding-001"
    assert runtime["docs_embedding_model"] == "gemini-embedding-001"
    assert runtime["gemini_api_base"] == "https://example.test/gemini"
    assert runtime["gemini_additional_headers"] == {"X-Test-Header": "test"}
    assert runtime["gemini_project"] == "test-project"
    assert runtime["gemini_location"] == "europe-west2"
    assert runtime["gemini_vertexai"] is False
    assert runtime["gemini_client_args"] == {"timeout": 30}
    assert runtime["embed_dim"] == 3072
    assert runtime["llama_query_max_tokens"] == 5000


def test_load_runtime_config_reports_missing_gemini_provider_keys(tmp_path):
    config_path = tmp_path / "metis.yaml"
    config_path.write_text(
        """
llm_provider:
  name: gemini
  model: ""
  code_embedding_model: gemini-embedding-001
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError) as exc_info:
        load_runtime_config(config_path)

    message = str(exc_info.value)
    assert "Gemini provider requires additional metis.yaml configuration" in message
    assert "Missing: llm_provider.model" in message
    assert "llm_provider.docs_embedding_model" in message
    assert "Required keys:" in message


def test_load_runtime_config_reports_missing_gemini_api_key(tmp_path, monkeypatch):
    config_path = tmp_path / "metis.yaml"
    config_path.write_text(
        """
llm_provider:
  name: gemini
  model: gemini-2.5-flash
  code_embedding_model: gemini-embedding-001
  docs_embedding_model: gemini-embedding-001
""",
        encoding="utf-8",
    )
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    with pytest.raises(RuntimeError) as exc_info:
        load_runtime_config(config_path)

    message = str(exc_info.value)
    assert "GOOGLE_API_KEY environment variable" in message
    assert "GEMINI_API_KEY environment variable" in message
    assert "Gemini provider" in message


def test_load_runtime_config_resolves_gemini_api_key_from_fallback_env(
    tmp_path, monkeypatch
):
    config_path = tmp_path / "metis.yaml"
    config_path.write_text(
        """
llm_provider:
  name: gemini
  model: gemini-2.5-flash
  code_embedding_model: gemini-embedding-001
  docs_embedding_model: gemini-embedding-001
""",
        encoding="utf-8",
    )
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    monkeypatch.setenv("GEMINI_API_KEY", "gemini-key")

    runtime = load_runtime_config(config_path)

    assert runtime["llm_api_key"] == "gemini-key"
    assert runtime["model"] == "gemini-2.5-flash"


def test_load_runtime_config_accepts_complete_anthropic_provider_config(
    tmp_path, monkeypatch
):
    config_path = tmp_path / "metis.yaml"
    config_path.write_text(
        """
llm_provider:
  name: anthropic
  model: opus
  api_key_env: CUSTOM_ANTHROPIC_KEY
  code_embedding_model: text-embedding-3-large
  docs_embedding_model: text-embedding-3-small
  embedding_api_key_env: CUSTOM_EMBEDDING_KEY
metis_engine:
  embed_dim: 3072
query:
  max_tokens: 5000
  temperature: 0.0
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("CUSTOM_ANTHROPIC_KEY", "anthropic-key")
    monkeypatch.setenv("CUSTOM_EMBEDDING_KEY", "embedding-key")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    runtime = load_runtime_config(config_path)

    assert runtime["llm_provider_name"] == "anthropic"
    assert runtime["llm_api_key"] == "anthropic-key"
    assert runtime["embedding_api_key"] == "embedding-key"
    assert runtime["model"] == "claude-opus-4-8"
    assert runtime["llama_query_model"] == "claude-opus-4-8"
    assert runtime["code_embedding_model"] == "text-embedding-3-large"
    assert runtime["docs_embedding_model"] == "text-embedding-3-small"
    assert runtime["embed_dim"] == 3072
    assert runtime["llama_query_max_tokens"] == 5000


def test_load_runtime_config_reports_missing_anthropic_provider_keys(tmp_path):
    config_path = tmp_path / "metis.yaml"
    config_path.write_text(
        """
llm_provider:
  name: anthropic
  model: ""
  code_embedding_model: text-embedding-3-large
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError) as exc_info:
        load_runtime_config(config_path)

    message = str(exc_info.value)
    assert "Anthropic provider requires additional metis.yaml configuration" in message
    assert "Missing: llm_provider.model" in message
    assert "llm_provider.docs_embedding_model" in message
    assert "Required keys:" in message


def test_load_runtime_config_reports_missing_anthropic_api_key(tmp_path, monkeypatch):
    config_path = tmp_path / "metis.yaml"
    config_path.write_text(
        """
llm_provider:
  name: anthropic
  model: claude-opus-4-1-20250805
  code_embedding_model: text-embedding-3-large
  docs_embedding_model: text-embedding-3-large
""",
        encoding="utf-8",
    )
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "embedding-key")

    with pytest.raises(RuntimeError) as exc_info:
        load_runtime_config(config_path)

    message = str(exc_info.value)
    assert "ANTHROPIC_API_KEY environment variable" in message
    assert "Anthropic provider" in message


def test_load_runtime_config_allows_anthropic_without_embedding_api_key(
    tmp_path, monkeypatch
):
    config_path = tmp_path / "metis.yaml"
    config_path.write_text(
        """
llm_provider:
  name: anthropic
  model: claude-opus-4-1-20250805
  code_embedding_model: text-embedding-3-large
  docs_embedding_model: text-embedding-3-large
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("ANTHROPIC_API_KEY", "anthropic-key")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    runtime = load_runtime_config(config_path)

    assert runtime["llm_api_key"] == "anthropic-key"
    assert runtime["embedding_api_key"] == ""


def test_load_runtime_config_accepts_bedrock_mantle_provider_config(
    tmp_path, monkeypatch
):
    config_path = tmp_path / "metis.yaml"
    config_path.write_text(
        """
llm_provider:
  name: bedrock_mantle
  model: anthropic.claude-example
  aws_profile: example-profile
  aws_region: example-region
  code_embedding_model: text-embedding-3-large
  docs_embedding_model: text-embedding-3-small
  embedding_api_key_env: CUSTOM_EMBEDDING_KEY
query:
  max_tokens: 5000
  temperature: 0.0
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("CUSTOM_EMBEDDING_KEY", "embedding-key")

    runtime = load_runtime_config(config_path)

    assert runtime["llm_provider_name"] == "bedrock_mantle"
    assert runtime["llm_api_key"] == ""
    assert runtime["embedding_api_key"] == "embedding-key"
    assert runtime["model"] == "anthropic.claude-example"
    assert runtime["llama_query_model"] == "anthropic.claude-example"
    assert runtime["aws_profile"] == "example-profile"
    assert runtime["aws_region"] == "example-region"
    assert runtime["supports_temperature"] is False
    assert runtime["code_embedding_model"] == "text-embedding-3-large"
    assert runtime["docs_embedding_model"] == "text-embedding-3-small"
    assert runtime["llama_query_max_tokens"] == 5000


def test_load_runtime_config_does_not_default_bedrock_mantle_region(tmp_path):
    config_path = tmp_path / "metis.yaml"
    config_path.write_text(
        """
llm_provider:
  name: bedrock_mantle
  model: anthropic.claude-example
  code_embedding_model: text-embedding-3-large
  docs_embedding_model: text-embedding-3-small
""",
        encoding="utf-8",
    )

    runtime = load_runtime_config(config_path)

    assert runtime["aws_region"] is None


def test_load_runtime_config_accepts_anthropic_query_model_alias(tmp_path, monkeypatch):
    config_path = tmp_path / "metis.yaml"
    config_path.write_text(
        """
llm_provider:
  name: anthropic
  model: claude-opus-4-1-20250805
  code_embedding_model: text-embedding-3-large
  docs_embedding_model: text-embedding-3-large
query:
  model: sonnet
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("ANTHROPIC_API_KEY", "anthropic-key")
    monkeypatch.setenv("OPENAI_API_KEY", "embedding-key")

    runtime = load_runtime_config(config_path)

    assert runtime["model"] == "claude-opus-4-1-20250805"
    assert runtime["llama_query_model"] == "claude-sonnet-4-6"


@pytest.mark.parametrize(
    ("alias", "resolved"),
    [
        ("opus", "claude-opus-4-8"),
        ("sonnet", "claude-sonnet-4-6"),
        ("haiku", "claude-haiku-4-5"),
    ],
)
def test_load_runtime_config_accepts_anthropic_model_aliases(
    tmp_path, monkeypatch, alias, resolved
):
    config_path = tmp_path / "metis.yaml"
    config_path.write_text(
        f"""
llm_provider:
  name: anthropic
  model: {alias}
  code_embedding_model: text-embedding-3-large
  docs_embedding_model: text-embedding-3-large
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("ANTHROPIC_API_KEY", "anthropic-key")
    monkeypatch.setenv("OPENAI_API_KEY", "embedding-key")

    runtime = load_runtime_config(config_path)

    assert runtime["model"] == resolved
    assert runtime["llama_query_model"] == resolved


def test_load_runtime_config_rejects_unknown_anthropic_model_alias(
    tmp_path, monkeypatch
):
    config_path = tmp_path / "metis.yaml"
    config_path.write_text(
        """
llm_provider:
  name: anthropic
  model: unsupported-model-alias
  code_embedding_model: text-embedding-3-large
  docs_embedding_model: text-embedding-3-large
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("ANTHROPIC_API_KEY", "anthropic-key")
    monkeypatch.setenv("OPENAI_API_KEY", "embedding-key")

    with pytest.raises(ValueError) as exc_info:
        load_runtime_config(config_path)

    assert "supported short alias" in str(exc_info.value)


def test_load_runtime_config_reports_missing_llamacpp_provider_keys(tmp_path):
    config_path = tmp_path / "metis.yaml"
    config_path.write_text(
        """
llm_provider:
  name: llamacpp
  model: llama3.1:8b
  docs_embedding_model: nomic-embed-text:v1.5
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError) as exc_info:
        load_runtime_config(config_path)

    message = str(exc_info.value)
    assert "llama.cpp provider requires additional metis.yaml configuration" in message
    assert "Missing: llm_provider.code_embedding_model" in message
    assert "llm_provider.docs_embedding_model" in message
    assert "Required keys:" in message


def test_load_runtime_config_keeps_llamacpp_api_key_optional(tmp_path, monkeypatch):
    monkeypatch.delenv("LLAMACPP_API_KEY", raising=False)
    config_path = tmp_path / "metis.yaml"
    config_path.write_text(
        """
llm_provider:
  name: llamacpp
  model: llama3.1:8b
  code_embedding_model: nomic-embed-text:v1.5
  docs_embedding_model: nomic-embed-text:v1.5
""",
        encoding="utf-8",
    )

    runtime = load_runtime_config(config_path)

    assert runtime["llm_api_key"] == ""
    assert runtime["openai_api_base"] == ""
    assert runtime["model"] == "llama3.1:8b"


def test_load_runtime_config_resolves_llamacpp_api_key_from_env(tmp_path, monkeypatch):
    config_path = tmp_path / "metis.yaml"
    config_path.write_text(
        """
llm_provider:
  name: llamacpp
  base_url: http://custom:8080/v1
  model: llama3.1:8b
  code_embedding_model: nomic-embed-text:v1.5
  docs_embedding_model: nomic-embed-text:v1.5
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("LLAMACPP_API_KEY", "my-secret-key")

    runtime = load_runtime_config(config_path)

    assert runtime["llm_api_key"] == "my-secret-key"
    assert runtime["openai_api_base"] == "http://custom:8080/v1"


def test_load_runtime_config_accepts_complete_azure_provider_config(
    tmp_path, monkeypatch
):
    config_path = tmp_path / "metis.yaml"
    config_path.write_text(
        """
llm_provider:
  name: azure_openai
  azure_endpoint: https://example.openai.azure.com/
  azure_api_version: "2024-02-01"
  engine: chat-deployment
  chat_deployment_model: gpt-4o-mini
  code_embedding_model: text-embedding-3-large
  docs_embedding_model: text-embedding-3-large
  code_embedding_deployment: code-embedding-deployment
  docs_embedding_deployment: docs-embedding-deployment
query:
  max_tokens: 1000
""",
        encoding="utf-8",
    )
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "test-key")

    runtime = load_runtime_config(config_path)

    assert runtime["azure_endpoint"] == "https://example.openai.azure.com/"
    assert runtime["azure_api_version"] == "2024-02-01"
    assert runtime["engine"] == "chat-deployment"
    assert runtime["chat_deployment_model"] == "gpt-4o-mini"
    assert runtime["code_embedding_deployment"] == "code-embedding-deployment"
    assert runtime["docs_embedding_deployment"] == "docs-embedding-deployment"

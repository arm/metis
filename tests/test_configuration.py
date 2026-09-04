# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from copy import deepcopy

import pytest
import yaml

from metis.configuration import build_embedding_provider_config
from metis.configuration import load_execution_config
from metis.configuration import load_metis_config
from metis.configuration import load_runtime_config
from metis.configuration import pgvector_use_halfvec_setting
from metis.runtime_settings import CapabilityRuntimeSettings
from metis.runtime_settings import ModelToolSettings
from metis.runtime_settings import TriageOptions

_TOOL_CONFIG = {
    "model_tools": {"max_rounds": 6, "max_contract_chars": 6000},
    "capabilities": {
        "index": {
            "search": {
                "max_top_k": 4,
                "code_top_k": 1,
                "docs_top_k": 4,
                "docs_char_ratio": 1.0,
                "default_max_chars": 5000,
                "max_chars": 7000,
            }
        },
        "navigation": {"timeout_seconds": 8, "max_chars": 16000},
    },
}


def _write_config(tmp_path, content: str, *, complete_tool_config: bool = True):
    config_path = tmp_path / "metis.yaml"
    config = yaml.safe_load(content)
    if complete_tool_config:
        engine = config.setdefault("metis_engine", {})
        model_tools = engine.setdefault("model_tools", {})
        for key, value in _TOOL_CONFIG["model_tools"].items():
            model_tools.setdefault(key, value)
        capabilities = engine.setdefault("capabilities", {})
        index = capabilities.setdefault("index", {})
        search = index.setdefault("search", {})
        for key, value in _TOOL_CONFIG["capabilities"]["index"]["search"].items():
            search.setdefault(key, value)
        navigation = capabilities.setdefault("navigation", {})
        for key, value in _TOOL_CONFIG["capabilities"]["navigation"].items():
            navigation.setdefault(key, value)
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    return config_path


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


def test_packaged_execution_graph_omits_index_initialization():
    packaged = load_metis_config()
    execution = load_execution_config()

    initialize = execution["stages"]["initialize"]
    review = execution["stages"]["review"]
    triage = execution["stages"]["triage"]
    assert "index" not in initialize["nodes"]
    assert "index" not in initialize["outputs"]
    assert initialize["outputs"]["codegraph"] == "codegraph.codegraph"
    assert "codegraph" in initialize["nodes"]
    assert "outputs" not in review
    assert review["inputs"]["codegraph"] == "initialize.codegraph"
    assert "codegraph" not in review["nodes"]
    assert "inputs" not in review["nodes"]["simple_llm_review"]
    assert "inputs" not in review["nodes"]["finding_dedup"]
    assert "inputs" not in review["nodes"]["result"]
    assert "outputs" not in triage
    assert triage["inputs"]["codegraph"] == "initialize.codegraph"
    assert set(triage["nodes"]) == {"triage", "result"}
    assert "inputs" not in triage["nodes"]["triage"]
    assert "inputs" not in triage["nodes"]["result"]
    assert review["nodes"]["result"]["formats"] == ["sarif"]
    assert triage["nodes"]["result"]["formats"] == ["sarif"]
    assert "triage" not in packaged["metis_engine"]
    assert packaged["metis_engine"]["review_checkpoints"] is True


def test_runtime_loads_codegraph_and_reachability_tuning_outside_execution(
    tmp_path, monkeypatch
):
    config_path = _write_config(
        tmp_path,
        """
metis_engine:
  codegraph:
    source_functions:
      - name: public_api
        reason: exported API
  reachability:
    max_path_length: 17
  triage:
    include_triaged: true
llm_provider:
  name: openai
  model: test-model
""",
    )
    monkeypatch.setenv("OPENAI_API_KEY", "chat-key")

    runtime = load_runtime_config(config_path)

    assert runtime["codegraph_config"] == {
        "source_functions": [{"name": "public_api", "reason": "exported API"}]
    }
    assert runtime["reachability_config"] == {"max_path_length": 17}
    assert runtime["triage_options"] == TriageOptions(include_triaged=True)


@pytest.mark.parametrize("max_workers", (0, -1, True, "2"))
def test_runtime_rejects_invalid_max_workers(tmp_path, monkeypatch, max_workers):
    config_path = _write_config(
        tmp_path,
        yaml.safe_dump(
            {
                "metis_engine": {"max_workers": max_workers},
                "llm_provider": {"name": "openai", "model": "test-model"},
            }
        ),
    )
    monkeypatch.setenv("OPENAI_API_KEY", "chat-key")

    with pytest.raises(
        ValueError,
        match="metis_engine.max_workers must be a positive integer",
    ):
        load_runtime_config(config_path)


@pytest.mark.parametrize("enabled", (True, False))
def test_runtime_loads_review_checkpoint_setting(tmp_path, monkeypatch, enabled):
    config_path = _write_config(
        tmp_path,
        yaml.safe_dump(
            {
                "metis_engine": {"review_checkpoints": enabled},
                "llm_provider": {"name": "openai", "model": "test-model"},
            }
        ),
    )
    monkeypatch.setenv("OPENAI_API_KEY", "chat-key")

    runtime = load_runtime_config(config_path)

    assert runtime["review_checkpoints_enabled"] is enabled


@pytest.mark.parametrize(
    "review_checkpoints",
    ([], "false"),
)
def test_runtime_rejects_invalid_review_checkpoint_setting(
    tmp_path,
    monkeypatch,
    review_checkpoints,
):
    config_path = _write_config(
        tmp_path,
        yaml.safe_dump(
            {
                "metis_engine": {"review_checkpoints": review_checkpoints},
                "llm_provider": {"name": "openai", "model": "test-model"},
            }
        ),
    )
    monkeypatch.setenv("OPENAI_API_KEY", "chat-key")

    with pytest.raises(ValueError, match="metis_engine.review_checkpoints"):
        load_runtime_config(config_path)


def test_runtime_passes_language_replacements_from_selected_yaml(tmp_path, monkeypatch):
    config_path = _write_config(
        tmp_path,
        """
language_plugins:
  verilog:
    implementation: vendor:VerilogPlugin
llm_provider:
  name: openai
  model: test-model
""",
    )
    monkeypatch.setenv("OPENAI_API_KEY", "chat-key")

    runtime = load_runtime_config(config_path)

    assert runtime["plugin_config"]["language_plugins"] == {
        "verilog": {"implementation": "vendor:VerilogPlugin"}
    }


def test_runtime_rejects_non_mapping_language_replacements(tmp_path, monkeypatch):
    config_path = _write_config(
        tmp_path,
        """
language_plugins: []
llm_provider:
  name: openai
  model: test-model
""",
    )
    monkeypatch.setenv("OPENAI_API_KEY", "chat-key")

    with pytest.raises(ValueError, match="language_plugins must be a mapping"):
        load_runtime_config(config_path)


def test_load_runtime_config_accepts_chat_provider_without_embeddings(
    tmp_path, monkeypatch
):
    config_path = _write_config(
        tmp_path,
        """
metis_engine:
  model_tools:
    max_rounds: 9
    max_contract_chars: 4200
llm_provider:
  name: openai
  model: gpt-test
  base_url: https://example.test/openai/v1
  default_headers:
    X-Test-Header: test
query:
  reasoning_effort: high
""",
    )
    monkeypatch.setenv("OPENAI_API_KEY", "chat-key")

    runtime = load_runtime_config(config_path)

    assert runtime["llm_provider_name"] == "openai"
    assert runtime["llm_provider"] == {
        "api_key": "chat-key",
        "base_url": "https://example.test/openai/v1",
        "default_headers": {"X-Test-Header": "test"},
        "model": "gpt-test",
        "max_retries": 5,
    }
    assert runtime["llm_max_retries"] == 5
    assert runtime["chat_model_kwargs"] == {"reasoning_effort": "high"}
    assert runtime["capability_settings"] == CapabilityRuntimeSettings(
        model_tools=ModelToolSettings(max_rounds=9, max_contract_chars=4200),
        configurations=deepcopy(_TOOL_CONFIG["capabilities"]),
    )
    assert runtime["memory"] == {
        "backend": "sqlite",
        "location": ".metis/memory/metis_memory.sqlite3",
    }
    assert "embedding_provider" not in runtime
    assert runtime["embedding_provider_raw_config"] is None
    assert "llm_api_key" not in runtime


def test_load_runtime_config_accepts_memory_config(tmp_path, monkeypatch):
    config_path = _write_config(
        tmp_path,
        """
memory:
  backend: sqlite
  location: custom/memory.sqlite3
llm_provider:
  name: openai
  model: gpt-test
  base_url: https://example.test/openai/v1
""",
    )
    monkeypatch.setenv("OPENAI_API_KEY", "chat-key")

    runtime = load_runtime_config(config_path)

    assert runtime["memory"] == {
        "backend": "sqlite",
        "location": "custom/memory.sqlite3",
    }


def test_memory_capability_configuration_uses_top_level_section(tmp_path, monkeypatch):
    config_path = _write_config(
        tmp_path,
        """
metis_engine:
  capabilities:
    memory:
      backend: sqlite
llm_provider:
  name: openai
  model: gpt-test
""",
    )
    monkeypatch.setenv("OPENAI_API_KEY", "chat-key")

    with pytest.raises(ValueError, match="top-level memory section"):
        load_runtime_config(config_path)


def test_load_runtime_config_keeps_capability_config_outside_execution(
    tmp_path, monkeypatch
):
    config_path = _write_config(
        tmp_path,
        """
metis_engine:
  capabilities:
    index:
      search:
        code_top_k: 1
        docs_top_k: 3
        docs_char_ratio: 0.8
        default_max_chars: 2500
        max_chars: 4000
    navigation:
      timeout_seconds: 7
      max_chars: 9000
  execution:
    stages: {}
llm_provider:
  name: openai
  model: gpt-test
  base_url: https://example.test/openai/v1
""",
    )
    monkeypatch.setenv("OPENAI_API_KEY", "chat-key")

    runtime = load_runtime_config(config_path)

    assert runtime["capability_settings"] == CapabilityRuntimeSettings(
        model_tools=ModelToolSettings(max_rounds=6, max_contract_chars=6000),
        configurations={
            "index": {
                "search": {
                    "max_top_k": 4,
                    "code_top_k": 1,
                    "docs_top_k": 3,
                    "docs_char_ratio": 0.8,
                    "default_max_chars": 2500,
                    "max_chars": 4000,
                }
            },
            "navigation": {"timeout_seconds": 7, "max_chars": 9000},
        },
    )
    assert runtime["execution_config"] == {"stages": {}}


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        (("model_tools", "max_contract_chars"), 0, "max_contract_chars"),
        (("model_tools",), "disabled", "model_tools must be a mapping"),
        (("model_tools",), False, "model_tools must be a mapping"),
    ],
)
def test_load_runtime_config_rejects_invalid_tool_limits(
    tmp_path, monkeypatch, path, value, message
):
    engine_config = deepcopy(_TOOL_CONFIG)
    target = engine_config
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    config_path = _write_config(
        tmp_path,
        yaml.safe_dump(
            {
                "metis_engine": engine_config,
                "llm_provider": {"name": "openai", "model": "gpt-test"},
            }
        ),
        complete_tool_config=False,
    )
    monkeypatch.setenv("OPENAI_API_KEY", "chat-key")

    with pytest.raises(ValueError, match=message):
        load_runtime_config(config_path)


def test_load_runtime_config_accepts_threat_model_sources(tmp_path, monkeypatch):
    config_path = _write_config(
        tmp_path,
        """
metis_engine:
  threat_model:
    source_patterns:
      - THREAT_MODEL.md
      - docs/threat-model/*.md
    history:
      enabled: true
      max_commits: 75
llm_provider:
  name: openai
  model: test-model
""",
    )
    monkeypatch.setenv("OPENAI_API_KEY", "chat-key")

    runtime = load_runtime_config(config_path)

    threat_model = runtime["threat_model_config"]
    assert threat_model["source_patterns"] == [
        "THREAT_MODEL.md",
        "docs/threat-model/*.md",
    ]
    assert threat_model["history"] == {
        "enabled": True,
        "max_commits": 75,
    }


@pytest.mark.parametrize("value", (2, [], "invalid"))
def test_pgvector_halfvec_rejects_invalid_flags(value):
    with pytest.raises(ValueError, match="pgvector_use_halfvec"):
        pgvector_use_halfvec_setting(value, 3072)


def test_load_runtime_config_accepts_pgvector_halfvec_flag(tmp_path, monkeypatch):
    config_path = _write_config(
        tmp_path,
        """
metis_engine:
  pgvector_use_halfvec: true
llm_provider:
  name: openai
  model: gpt-test
  base_url: https://example.test/openai/v1
""",
    )
    monkeypatch.setenv("OPENAI_API_KEY", "chat-key")

    runtime = load_runtime_config(config_path)

    assert runtime["pgvector_use_halfvec"] is True


def test_load_runtime_config_auto_enables_pgvector_halfvec_for_large_embeddings(
    tmp_path, monkeypatch
):
    config_path = _write_config(
        tmp_path,
        """
metis_engine:
  embed_dim: 3072
llm_provider:
  name: openai
  model: gpt-test
  base_url: https://example.test/openai/v1
""",
    )
    monkeypatch.setenv("OPENAI_API_KEY", "chat-key")

    runtime = load_runtime_config(config_path)

    assert runtime["pgvector_use_halfvec"] is True


def test_load_runtime_config_auto_keeps_pgvector_full_precision_for_small_embeddings(
    tmp_path, monkeypatch
):
    config_path = _write_config(
        tmp_path,
        """
metis_engine:
  embed_dim: 1536
llm_provider:
  name: openai
  model: gpt-test
  base_url: https://example.test/openai/v1
""",
    )
    monkeypatch.setenv("OPENAI_API_KEY", "chat-key")

    runtime = load_runtime_config(config_path)

    assert runtime["pgvector_use_halfvec"] is False


def test_load_runtime_config_allows_forcing_pgvector_halfvec_off(tmp_path, monkeypatch):
    config_path = _write_config(
        tmp_path,
        """
metis_engine:
  embed_dim: 3072
  pgvector_use_halfvec: false
llm_provider:
  name: openai
  model: gpt-test
  base_url: https://example.test/openai/v1
""",
    )
    monkeypatch.setenv("OPENAI_API_KEY", "chat-key")

    runtime = load_runtime_config(config_path)

    assert runtime["pgvector_use_halfvec"] is False


def test_build_embedding_provider_config_resolves_openai_embedding_provider(
    tmp_path, monkeypatch
):
    config_path = _write_config(
        tmp_path,
        """
llm_provider:
  name: anthropic
  api_key: anthropic-key
  model: claude-sonnet-4-6
embedding_provider:
  name: openai
  api_key_env: CUSTOM_OPENAI_EMBEDDING_KEY
  code_embedding_model: text-embedding-3-large
  docs_embedding_model: text-embedding-3-small
  default_headers:
      X-Embedding: test
  code_extra_kwargs:
      dimensions: 1536
""",
    )
    monkeypatch.setenv("CUSTOM_OPENAI_EMBEDDING_KEY", "embedding-key")

    runtime = load_runtime_config(config_path)
    assert "embedding_provider" not in runtime
    assert runtime["embedding_provider_raw_config"]["name"] == "openai"

    embedding_provider_config = build_embedding_provider_config(
        runtime["embedding_provider_raw_config"]
    )

    assert embedding_provider_config == {
        "name": "openai",
        "api_key": "embedding-key",
        "default_headers": {"X-Embedding": "test"},
        "code_embedding_model": "text-embedding-3-large",
        "docs_embedding_model": "text-embedding-3-small",
        "code_extra_kwargs": {"dimensions": 1536},
    }


def test_load_runtime_config_reports_missing_openai_chat_keys(tmp_path, monkeypatch):
    config_path = _write_config(
        tmp_path,
        """
llm_provider:
  name: openai
  model: ""
""",
    )
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    with pytest.raises(ValueError) as exc_info:
        load_runtime_config(config_path)

    message = str(exc_info.value)
    assert "OpenAI provider requires additional metis.yaml configuration" in message
    assert "Missing: llm_provider.model" in message
    assert "Required keys:" in message


def test_load_runtime_config_reports_missing_openai_llm_api_key(tmp_path, monkeypatch):
    config_path = _write_config(
        tmp_path,
        """
llm_provider:
  name: openai
  model: gpt-test
""",
    )
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    with pytest.raises(RuntimeError) as exc_info:
        load_runtime_config(config_path)

    message = str(exc_info.value)
    assert "OPENAI_API_KEY environment variable" in message
    assert "llm_provider.api_key" in message
    assert "OpenAI provider" in message


def test_build_embedding_provider_config_reports_missing_provider_keys(
    tmp_path, monkeypatch
):
    config_path = _write_config(
        tmp_path,
        """
llm_provider:
  name: openai
  model: gpt-test
embedding_provider:
  name: openai
  code_embedding_model: text-embedding-3-large
""",
    )
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    runtime = load_runtime_config(config_path)

    with pytest.raises(ValueError) as exc_info:
        build_embedding_provider_config(runtime["embedding_provider_raw_config"])

    message = str(exc_info.value)
    assert (
        "OpenAI embeddings provider requires additional metis.yaml configuration"
        in message
    )
    assert "Missing: embedding_provider.docs_embedding_model" in message


def test_build_embedding_provider_config_rejects_short_embedding_model_keys():
    with pytest.raises(ValueError) as exc_info:
        build_embedding_provider_config(
            {
                "name": "openai",
                "api_key": "embedding-key",
                "code_model": "text-embedding-3-large",
                "docs_model": "text-embedding-3-large",
            }
        )

    message = str(exc_info.value)
    assert "Missing: embedding_provider.code_embedding_model" in message
    assert "embedding_provider.docs_embedding_model" in message


def test_load_runtime_config_accepts_anthropic_model_ids_without_embeddings(
    tmp_path, monkeypatch
):
    config_path = _write_config(
        tmp_path,
        """
llm_provider:
  name: anthropic
  model: claude-opus-4-8
  api_key_env: CUSTOM_ANTHROPIC_KEY
query:
  model: claude-sonnet-4-6
""",
    )
    monkeypatch.setenv("CUSTOM_ANTHROPIC_KEY", "anthropic-key")
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    runtime = load_runtime_config(config_path)

    assert runtime["llm_provider_name"] == "anthropic"
    assert runtime["model"] == "claude-opus-4-8"
    assert runtime["llama_query_model"] == "claude-sonnet-4-6"
    assert runtime["llm_provider"]["model"] == "claude-opus-4-8"
    assert runtime["chat_model_kwargs"] == {}
    assert "embedding_provider" not in runtime


def test_load_runtime_config_accepts_gemini_vertex_ai_without_api_key(
    tmp_path, monkeypatch
):
    config_path = _write_config(
        tmp_path,
        """
llm_provider:
  name: gemini
  model: gemini-2.5-flash
  project: test-project
  location: europe-west2
  vertexai: true
""",
    )
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    runtime = load_runtime_config(config_path)

    assert runtime["llm_provider_name"] == "gemini"
    assert "api_key" not in runtime["llm_provider"]
    assert runtime["llm_provider"]["project"] == "test-project"
    assert runtime["llm_provider"]["location"] == "europe-west2"
    assert runtime["llm_provider"]["vertexai"] is True


def test_load_runtime_config_accepts_bedrock_mantle_chat_without_embeddings(tmp_path):
    config_path = _write_config(
        tmp_path,
        """
llm_provider:
  name: bedrock_mantle
  model: anthropic.claude-example
  aws_profile: example-profile
  aws_region: example-region
""",
    )

    runtime = load_runtime_config(config_path)

    assert runtime["llm_provider_name"] == "bedrock_mantle"
    assert runtime["llm_provider"]["model"] == "anthropic.claude-example"
    assert runtime["llm_provider"]["aws_profile"] == "example-profile"
    assert runtime["llm_provider"]["aws_region"] == "example-region"
    assert runtime["llama_query_model"] == "anthropic.claude-example"
    assert runtime["llama_query_max_tokens"] is None
    assert "embedding_provider" not in runtime


def test_load_runtime_config_accepts_split_azure_chat_and_embedding_config(
    tmp_path, monkeypatch
):
    config_path = _write_config(
        tmp_path,
        """
llm_provider:
  name: azure_openai
  azure_endpoint: https://example.openai.azure.com/
  azure_api_version: "2024-02-01"
  engine: chat-deployment
  chat_deployment_model: gpt-4o-mini
  use_responses_api: true
embedding_provider:
  name: azure_openai
  azure_endpoint: https://example.openai.azure.com/
  azure_api_version: "2024-02-01"
  code_embedding_model: text-embedding-3-large
  docs_embedding_model: text-embedding-3-small
  code_deployment: code-embedding-deployment
  docs_deployment: docs-embedding-deployment
""",
    )
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "test-key")

    runtime = load_runtime_config(config_path)

    assert runtime["llm_provider_name"] == "azure_openai"
    assert runtime["llm_provider"]["engine"] == "chat-deployment"
    assert runtime["llm_provider"]["chat_deployment_model"] == "gpt-4o-mini"
    assert runtime["llm_provider"]["use_responses_api"] is True
    assert "embedding_provider" not in runtime

    embedding_provider_config = build_embedding_provider_config(
        runtime["embedding_provider_raw_config"]
    )

    assert embedding_provider_config["code_embedding_model"] == "text-embedding-3-large"
    assert embedding_provider_config["docs_embedding_model"] == "text-embedding-3-small"
    assert embedding_provider_config["code_deployment"] == "code-embedding-deployment"
    assert embedding_provider_config["docs_deployment"] == "docs-embedding-deployment"


@pytest.mark.parametrize("provider_name", ["ollama", "llamacpp"])
def test_load_runtime_config_keeps_local_provider_api_key_optional(
    tmp_path, monkeypatch, provider_name
):
    monkeypatch.delenv("LLAMACPP_API_KEY", raising=False)
    config_path = _write_config(
        tmp_path,
        f"""
llm_provider:
  name: {provider_name}
  model: llama3.1:8b
embedding_provider:
  name: {provider_name}
  code_embedding_model: nomic-embed-text:v1.5
  docs_embedding_model: nomic-embed-text:v1.5
""",
    )

    runtime = load_runtime_config(config_path)
    embedding_provider_config = build_embedding_provider_config(
        runtime["embedding_provider_raw_config"]
    )

    assert "api_key" not in runtime["llm_provider"]
    assert "api_key" not in embedding_provider_config
    assert embedding_provider_config["code_embedding_model"] == "nomic-embed-text:v1.5"

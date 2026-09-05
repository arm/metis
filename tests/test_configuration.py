# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from importlib.resources import as_file
from importlib.resources import files

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


def _write_config(tmp_path, content: str):
    config_path = tmp_path / "metis.yaml"
    config_path.write_text(content, encoding="utf-8")
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
    assert runtime["capability_settings"].model_tools == ModelToolSettings(
        max_rounds=9,
        max_contract_chars=4200,
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


@pytest.mark.parametrize(
    "settings,expected",
    [
        ("pgvector_use_halfvec: true", True),
        ("embed_dim: 3072", True),
        ("embed_dim: 1536", False),
        ("embed_dim: 3072\n  pgvector_use_halfvec: false", False),
    ],
    ids=["explicit-on", "auto-large", "auto-small", "explicit-off"],
)
def test_load_runtime_config_resolves_pgvector_halfvec(
    tmp_path, monkeypatch, settings, expected
):
    config_path = _write_config(
        tmp_path,
        f"""
metis_engine:
  {settings}
llm_provider:
  name: openai
  model: gpt-test
  base_url: https://example.test/openai/v1
""",
    )
    monkeypatch.setenv("OPENAI_API_KEY", "chat-key")
    assert load_runtime_config(config_path)["pgvector_use_halfvec"] is expected


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


@pytest.mark.parametrize(
    ("content", "key"),
    [
        ("metis_engine: {}\nmetis_engine: {}\n", "metis_engine"),
        ("metis_engine: {execution: {stages: {custom: {}, custom: {}}}}", "custom"),
        (
            "metis_engine: {execution: {stages: {custom: {nodes: {task: {}, task: {}}}}}}",
            "task",
        ),
        ("metis_engine: {<<: {max_workers: 1, max_workers: 2}}", "max_workers"),
        ('{=: first, "=": second}', "="),
        ('{<<: {=: first, "=": second}}', "="),
    ],
)
def test_raw_yaml_rejects_duplicate_keys_including_merged_maps(tmp_path, content, key):
    config_path = _write_config(tmp_path, content)

    with pytest.raises(
        yaml.constructor.ConstructorError, match=f"duplicate key '{key}'"
    ) as failure:
        load_metis_config(config_path)

    assert str(config_path) in str(failure.value)
    assert "line" in str(failure.value)


@pytest.mark.parametrize("key", ("=", '"="'))
def test_raw_yaml_allows_value_keys_in_merge_overrides(tmp_path, key):
    config_path = _write_config(
        tmp_path,
        f"defaults: &defaults {{=: inherited}}\nmerged: {{<<: *defaults, {key}: explicit}}",
    )

    loaded = load_metis_config(config_path)

    assert loaded == {"defaults": {"=": "inherited"}, "merged": {"=": "explicit"}}


def test_raw_yaml_allows_nested_merge_overrides_and_literal_merge_key(tmp_path):
    config_path = _write_config(
        tmp_path,
        """
first:
  nested: &overrides
    <<: &defaults {max_workers: 1}
    max_workers: 2
later:
  <<: *overrides
literal:
  <<: *defaults
  "<<": preserved
""",
    )

    loaded = load_metis_config(config_path)

    assert loaded["first"]["nested"] == loaded["later"] == {"max_workers": 2}
    assert loaded["literal"] == {"max_workers": 1, "<<": "preserved"}


@pytest.mark.parametrize("content", ("", "[]", "false", "42"))
def test_runtime_rejects_non_mapping_document(tmp_path, content):
    with pytest.raises(ValueError, match="configuration must be a mapping"):
        load_runtime_config(_write_config(tmp_path, content))


@pytest.mark.parametrize(
    ("configured", "message"),
    [
        ("metis_engine: null", "metis_engine must be a mapping"),
        ("metis_engine: {max_worker: 2}", "Unknown metis_engine settings: max_worker"),
        ("metis_engine: {max_workers: 0}", "max_workers must be a positive integer"),
        ("metis_engine: {max_workers: -1}", "max_workers must be a positive integer"),
        ("metis_engine: {max_workers: true}", "max_workers must be a positive integer"),
        ('metis_engine: {max_workers: "2"}', "max_workers must be a positive integer"),
        (
            "metis_engine: {max_token_length: .inf}",
            "max_token_length must be a positive integer",
        ),
        (
            "metis_engine: {doc_chunk_size: 20, doc_chunk_overlap: 20}",
            "doc_chunk_overlap must be less",
        ),
        (
            "metis_engine: {triage_checkpoint_every: -1}",
            "triage_checkpoint_every must be a non-negative integer",
        ),
        (
            "metis_engine: {review_checkpoints: []}",
            "review_checkpoints must be a boolean",
        ),
        (
            'metis_engine: {review_checkpoints: "false"}',
            "review_checkpoints must be a boolean",
        ),
        (
            "metis_engine: {model_tools: {max_contract_chars: 0}}",
            "max_contract_chars must be a positive integer",
        ),
        ("metis_engine: {model_tools: disabled}", "model_tools must be a mapping"),
        ("metis_engine: {model_tools: false}", "model_tools must be a mapping"),
        ("metis_engine: {codegraph: false}", "codegraph must be a mapping"),
        ("metis_engine: {capabilities: []}", "capabilities must be a mapping"),
        ("language_plugins: []", "language_plugins must be a mapping"),
        ("query: {max_token: 20}", "Unknown query settings: max_token"),
        *[
            (f"query: {{{key}: {value}}}", f"query.{key} must be a positive integer")
            for key in ("max_tokens", "similarity_top_k")
            for value in ("true", "false", "0", "-1", "1.5", '"2"', "[]", "{}")
        ],
        (
            "query: {similarity_top_k: null}",
            "similarity_top_k must be a positive integer",
        ),
        *[
            (
                f"metis_engine: {{{key}: {value}}}",
                f"metis_engine.{key} must be a list of strings",
            )
            for key in ("review_code_include_paths", "review_code_exclude_paths")
            for value in ("false", "null", '"src/"', "{}", "[src/, 2]", "[null]")
        ],
        *[
            (
                f"metis_engine: {{metisignore_file: {value}}}",
                "metisignore_file must be a string or null",
            )
            for value in ("true", "1", "[]", "{}")
        ],
    ],
)
def test_runtime_rejects_invalid_raw_configuration(tmp_path, configured, message):
    config_path = _write_config(
        tmp_path, configured + "\nllm_provider: {name: ollama, model: test-model}\n"
    )

    with pytest.raises(ValueError, match=message):
        load_runtime_config(config_path)


@pytest.mark.parametrize(
    ("max_tokens", "metisignore_file"),
    [(None, None), (1, ""), (5000, "config/.metisignore")],
)
def test_runtime_preserves_valid_query_and_path_values(
    tmp_path, max_tokens, metisignore_file
):
    runtime = load_runtime_config(
        _write_config(
            tmp_path,
            yaml.safe_dump(
                {
                    "llm_provider": {"name": "ollama", "model": "test-model"},
                    "query": {"max_tokens": max_tokens, "similarity_top_k": 3},
                    "metis_engine": {
                        "metisignore_file": metisignore_file,
                        "review_code_include_paths": ["src/", "!src/generated/"],
                        "review_code_exclude_paths": ["tests/"],
                        "capabilities": {"CustomCapability": {"opaque": [None, False]}},
                    },
                }
            ),
        )
    )

    assert runtime["llama_query_max_tokens"] == max_tokens
    assert runtime["similarity_top_k"] == 3
    assert runtime["metisignore_file"] == metisignore_file
    assert runtime["review_code_include_paths"] == ["src/", "!src/generated/"]
    assert runtime["review_code_exclude_paths"] == ["tests/"]
    assert runtime["capability_settings"].configurations["CustomCapability"] == {
        "opaque": [None, False]
    }


def test_runtime_inherits_packaged_defaults_and_respects_explicit_replacements(
    tmp_path,
):
    with as_file(files("metis") / "metis.yaml") as packaged_path:
        defaults = load_metis_config(packaged_path)["metis_engine"]
    provider = "llm_provider: {name: ollama, model: test-model}\n"
    minimal = load_runtime_config(_write_config(tmp_path, provider))

    assert minimal["llama_query_max_tokens"] is None
    assert minimal["similarity_top_k"] == 5
    assert minimal["metisignore_file"] is None
    assert minimal["review_code_include_paths"] == []
    assert minimal["review_code_exclude_paths"] == []

    for key in ("max_workers", "max_token_length", "embed_dim"):
        assert minimal[key] == defaults[key]
    assert minimal["threat_model_config"] == defaults["threat_model"]
    assert minimal["capability_settings"].configurations == defaults["capabilities"]

    changed = load_runtime_config(
        _write_config(
            tmp_path,
            provider
            + """
metis_engine:
  capabilities:
    navigation: {timeout_seconds: 2}
    CustomCapability: {own_setting: 7}
  execution: {stages: {}}
  threat_model: {source_patterns: []}
  codegraph: {source_functions: []}
  triage_checkpoint_every: 0
  llm_max_retries: 0
""",
        )
    )
    capabilities = changed["capability_settings"].configurations
    assert capabilities["navigation"] == {
        **defaults["capabilities"]["navigation"],
        "timeout_seconds": 2,
    }
    assert capabilities["index"] == defaults["capabilities"]["index"]
    assert capabilities["CustomCapability"] == {"own_setting": 7}
    assert changed["execution_config"] == {"stages": {}}
    assert changed["threat_model_config"]["source_patterns"] == []
    assert changed["codegraph_config"] == {"source_functions": []}
    assert changed["triage_checkpoint_every"] == changed["llm_max_retries"] == 0

    empty = load_runtime_config(
        _write_config(
            tmp_path, provider + "metis_engine: {capabilities: {}, execution: {}}\n"
        )
    )
    assert empty["capability_settings"].configurations == {}
    assert empty["execution_config"] == {}


@pytest.mark.parametrize("name", ["max_active_nodes", "max_concurrent_executions"])
@pytest.mark.parametrize("value", [0, -1, True, 1.5, "2", []])
def test_runtime_rejects_invalid_concurrency_budgets(tmp_path, name, value):
    config = {"metis_engine": {name: value}}
    with pytest.raises(ValueError, match=f"{name} must be a positive integer"):
        load_runtime_config(_write_config(tmp_path, yaml.safe_dump(config)))


@pytest.mark.parametrize(
    "limits",
    [
        {},
        {"max_active_nodes": None, "max_concurrent_executions": None},
        {"max_active_nodes": 1, "max_concurrent_executions": 4},
    ],
)
def test_runtime_resolves_independent_concurrency_budgets(tmp_path, limits):
    runtime = load_runtime_config(
        _write_config(
            tmp_path,
            yaml.safe_dump(
                {
                    "llm_provider": {"name": "ollama", "model": "unused"},
                    "metis_engine": {"max_workers": 3, **limits},
                }
            ),
        )
    )
    assert runtime["max_workers"] == 3
    assert runtime["max_active_nodes"] == (limits.get("max_active_nodes") or 3)
    assert runtime["max_concurrent_executions"] == (
        limits.get("max_concurrent_executions") or 3
    )


@pytest.mark.parametrize(
    ("configured", "message"),
    [
        *[
            (f"query: {{temperature: {value}}}", "query.temperature")
            for value in (
                "true",
                '"warm"',
                "[]",
                ".nan",
                ".inf",
                "-.inf",
                "-0.1",
                str(10**400),
            )
        ],
        *[
            (f"metis_engine: {{hnsw_kwargs: {{{key}: {value}}}}}", key)
            for key in ("hnsw_m", "hnsw_ef_construction", "hnsw_ef_search")
            for value in ("true", "null", "0", "1.5", '"16"')
        ],
        ("metis_engine: {review_checkpoints: falsehood}", "review_checkpoints"),
        ("memory: invalid-shape", "MemoryCapabilityConfiguration"),
        (
            "metis_engine: {codegraph: {source_functions: [{name: ' '}]}}",
            "source_functions",
        ),
        (
            "metis_engine: {reachability: {max_path_length: 0}}",
            "max_path_length",
        ),
    ],
)
def test_invalid_shared_settings_fail_before_provider_lookup(
    tmp_path, monkeypatch, configured, message
):
    def unexpected_provider(**_kwargs):
        pytest.fail("invalid shared settings reached provider lookup")

    monkeypatch.setattr("metis.configuration._get_provider_cls", unexpected_provider)
    with pytest.raises(ValueError, match=message):
        load_runtime_config(_write_config(tmp_path, configured))


@pytest.mark.parametrize("temperature", [None, 0, 0.5, 100, 1e100])
def test_valid_temperature_and_partial_hnsw_settings(tmp_path, temperature):
    runtime = load_runtime_config(
        _write_config(
            tmp_path,
            yaml.safe_dump(
                {
                    "llm_provider": {"name": "ollama", "model": "inert"},
                    "query": {"temperature": temperature},
                    "metis_engine": {"hnsw_kwargs": {"hnsw_m": 16}},
                }
            ),
        )
    )
    assert runtime["hnsw_kwargs"] == {"hnsw_m": 16}
    if temperature is None:
        assert "temperature" not in runtime["chat_model_kwargs"]
    else:
        assert runtime["chat_model_kwargs"]["temperature"] == temperature


def test_blank_environment_credentials_allow_fallback(tmp_path, monkeypatch):
    monkeypatch.setenv("METIS_TEST_EMPTY_KEY", " \t")
    monkeypatch.setenv("OPENAI_API_KEY", "inert-fallback")
    config = (
        "llm_provider: {name: openai, model: inert, api_key_env: METIS_TEST_EMPTY_KEY}"
    )
    runtime = load_runtime_config(_write_config(tmp_path, config))
    assert runtime["llm_provider"]["api_key"] == "inert-fallback"
    monkeypatch.setenv("OPENAI_API_KEY", " ")
    with pytest.raises(RuntimeError, match="required.*not set"):
        load_runtime_config(_write_config(tmp_path, config))


@pytest.mark.parametrize("value", ["2026-02-30", "!!int nope", "!!float nope"])
def test_invalid_yaml_scalars_preserve_source_location_and_recover(tmp_path, value):
    path = _write_config(tmp_path, f"metis_engine:\n  max_workers: {value}\n")
    with pytest.raises(yaml.constructor.ConstructorError) as caught:
        load_metis_config(path)
    assert caught.value.problem_mark.name == str(path)
    assert (caught.value.problem_mark.line, caught.value.problem_mark.column) == (1, 15)
    assert isinstance(caught.value.__cause__, ValueError)
    path.write_text("metis_engine: {max_workers: 2}\n", encoding="utf-8")
    assert load_metis_config(path)["metis_engine"]["max_workers"] == 2

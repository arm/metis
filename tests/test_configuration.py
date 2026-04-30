# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.configuration import load_metis_config
from metis.configuration import load_runtime_config


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

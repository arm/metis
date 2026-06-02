# SPDX-FileCopyrightText: Copyright 2025-2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import os
import logging
import yaml

from importlib.resources import files, as_file
from pathlib import Path
from typing import TypedDict

from metis.reachability_settings import collect_reachability_config

logger = logging.getLogger("metis")


class _ApiKeySources(TypedDict):
    required: bool
    config_keys: tuple[str, ...]
    config_env_keys: tuple[str, ...]
    env_vars: tuple[str, ...]


_LLM_PROVIDER_DISPLAY_NAMES: dict[str, str] = {
    "openai": "OpenAI",
    "azure_openai": "Azure OpenAI",
    "vllm": "vLLM",
    "ollama": "Ollama",
    "llamacpp": "llama.cpp",
}

_LLM_PROVIDER_REQUIRED_KEYS: dict[str, tuple[str, ...]] = {
    "openai": (
        "model",
        "code_embedding_model",
        "docs_embedding_model",
    ),
    "azure_openai": (
        "azure_endpoint",
        "azure_api_version",
        "engine",
        "chat_deployment_model",
        "code_embedding_model",
        "docs_embedding_model",
        "code_embedding_deployment",
        "docs_embedding_deployment",
    ),
    "vllm": (
        "base_url",
        "model",
        "code_embedding_model",
        "docs_embedding_model",
    ),
    "ollama": (
        "model",
        "code_embedding_model",
        "docs_embedding_model",
    ),
    "llamacpp": (
        "model",
        "code_embedding_model",
        "docs_embedding_model",
    ),
}

_LLM_PROVIDER_API_KEY_SOURCES: dict[str, _ApiKeySources] = {
    "openai": {
        "required": True,
        "config_keys": (),
        "config_env_keys": (),
        "env_vars": ("OPENAI_API_KEY",),
    },
    "azure_openai": {
        "required": True,
        "config_keys": (),
        "config_env_keys": (),
        "env_vars": ("AZURE_OPENAI_API_KEY",),
    },
    "vllm": {
        "required": False,
        "config_keys": ("api_key",),
        "config_env_keys": ("api_key_env",),
        "env_vars": ("VLLM_API_KEY",),
    },
    "ollama": {
        "required": False,
        "config_keys": ("api_key",),
        "config_env_keys": ("api_key_env",),
        "env_vars": (),
    },
    "llamacpp": {
        "required": False,
        "config_keys": ("api_key",),
        "config_env_keys": ("api_key_env",),
        "env_vars": ("LLAMACPP_API_KEY",),
    },
}


def load_yaml(path):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def _missing_required_keys(config: dict, keys: tuple[str, ...]) -> list[str]:
    missing = []
    for key in keys:
        value = config.get(key)
        if value is None or (isinstance(value, str) and not value.strip()):
            missing.append(key)
    return missing


def _validate_llm_provider_config(provider_name: str, provider_config: dict) -> None:
    required_keys = _LLM_PROVIDER_REQUIRED_KEYS.get(provider_name)
    if not required_keys:
        return
    missing_keys = _missing_required_keys(provider_config, required_keys)
    if not missing_keys:
        return

    display_name = _LLM_PROVIDER_DISPLAY_NAMES.get(provider_name, provider_name)
    missing = ", ".join(f"llm_provider.{key}" for key in missing_keys)
    required = ", ".join(f"llm_provider.{key}" for key in required_keys)
    raise ValueError(
        f"{display_name} provider requires additional metis.yaml configuration. "
        f"Missing: {missing}. Required keys: {required}."
    )


def _resolve_llm_api_key(provider_name: str, provider_config: dict) -> str:
    sources = _LLM_PROVIDER_API_KEY_SOURCES.get(provider_name)
    if sources is None:
        return ""

    for config_key in sources["config_keys"]:
        value = provider_config.get(config_key)
        if isinstance(value, str) and value.strip():
            return value

    for config_env_key in sources["config_env_keys"]:
        env_var = provider_config.get(config_env_key)
        if isinstance(env_var, str) and env_var.strip():
            value = os.environ.get(env_var)
            if value:
                return value

    for env_var in sources["env_vars"]:
        value = os.environ.get(env_var)
        if value:
            return value

    if sources["required"]:
        display_name = _LLM_PROVIDER_DISPLAY_NAMES.get(provider_name, provider_name)
        source_descriptions = [
            f"{env_var} environment variable" for env_var in sources["env_vars"]
        ]
        source_descriptions.extend(
            f"llm_provider.{key}" for key in sources["config_keys"]
        )
        source_descriptions.extend(
            f"environment variable named by llm_provider.{key}"
            for key in sources["config_env_keys"]
        )
        sources_text = " or ".join(source_descriptions)
        raise RuntimeError(
            f"{sources_text} is required for {display_name} provider but not set."
        )

    return ""


def load_runtime_config(config_path=None, enable_psql=False):
    cfg = load_metis_config(config_path)

    runtime: dict[str, object] = {}
    if enable_psql:
        db_cfg = cfg.get("psql_database", {})
        provider = db_cfg.get("provider", "config")
        if provider == "env":
            secrets = dict(
                username=os.environ["PGUSER"],
                password=os.environ["PGPASSWORD"],
                host=os.environ.get("PGHOST", "localhost"),
                port=int(os.environ.get("PGPORT", 5432)),
                database_name=os.environ.get("PGDATABASE", "metis_db"),
            )
        elif provider == "config":
            secrets = db_cfg.get("credentials", {})
        else:
            raise ValueError(f"Unknown database config provider: {provider}")

        runtime.update(
            pg_username=secrets.get("username"),
            pg_password=secrets.get("password"),
            pg_host=secrets.get("host"),
            pg_port=secrets.get("port"),
            pg_db_name=secrets.get("database_name"),
        )

    llm_cfg = cfg.get("llm_provider", {})
    runtime["code_embedding_model"] = llm_cfg.get("code_embedding_model", "")
    runtime["docs_embedding_model"] = llm_cfg.get("docs_embedding_model", "")
    runtime["code_embedding_extra_kwargs"] = llm_cfg.get(
        "code_embedding_extra_kwargs", {}
    )
    runtime["docs_embedding_extra_kwargs"] = llm_cfg.get(
        "docs_embedding_extra_kwargs", {}
    )

    llm_provider_name = cfg.get("llm_provider", {}).get("name", "").lower()
    runtime["llm_provider_name"] = llm_provider_name
    _validate_llm_provider_config(llm_provider_name, llm_cfg)
    llm_api_key = _resolve_llm_api_key(llm_provider_name, llm_cfg)
    if llm_provider_name == "openai":
        runtime["llm_api_key"] = llm_api_key
        runtime["openai_api_base"] = llm_cfg.get("base_url", "")
        runtime["openai_default_headers"] = llm_cfg.get("default_headers", {})
        runtime["model"] = llm_cfg.get("model", "")
    elif llm_provider_name == "azure_openai":
        runtime["llm_api_key"] = llm_api_key
        runtime["azure_endpoint"] = llm_cfg.get("azure_endpoint", "")
        runtime["azure_api_version"] = llm_cfg.get("azure_api_version", "")
        runtime["engine"] = llm_cfg.get("engine", "")
        runtime["chat_deployment_model"] = llm_cfg.get("chat_deployment_model", "")
        runtime["code_embedding_deployment"] = llm_cfg.get(
            "code_embedding_deployment", ""
        )
        runtime["docs_embedding_deployment"] = llm_cfg.get(
            "docs_embedding_deployment", ""
        )
        runtime["model_token_param"] = llm_cfg.get(
            "model_token_param", "max_completion_tokens"
        )
        runtime["supports_temperature"] = llm_cfg.get("supports_temperature", False)
    elif llm_provider_name == "vllm":
        runtime["llm_api_key"] = llm_api_key
        runtime["openai_api_base"] = llm_cfg.get("base_url", "")
        runtime["openai_default_headers"] = llm_cfg.get("default_headers", {})
        runtime["model"] = llm_cfg.get("model", "")
    elif llm_provider_name == "ollama":
        runtime["llm_api_key"] = llm_api_key
        runtime["openai_api_base"] = llm_cfg.get(
            "base_url", "http://localhost:11434/v1"
        )
        runtime["openai_default_headers"] = llm_cfg.get("default_headers", {})
        runtime["model"] = llm_cfg.get("model", "")
        runtime["force_openai_like"] = True
    elif llm_provider_name == "llamacpp":
        runtime["llm_api_key"] = llm_api_key
        runtime["openai_api_base"] = llm_cfg.get("base_url", "")
        runtime["openai_default_headers"] = llm_cfg.get("default_headers", {})
        runtime["model"] = llm_cfg.get("model", "")
    else:
        raise ValueError(f"Unsupported LLM provider: {llm_provider_name}")

    # Engine/vector store settings
    engine_cfg = cfg.get("metis_engine", {})
    runtime["max_token_length"] = engine_cfg.get("max_token_length", 100000)
    runtime["max_workers"] = engine_cfg.get("max_workers", 8)
    runtime["embed_dim"] = engine_cfg.get("embed_dim", 1536)
    runtime["doc_chunk_size"] = engine_cfg.get("doc_chunk_size", 1024)
    runtime["doc_chunk_overlap"] = engine_cfg.get("doc_chunk_overlap", 200)
    runtime["triage_checkpoint_every"] = engine_cfg.get("triage_checkpoint_every", 50)
    runtime["triage_tool_timeout_seconds"] = engine_cfg.get(
        "triage_tool_timeout_seconds", 12
    )
    runtime["hnsw_kwargs"] = engine_cfg.get(
        "hnsw_kwargs",
        {
            "hnsw_m": 16,
            "hnsw_ef_construction": 64,
            "hnsw_ef_search": 40,
            "hnsw_dist_method": "vector_cosine_ops",
        },
    )
    runtime["metisignore_file"] = engine_cfg.get("metisignore_file", None)
    runtime["review_code_include_paths"] = engine_cfg.get(
        "review_code_include_paths", []
    )
    runtime["review_code_exclude_paths"] = engine_cfg.get(
        "review_code_exclude_paths", []
    )
    runtime.update(collect_reachability_config(cfg, engine_cfg))

    # Query config
    query_cfg = cfg.get("query", {})
    runtime["llama_query_model"] = query_cfg.get("model") or runtime.get("model", "")
    runtime["llama_query_temperature"] = query_cfg.get("temperature", 0.0)
    runtime["llama_query_max_tokens"] = query_cfg.get("max_tokens", 3072)
    runtime["llama_query_reasoning_effort"] = (
        query_cfg.get("reasoning_effort")
        or query_cfg.get("reasoning_level")
        or llm_cfg.get("reasoning_effort")
        or llm_cfg.get("reasoning_level")
    )
    runtime["similarity_top_k"] = query_cfg.get("similarity_top_k", 5)
    runtime["triage_similarity_top_k"] = query_cfg.get("triage_similarity_top_k", 3)
    runtime["response_mode"] = query_cfg.get("response_mode", "compact")

    return runtime


def load_plugin_config(plugins_path: str | Path | None = None):
    return config_path_fallback("plugins.yaml", "metis.plugins", plugins_path)


def load_metis_config(config_path: str | Path | None = None):
    return config_path_fallback(
        "metis.yaml",
        "metis",
        config_path,
        alt_filenames=("metis.yml",),
    )


def config_path_fallback(
    filename: str,
    anchor: str,
    config_path: str | Path | None = None,
    alt_filenames: tuple[str, ...] = (),
):
    """
    Loads the config from either a given path, the current working
    directory or from the packaged resource directory.
    """
    candidate_filenames = (filename, *alt_filenames)

    if config_path is not None:
        config_path = Path(config_path)
        if not config_path.is_file():
            raise FileNotFoundError(f"Config not found: {config_path}")
        logger.info(f"Loading {config_path.name} from {config_path}")
        return load_yaml(config_path)

    for candidate_filename in candidate_filenames:
        cwd_path = Path.cwd() / candidate_filename
        if cwd_path.is_file():
            logger.info(f"Loading {candidate_filename} from {cwd_path}")
            return load_yaml(cwd_path)

    for candidate_filename in candidate_filenames:
        resource = files(anchor) / candidate_filename
        if not resource.is_file():
            continue

        # ensure we have a real path
        with as_file(resource) as real_path:
            logger.info(f"Loading default {candidate_filename}")
            return load_yaml(real_path)

    supported_names = ", ".join(candidate_filenames)
    raise FileNotFoundError(
        f"No config file ({supported_names}) found in CWD or package resources"
    )

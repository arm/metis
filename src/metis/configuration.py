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
    "anthropic": "Anthropic",
    "bedrock": "AWS Bedrock",
    "bedrock_mantle": "Bedrock Mantle",
    "gemini": "Gemini",
    "llamacpp": "llama.cpp",
}

_LLM_PROVIDER_REQUIRED_KEYS: dict[str, tuple[str, ...]] = {
    "openai": ("model",),
    "azure_openai": (
        "azure_endpoint",
        "azure_api_version",
        "engine",
        "chat_deployment_model",
    ),
    "vllm": ("base_url", "model"),
    "ollama": ("model",),
    "llamacpp": ("model",),
    "anthropic": ("model",),
    "bedrock": ("model", "region"),
    "bedrock_mantle": ("model",),
    "gemini": ("model",),
}

_EMBEDDING_PROVIDER_REQUIRED_KEYS: dict[str, tuple[str, ...]] = {
    "openai": ("code_embedding_model", "docs_embedding_model"),
    "azure_openai": (
        "azure_endpoint",
        "azure_api_version",
        "code_embedding_model",
        "docs_embedding_model",
        "code_embedding_deployment",
        "docs_embedding_deployment",
    ),
    "vllm": ("base_url", "code_embedding_model", "docs_embedding_model"),
    "ollama": ("code_embedding_model", "docs_embedding_model"),
    "llamacpp": ("code_embedding_model", "docs_embedding_model"),
    "anthropic": ("code_embedding_model", "docs_embedding_model"),
    "bedrock": ("region", "code_embedding_model", "docs_embedding_model"),
    "bedrock_mantle": ("code_embedding_model", "docs_embedding_model"),
    "gemini": ("code_embedding_model", "docs_embedding_model"),
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
    "anthropic": {
        "required": True,
        "config_keys": ("api_key",),
        "config_env_keys": ("api_key_env",),
        "env_vars": ("ANTHROPIC_API_KEY",),
    },
    "bedrock": {
        "required": False,
        "config_keys": (),
        "config_env_keys": (),
        "env_vars": (),
    },
    "bedrock_mantle": {
        "required": False,
        "config_keys": (),
        "config_env_keys": (),
        "env_vars": (),
    },
    "gemini": {
        "required": False,
        "config_keys": ("api_key",),
        "config_env_keys": ("api_key_env",),
        "env_vars": ("GOOGLE_API_KEY", "GEMINI_API_KEY"),
    },
    "llamacpp": {
        "required": False,
        "config_keys": ("api_key",),
        "config_env_keys": ("api_key_env",),
        "env_vars": ("LLAMACPP_API_KEY",),
    },
}

_ANTHROPIC_MODEL_ALIASES = {
    "opus": "claude-opus-4-8",
    "sonnet": "claude-sonnet-4-6",
    "haiku": "claude-haiku-4-5",
    "fable": "claude-fable-5",
    "mythos": "claude-mythos-5",
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


def _validate_provider_config(
    provider_name: str,
    provider_config: dict,
    required_table: dict[str, tuple[str, ...]],
    section: str,
) -> None:
    required_keys = required_table.get(provider_name)
    if not required_keys:
        return
    missing_keys = _missing_required_keys(provider_config, required_keys)
    if not missing_keys:
        return

    display_name = _LLM_PROVIDER_DISPLAY_NAMES.get(provider_name, provider_name)
    missing = ", ".join(f"{section}.{key}" for key in missing_keys)
    required = ", ".join(f"{section}.{key}" for key in required_keys)
    raise ValueError(
        f"{display_name} provider requires additional metis.yaml configuration. "
        f"Missing: {missing}. Required keys: {required}."
    )


def _validate_llm_provider_config(provider_name: str, provider_config: dict) -> None:
    _validate_provider_config(
        provider_name, provider_config, _LLM_PROVIDER_REQUIRED_KEYS, "llm_provider"
    )


def validate_embedding_provider_config(
    provider_name: str, provider_config: dict, section: str = "embedding_provider"
) -> None:
    _validate_provider_config(
        provider_name, provider_config, _EMBEDDING_PROVIDER_REQUIRED_KEYS, section
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


def _resolve_anthropic_model_name(model: str | None) -> str:
    model = str(model or "").strip()
    normalized = model.lower()
    resolved = _ANTHROPIC_MODEL_ALIASES.get(normalized, model)
    if not resolved.startswith("claude-"):
        aliases = ", ".join(_ANTHROPIC_MODEL_ALIASES)
        raise ValueError(
            "Anthropic provider requires an exact Claude model ID or a supported "
            f"short alias: {aliases}."
        )
    return resolved


def _build_provider_runtime(provider_name: str, cfg: dict) -> dict[str, object]:
    """Build the provider-specific portion of the runtime config dict."""
    runtime: dict[str, object] = {}
    api_key = _resolve_llm_api_key(provider_name, cfg)

    runtime["code_embedding_model"] = cfg.get("code_embedding_model", "")
    runtime["docs_embedding_model"] = cfg.get("docs_embedding_model", "")
    runtime["code_embedding_extra_kwargs"] = cfg.get("code_embedding_extra_kwargs", {})
    runtime["docs_embedding_extra_kwargs"] = cfg.get("docs_embedding_extra_kwargs", {})

    if not provider_name:
        raise ValueError(
            "Provider configuration is missing 'name' (e.g. 'openai', 'anthropic')."
        )
    if provider_name == "openai":
        runtime["llm_api_key"] = api_key
        runtime["openai_api_base"] = cfg.get("base_url", "")
        runtime["openai_default_headers"] = cfg.get("default_headers", {})
        runtime["model"] = cfg.get("model", "")
    elif provider_name == "azure_openai":
        runtime["llm_api_key"] = api_key
        runtime["azure_endpoint"] = cfg.get("azure_endpoint", "")
        runtime["azure_api_version"] = cfg.get("azure_api_version", "")
        runtime["engine"] = cfg.get("engine", "")
        runtime["chat_deployment_model"] = cfg.get("chat_deployment_model", "")
        runtime["code_embedding_deployment"] = cfg.get("code_embedding_deployment", "")
        runtime["docs_embedding_deployment"] = cfg.get("docs_embedding_deployment", "")
        runtime["model_token_param"] = cfg.get(
            "model_token_param", "max_completion_tokens"
        )
        runtime["supports_temperature"] = cfg.get("supports_temperature", False)
    elif provider_name == "vllm":
        runtime["llm_api_key"] = api_key
        runtime["openai_api_base"] = cfg.get("base_url", "")
        runtime["openai_default_headers"] = cfg.get("default_headers", {})
        runtime["model"] = cfg.get("model", "")
    elif provider_name == "ollama":
        runtime["llm_api_key"] = api_key
        runtime["openai_api_base"] = cfg.get("base_url", "http://localhost:11434/v1")
        runtime["openai_default_headers"] = cfg.get("default_headers", {})
        runtime["model"] = cfg.get("model", "")
        runtime["force_openai_like"] = True
    elif provider_name == "anthropic":
        raw_model = cfg.get("model")
        model = _resolve_anthropic_model_name(raw_model) if raw_model else ""
        runtime["llm_api_key"] = api_key
        runtime["embedding_api_key"] = _resolve_anthropic_embedding_api_key(cfg)
        runtime["model"] = model
        runtime["anthropic_api_url"] = cfg.get("base_url") or cfg.get(
            "anthropic_api_url"
        )
        runtime["embedding_api_base"] = cfg.get("embedding_base_url") or cfg.get(
            "embedding_api_base"
        )
        runtime["embedding_default_headers"] = cfg.get("embedding_default_headers", {})
        runtime["supports_temperature"] = cfg.get("supports_temperature", False)
    elif provider_name == "bedrock":
        runtime["llm_api_key"] = api_key
        runtime["model"] = cfg.get("model", "")
        runtime["bedrock_region"] = cfg.get("region") or cfg.get("aws_region")
        runtime["bedrock_endpoint_url"] = cfg.get("endpoint_url", "")
        runtime["supports_temperature"] = cfg.get("supports_temperature", False)
        runtime["aws_profile"] = cfg.get("aws_profile", "")
        runtime["aws_access_key_id"] = cfg.get(
            "aws_access_key_id", os.environ.get("AWS_ACCESS_KEY_ID", "")
        )
        runtime["aws_secret_access_key"] = cfg.get(
            "aws_secret_access_key", os.environ.get("AWS_SECRET_ACCESS_KEY", "")
        )
        runtime["aws_session_token"] = cfg.get(
            "aws_session_token", os.environ.get("AWS_SESSION_TOKEN", "")
        )
    elif provider_name == "bedrock_mantle":
        runtime["llm_api_key"] = api_key
        runtime["embedding_api_key"] = _resolve_anthropic_embedding_api_key(cfg)
        runtime["model"] = cfg.get("model", "")
        runtime["aws_region"] = cfg.get("aws_region")
        runtime["aws_profile"] = cfg.get("aws_profile")
        runtime["aws_access_key_id"] = cfg.get(
            "aws_access_key_id", os.environ.get("AWS_ACCESS_KEY_ID", "")
        )
        runtime["aws_secret_access_key"] = cfg.get(
            "aws_secret_access_key", os.environ.get("AWS_SECRET_ACCESS_KEY", "")
        )
        runtime["aws_session_token"] = cfg.get(
            "aws_session_token", os.environ.get("AWS_SESSION_TOKEN", "")
        )
        runtime["bedrock_base_url"] = cfg.get("base_url") or cfg.get("bedrock_base_url")
        runtime["default_headers"] = cfg.get("default_headers", {})
        runtime["supports_temperature"] = cfg.get("supports_temperature", False)
        runtime["embedding_api_base"] = cfg.get("embedding_base_url") or cfg.get(
            "embedding_api_base"
        )
        runtime["embedding_default_headers"] = cfg.get("embedding_default_headers", {})
    elif provider_name == "gemini":
        runtime["llm_api_key"] = api_key
        runtime["model"] = cfg.get("model", "")
        runtime["gemini_api_base"] = cfg.get("base_url") or cfg.get("gemini_api_base")
        runtime["gemini_additional_headers"] = cfg.get(
            "additional_headers", {}
        ) or cfg.get("gemini_additional_headers", {})
        runtime["gemini_project"] = cfg.get("project")
        runtime["gemini_location"] = cfg.get("location")
        runtime["gemini_vertexai"] = cfg.get("vertexai")
        runtime["gemini_client_args"] = cfg.get("client_args", {})
    elif provider_name == "llamacpp":
        runtime["llm_api_key"] = api_key
        runtime["openai_api_base"] = cfg.get("base_url", "")
        runtime["openai_default_headers"] = cfg.get("default_headers", {})
        runtime["model"] = cfg.get("model", "")
    else:
        raise ValueError(f"Unsupported LLM provider: {provider_name}")
    return runtime


def _resolve_anthropic_embedding_api_key(provider_config: dict) -> str:
    value = provider_config.get("embedding_api_key")
    if isinstance(value, str) and value.strip():
        return value

    env_var = provider_config.get("embedding_api_key_env")
    if isinstance(env_var, str) and env_var.strip():
        value = os.environ.get(env_var)
        if value:
            return value

    value = os.environ.get("OPENAI_API_KEY")
    if value:
        return value

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
    llm_provider_name = llm_cfg.get("name", "").lower()
    runtime["llm_provider_name"] = llm_provider_name
    _validate_llm_provider_config(llm_provider_name, llm_cfg)
    runtime.update(_build_provider_runtime(llm_provider_name, llm_cfg))

    # Embedding provider — optional separate block; falls back to llm_provider
    embed_cfg = cfg.get("embedding_provider")
    if embed_cfg:
        embed_provider_name = embed_cfg.get("name", llm_provider_name).lower()
        embed_runtime = _build_provider_runtime(embed_provider_name, embed_cfg)
    else:
        embed_provider_name = llm_provider_name
        embed_cfg = llm_cfg
        embed_runtime = dict(runtime)
    runtime["embedding_provider_name"] = embed_provider_name
    runtime["embedding_provider_config"] = embed_runtime
    runtime["embedding_provider_raw_config"] = dict(embed_cfg)

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
    runtime["enabled_tools"] = engine_cfg.get("tools")
    runtime.update(collect_reachability_config(cfg, engine_cfg))

    # Query config
    query_cfg = cfg.get("query", {})
    llama_query_model = query_cfg.get("model") or runtime.get("model", "")
    if llm_provider_name == "anthropic":
        llama_query_model = _resolve_anthropic_model_name(llama_query_model)
    runtime["llama_query_model"] = llama_query_model
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

    return runtime


def load_plugin_config():
    resource = files("metis.plugins.config") / "global.yaml"
    with as_file(resource) as real_path:
        logger.info("Loading default plugin config")
        return load_yaml(real_path)


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

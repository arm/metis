# SPDX-FileCopyrightText: Copyright 2025-2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import logging
import os
from importlib.resources import as_file
from importlib.resources import files
from pathlib import Path

import yaml

from metis.memory.registry import parse_memory_store_spec
from metis.providers.config import build_provider_config
from metis.providers.registry import get_chat_provider
from metis.providers.registry import get_embedding_provider
from metis.reachability_settings import collect_reachability_config

logger = logging.getLogger("metis")


def load_yaml(path):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


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

    llm_cfg = dict(cfg.get("llm_provider") or {})
    llm_provider_name = str(llm_cfg.get("name", "")).lower()
    runtime["llm_provider_name"] = llm_provider_name
    llm_provider_cls = _get_provider_cls(
        provider_name=llm_provider_name,
        section="llm_provider",
    )
    llm_provider_config = build_provider_config(
        provider_name=llm_provider_name,
        provider_cls=llm_provider_cls,
        raw_config=llm_cfg,
        section="llm_provider",
    )

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
    runtime["llm_max_retries"] = int(engine_cfg.get("llm_max_retries", 5))
    runtime["hnsw_kwargs"] = engine_cfg.get(
        "hnsw_kwargs",
        {
            "hnsw_m": 16,
            "hnsw_ef_construction": 64,
            "hnsw_ef_search": 40,
            "hnsw_dist_method": "vector_cosine_ops",
        },
    )
    runtime["pgvector_use_halfvec"] = pgvector_use_halfvec_setting(
        engine_cfg.get("pgvector_use_halfvec", "auto"),
        runtime["embed_dim"],
    )
    runtime["metisignore_file"] = engine_cfg.get("metisignore_file", None)
    runtime["review_code_include_paths"] = engine_cfg.get(
        "review_code_include_paths", []
    )
    runtime["review_code_exclude_paths"] = engine_cfg.get(
        "review_code_exclude_paths", []
    )
    runtime["enabled_tools"] = engine_cfg.get("tools")
    model_tools_cfg = engine_cfg.get("model_tools") or {}
    if not isinstance(model_tools_cfg, dict):
        model_tools_cfg = {}
    runtime["model_tool_max_rounds"] = _positive_int(
        model_tools_cfg.get("max_rounds"),
        fallback=6,
    )
    index_search_cfg = engine_cfg.get("index_search") or {}
    runtime["index_search_config"] = (
        dict(index_search_cfg) if isinstance(index_search_cfg, dict) else {}
    )
    memory_cfg = cfg.get("memory") or {}
    runtime["memory"] = _memory_config(memory_cfg)
    runtime.update(collect_reachability_config(cfg, engine_cfg))

    query_cfg = cfg.get("query", {})
    llama_query_model = query_cfg.get("model") or llm_provider_config.get("model", "")
    llama_query_model = str(llama_query_model or "")
    runtime["model"] = llm_provider_config.get("model", "")
    runtime["llama_query_model"] = llama_query_model
    if query_cfg.get("temperature") is not None:
        runtime["llama_query_temperature"] = query_cfg["temperature"]
    runtime["llama_query_max_tokens"] = query_cfg.get("max_tokens")
    runtime["llama_query_reasoning_effort"] = query_cfg.get(
        "reasoning_effort"
    ) or llm_cfg.get("reasoning_effort")
    runtime["similarity_top_k"] = query_cfg.get("similarity_top_k", 5)
    chat_model_kwargs: dict[str, object] = {}
    if runtime.get("llama_query_temperature") is not None:
        chat_model_kwargs["temperature"] = runtime["llama_query_temperature"]
    if runtime["llama_query_max_tokens"] is not None:
        chat_model_kwargs["max_tokens"] = runtime["llama_query_max_tokens"]
    if runtime["llama_query_reasoning_effort"]:
        chat_model_kwargs["reasoning_effort"] = runtime["llama_query_reasoning_effort"]
    runtime["chat_model_kwargs"] = chat_model_kwargs
    llm_provider_config["max_retries"] = runtime["llm_max_retries"]
    runtime["llm_provider"] = llm_provider_config

    embedding_provider_raw_config = dict(cfg.get("embedding_provider") or {})
    if not embedding_provider_raw_config:
        runtime["embedding_provider_raw_config"] = None
    else:
        runtime["embedding_provider_raw_config"] = embedding_provider_raw_config

    return runtime


def build_embedding_provider_config(
    embedding_provider_config: dict | None,
) -> dict[str, object] | None:
    embedding_cfg = dict(embedding_provider_config or {})
    if not embedding_cfg:
        return None

    provider_name = str(embedding_cfg.get("name", "")).lower()
    section = "embedding_provider"
    provider_cls = _get_provider_cls(
        provider_name=provider_name,
        section=section,
    )
    config = build_provider_config(
        provider_name=provider_name,
        provider_cls=provider_cls,
        raw_config=embedding_cfg,
        section="embedding_provider",
    )
    return {"name": provider_name, **config}


def _get_provider_cls(provider_name: str, section: str) -> type:
    try:
        if section == "llm_provider":
            return get_chat_provider(provider_name)
        return get_embedding_provider(provider_name)
    except ValueError as exc:
        raise ValueError(f"Unsupported {section} provider: {provider_name}") from exc


def _positive_int(value: object, *, fallback: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return fallback
    if parsed <= 0:
        return fallback
    return parsed


def pgvector_use_halfvec_setting(value: object, embed_dim: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "yes", "on", "1"}:
            return True
        if normalized in {"false", "no", "off", "0"}:
            return False
        if normalized != "auto":
            raise ValueError(
                "metis_engine.pgvector_use_halfvec must be true, false, or auto."
            )
    try:
        parsed_embed_dim = int(embed_dim)
    except (TypeError, ValueError):
        return False
    return parsed_embed_dim > 2000


def _memory_config(raw_config: object) -> dict[str, object]:
    if not isinstance(raw_config, dict):
        raw_config = {}
    location = str(raw_config.get("location") or ".metis/memory/metis_memory.sqlite3")
    backend = str(raw_config.get("backend") or "sqlite")
    spec = parse_memory_store_spec(
        location,
        backend=backend,
    )
    return {
        "enabled": bool(raw_config.get("enabled", False)),
        "backend": spec.backend,
        "location": spec.location,
    }


def load_plugin_config(plugins_path: str | Path | None = None):
    if plugins_path is not None:
        plugins_path = Path(plugins_path)
        if not plugins_path.is_file():
            raise FileNotFoundError(f"Config not found: {plugins_path}")
        logger.info(f"Loading {plugins_path.name} from {plugins_path}")
        return load_yaml(plugins_path)

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

        with as_file(resource) as real_path:
            logger.info(f"Loading default {candidate_filename}")
            return load_yaml(real_path)

    supported_names = ", ".join(candidate_filenames)
    raise FileNotFoundError(
        f"No config file ({supported_names}) found in CWD or package resources"
    )

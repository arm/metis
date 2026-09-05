# SPDX-FileCopyrightText: Copyright 2025-2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from collections.abc import Mapping
from contextlib import nullcontext
import logging
import os
import sys
from importlib.resources import as_file
from importlib.resources import files
from pathlib import Path
from typing import Any
from typing import cast

import yaml

from metis.memory.configuration import MemoryCapabilityConfiguration
from metis.providers.config import build_provider_config
from metis.providers.registry import get_chat_provider
from metis.providers.registry import get_embedding_provider
from metis.runtime_settings import ModelToolSettings
from metis.runtime_settings import CapabilityRuntimeSettings
from metis.runtime_settings import TriageOptions

logger = logging.getLogger("metis")


class _UniqueSafeLoader(yaml.SafeLoader):
    def __init__(self, stream):
        super().__init__(stream)
        self._checked_mappings = set()

    def construct_object(self, node, deep=False):
        try:
            return super().construct_object(node, deep=deep)
        except (ValueError, OverflowError) as exc:
            if not isinstance(node, yaml.ScalarNode):
                raise
            raise yaml.constructor.ConstructorError(
                None, None, str(exc), node.start_mark
            ) from exc

    def flatten_mapping(self, node):
        # Merged nodes can be flattened before construction. Validate each original
        # mapping once, before flattening replaces its explicit keys with inherited ones.
        if node not in self._checked_mappings:
            self._checked_mappings.add(node)
            keys = set()
            for key_node, _ in node.value:
                if key_node.tag == "tag:yaml.org,2002:value":
                    key_node.tag = "tag:yaml.org,2002:str"
                key = (
                    (key_node.tag,)
                    if key_node.tag == "tag:yaml.org,2002:merge"
                    else self.construct_object(key_node)
                )
                try:
                    duplicate = key in keys
                    keys.add(key)
                except TypeError:
                    raise yaml.constructor.ConstructorError(
                        "while constructing a mapping",
                        node.start_mark,
                        "found an unhashable key",
                        key_node.start_mark,
                    ) from None
                if duplicate:
                    raise yaml.constructor.ConstructorError(
                        "while constructing a mapping",
                        node.start_mark,
                        f"found duplicate key {key!r}",
                        key_node.start_mark,
                    )
        return super().flatten_mapping(node)


def load_yaml(path):
    stream = (
        nullcontext(path)
        if hasattr(path, "read")
        else open(path, "r", encoding="utf-8")
    )
    with stream as handle:
        loader = _UniqueSafeLoader(handle)
        try:
            return loader.get_single_data()
        finally:
            loader.dispose()


def _deep_merge(
    base: Mapping[str, Any],
    overlay: Mapping[str, Any],
    *,
    replace_empty: bool = False,
) -> dict[str, Any]:
    merged = dict(base)
    for key, value in overlay.items():
        existing = merged.get(key)
        if (
            isinstance(existing, Mapping)
            and isinstance(value, Mapping)
            and (value or not replace_empty)
        ):
            merged[key] = _deep_merge(existing, value, replace_empty=replace_empty)
        else:
            merged[key] = value
    return merged


def load_runtime_config(config_path=None, enable_psql=False):
    cfg = _required_mapping(
        load_metis_config(config_path),
        section="configuration",
        allowed={
            "metis_engine",
            "llm_provider",
            "embedding_provider",
            "query",
            "psql_database",
            "memory",
            "language_plugins",
        },
    )
    for name in (
        "llm_provider",
        "embedding_provider",
        "query",
        "psql_database",
        "language_plugins",
    ):
        if name in cfg:
            _required_mapping(cfg[name], section=name)
    engine_defaults = _packaged_engine_config()
    configured_engine = _required_mapping(
        cfg.get("metis_engine", {}),
        section="metis_engine",
        allowed=engine_defaults,
    )
    engine_cfg = {**engine_defaults, **configured_engine}
    # Only shared settings inherit defaults; graphs and node-owned settings replace them.
    for name in ("model_tools", "capabilities", "threat_model"):
        value = configured_engine.get(name)
        if isinstance(value, dict) and value:
            engine_cfg[name] = _deep_merge(
                engine_defaults[name], value, replace_empty=True
            )
    for name in (
        "model_tools",
        "capabilities",
        "execution",
        "codegraph",
        "reachability",
        "threat_model",
        "triage",
        "hnsw_kwargs",
    ):
        _required_mapping(engine_cfg[name], section=f"metis_engine.{name}")
    hnsw_kwargs = engine_cfg["hnsw_kwargs"]
    for name in ("hnsw_m", "hnsw_ef_construction", "hnsw_ef_search"):
        if name in hnsw_kwargs:
            _required_positive_int(
                hnsw_kwargs, name, section="metis_engine.hnsw_kwargs"
            )
    for name in ("max_token_length", "max_workers", "embed_dim", "doc_chunk_size"):
        _required_positive_int(engine_cfg, name, section="metis_engine")
    for name in ("max_active_nodes", "max_concurrent_executions"):
        if engine_cfg[name] is None:
            engine_cfg[name] = engine_cfg["max_workers"]
        _required_positive_int(engine_cfg, name, section="metis_engine")
    for name in ("doc_chunk_overlap", "triage_checkpoint_every", "llm_max_retries"):
        _required_positive_int(engine_cfg, name, section="metis_engine", minimum=0)
    if engine_cfg["doc_chunk_overlap"] >= engine_cfg["doc_chunk_size"]:
        raise ValueError(
            "metis_engine.doc_chunk_overlap must be less than doc_chunk_size"
        )
    for name in ("review_code_include_paths", "review_code_exclude_paths"):
        _required_string_list(engine_cfg[name], section=f"metis_engine.{name}")
    metisignore_file = engine_cfg["metisignore_file"]
    if metisignore_file is not None and not isinstance(metisignore_file, str):
        raise ValueError("metis_engine.metisignore_file must be a string or null")
    query_cfg = _required_mapping(
        cfg.get("query", {}),
        section="query",
        allowed={
            "model",
            "temperature",
            "max_tokens",
            "reasoning_effort",
            "similarity_top_k",
        },
    )
    temperature = query_cfg.get("temperature")
    if temperature is not None and (
        isinstance(temperature, bool)
        or not isinstance(temperature, (int, float))
        or not 0 <= temperature <= sys.float_info.max
    ):
        raise ValueError("query.temperature must be a finite non-negative number")
    if query_cfg.get("max_tokens") is not None:
        _required_positive_int(query_cfg, "max_tokens", section="query")
    _required_positive_int(query_cfg, "similarity_top_k", section="query", default=5)
    db_cfg = _required_mapping(
        cfg.get("psql_database", {}),
        section="psql_database",
        allowed={"provider", "credentials"},
    )
    if "credentials" in db_cfg:
        _required_mapping(
            db_cfg["credentials"],
            section="psql_database.credentials",
            allowed={"username", "password", "host", "port", "database_name"},
        )
    capability_settings = _capability_runtime_settings(engine_cfg)
    threat_model_config = _threat_model_config(engine_cfg["threat_model"])
    triage_options = _triage_options(engine_cfg["triage"])
    execution_config = load_execution_config(engine_cfg["execution"])

    # Engine imports this module, so resolve its schemas after module initialization.
    from metis.engine.nodes.codegraph.annotations import CodeGraphConfiguration
    from metis.engine.nodes.reachability.options import ReachabilityConfiguration

    CodeGraphConfiguration.model_validate(engine_cfg["codegraph"])
    ReachabilityConfiguration.model_validate(engine_cfg["reachability"])

    review_checkpoints_enabled = engine_cfg.get("review_checkpoints", True)
    if not isinstance(review_checkpoints_enabled, bool):
        raise ValueError("metis_engine.review_checkpoints must be a boolean")
    memory_config = _memory_config(cfg.get("memory"))

    runtime: dict[str, object] = {}
    if enable_psql:
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

    llm_cfg = _required_mapping(cfg.get("llm_provider", {}), section="llm_provider")
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

    for name in (
        "max_token_length",
        "max_workers",
        "max_active_nodes",
        "max_concurrent_executions",
        "embed_dim",
        "doc_chunk_size",
        "doc_chunk_overlap",
        "triage_checkpoint_every",
    ):
        runtime[name] = engine_cfg[name]
    runtime["review_checkpoints_enabled"] = review_checkpoints_enabled
    runtime["llm_max_retries"] = engine_cfg["llm_max_retries"]
    runtime["hnsw_kwargs"] = engine_cfg["hnsw_kwargs"]
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
    runtime["capability_settings"] = capability_settings
    runtime["memory"] = memory_config
    runtime["threat_model_config"] = threat_model_config
    runtime["triage_options"] = triage_options
    runtime["execution_config"] = execution_config
    runtime["codegraph_config"] = dict(engine_cfg["codegraph"])
    runtime["reachability_config"] = dict(engine_cfg["reachability"])
    language_plugins = cfg.get("language_plugins", {})
    plugin_config = load_plugin_config()
    if language_plugins:
        plugin_config["language_plugins"] = dict(language_plugins)
    runtime["plugin_config"] = plugin_config
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

    runtime["embedding_provider_raw_config"] = (
        dict(cfg.get("embedding_provider", {})) or None
    )

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
        surface = "chat" if section == "llm_provider" else "embedding"
        if str(exc) != f"Unsupported {surface} provider: {provider_name}":
            raise
        raise ValueError(f"Unsupported {section} provider: {provider_name}") from exc


def _required_positive_int(
    values: dict[str, Any],
    key: str,
    *,
    section: str,
    default: int | None = None,
    minimum: int = 1,
) -> int:
    value = values.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        requirement = "positive" if minimum else "non-negative"
        raise ValueError(f"{section}.{key} must be a {requirement} integer")
    return value


def _required_string_list(value: object, *, section: str) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"{section} must be a list of strings")
    return value


def _required_mapping(
    value: object,
    *,
    section: str,
    allowed: Mapping | set[str] | None = None,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{section} must be a mapping")
    if allowed is not None:
        unknown = value.keys() - allowed
        if unknown:
            raise ValueError(
                f"Unknown {section} settings: {', '.join(sorted(map(str, unknown)))}"
            )
    return value


def _triage_options(value: object) -> TriageOptions:
    if value is None:
        return TriageOptions()
    configured = _required_mapping(
        value, section="metis_engine.triage", allowed={"include_triaged"}
    )
    include_triaged = configured.get("include_triaged", False)
    if not isinstance(include_triaged, bool):
        raise ValueError("metis_engine.triage.include_triaged must be a boolean")
    return TriageOptions(include_triaged=include_triaged)


def _capability_runtime_settings(
    engine_config: object,
) -> CapabilityRuntimeSettings:
    engine = _required_mapping(engine_config, section="metis_engine")
    model = _load_engine_mapping("model_tools", None)
    configured_model = engine.get("model_tools")
    if configured_model is not None:
        model.update(
            _required_mapping(configured_model, section="metis_engine.model_tools")
        )
    _required_mapping(
        model,
        section="metis_engine.model_tools",
        allowed={"max_rounds", "max_contract_chars"},
    )
    capabilities = _load_engine_mapping("capabilities", engine.get("capabilities"))
    configurations: dict[str, dict[str, Any]] = {}
    for name, value in capabilities.items():
        if not isinstance(name, str) or not name.isidentifier():
            raise ValueError("metis_engine.capabilities keys must be valid names")
        if name == "memory":
            raise ValueError(
                "Configure the memory capability in the top-level memory section"
            )
        configurations[name] = _required_mapping(
            value,
            section=f"metis_engine.capabilities.{name}",
        )
    return CapabilityRuntimeSettings(
        model_tools=ModelToolSettings(
            max_rounds=_required_positive_int(
                model, "max_rounds", section="metis_engine.model_tools"
            ),
            max_contract_chars=_required_positive_int(
                model, "max_contract_chars", section="metis_engine.model_tools"
            ),
        ),
        configurations=configurations,
    )


def pgvector_use_halfvec_setting(value: object, embed_dim: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        value = value.strip().lower()
        if value in {"true", "yes", "on", "1"}:
            return True
        if value in {"false", "no", "off", "0"}:
            return False
    if value is not None and value != "auto":
        raise ValueError(
            "metis_engine.pgvector_use_halfvec must be true, false, or auto."
        )
    try:
        parsed_embed_dim = int(cast(Any, embed_dim))
    except (TypeError, ValueError):
        return False
    return parsed_embed_dim > 2000


def _memory_config(raw_config: object) -> dict[str, object]:
    return MemoryCapabilityConfiguration.model_validate(raw_config).model_dump()


def _threat_model_config(value: object) -> dict[str, object]:
    config = _required_mapping(
        value,
        section="metis_engine.threat_model",
        allowed={"source_patterns", "history"},
    )
    patterns = _required_string_list(
        config.get("source_patterns", []),
        section="metis_engine.threat_model.source_patterns",
    )
    history = _required_mapping(
        config.get("history", {}),
        section="metis_engine.threat_model.history",
        allowed={"enabled", "max_commits"},
    )
    enabled = history.get("enabled", False)
    if not isinstance(enabled, bool):
        raise ValueError("metis_engine.threat_model.history.enabled must be a boolean")
    return {
        "source_patterns": list(patterns),
        "history": {
            "enabled": enabled,
            "max_commits": _required_positive_int(
                history,
                "max_commits",
                section="metis_engine.threat_model.history",
                default=500,
            ),
        },
    }


def load_execution_config(value: object = None) -> dict[str, Any]:
    return _load_engine_mapping("execution", value)


def _load_engine_mapping(name: str, value: object) -> dict[str, Any]:
    if value is not None and not isinstance(value, dict):
        raise ValueError(f"metis_engine.{name} must be a mapping")
    if isinstance(value, dict):
        return dict(value)
    return dict(_packaged_engine_config()[name])


def _packaged_engine_config() -> dict[str, Any]:
    resource = files("metis") / "metis.yaml"
    with as_file(resource) as real_path:
        return {"triage": {}, **load_yaml(real_path)["metis_engine"]}


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

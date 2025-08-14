# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import os
import yaml


def load_yaml(path):
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_runtime_config(config_path="config.yaml", enable_psql=False):

    cfg = load_yaml(config_path)
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

    llm_provider_name = cfg.get("llm_provider", {}).get("name", "").lower()
    runtime["llm_provider_name"] = llm_provider_name
    if llm_provider_name == "openai":
        llm_api_key = os.environ.get("OPENAI_API_KEY")
        if not llm_api_key:
            raise RuntimeError(
                "OPENAI_API_KEY environment variable is required for OpenAI provider but not set."
            )
        runtime["llm_api_key"] = llm_api_key
        runtime["model"] = llm_cfg.get("model", "")
    elif llm_provider_name == "azure_openai":
        llm_api_key = os.environ.get("AZURE_OPENAI_API_KEY")
        if not llm_api_key:
            raise RuntimeError(
                "AZURE_OPENAI_API_KEY environment variable is required for Azure OpenAI provider but not set."
            )
        runtime["llm_api_key"] = llm_api_key
        runtime["azure_endpoint"] = llm_cfg.get("azure_endpoint", "")
        runtime["azure_api_version"] = llm_cfg.get("azure_api_version", "")
        runtime["chat_deployment_name"] = llm_cfg.get("chat_deployment_name", "")
        runtime["code_embedding_deployment"] = llm_cfg.get(
            "code_embedding_deployment", ""
        )
        runtime["docs_embedding_deployment"] = llm_cfg.get(
            "docs_embedding_deployment", ""
        )
    else:
        raise ValueError(f"Unsupported LLM provider: {llm_provider_name}")

    # Engine/vector store settings
    engine_cfg = cfg.get("metis_engine", {})
    runtime["max_token_length"] = engine_cfg.get("max_token_length", 100000)
    runtime["max_workers"] = engine_cfg.get("max_workers", 8)
    runtime["embed_dim"] = engine_cfg.get("embed_dim", 1536)
    runtime["hnsw_kwargs"] = engine_cfg.get(
        "hnsw_kwargs",
        {
            "hnsw_m": 16,
            "hnsw_ef_construction": 64,
            "hnsw_ef_search": 40,
            "hnsw_dist_method": "vector_cosine_ops",
        },
    )

    # Query config
    query_cfg = cfg.get("query", {})
    runtime["llama_query_model"] = query_cfg.get("model", "")
    runtime["llama_query_temperature"] = query_cfg.get("temperature", 0.0)
    runtime["llama_query_max_tokens"] = query_cfg.get("max_tokens", 500)
    runtime["similarity_top_k"] = query_cfg.get("similarity_top_k", 5)
    runtime["response_mode"] = query_cfg.get("response_mode", "compact")

    return runtime


def load_plugin_config(plugins_path="plugins.yaml"):
    return load_yaml(plugins_path)

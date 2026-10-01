# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import json
import logging

from llama_index.core import StorageContext
from llama_index.vector_stores.postgres import PGVectorStore
from sqlalchemy import Column
from sqlalchemy import MetaData
from sqlalchemy import Table
from sqlalchemy import Text
from sqlalchemy import create_engine
from sqlalchemy import func
from sqlalchemy import inspect
from sqlalchemy import select
from sqlalchemy import text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import TIMESTAMP
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.engine.url import make_url

from metis.exceptions import IndexStateError
from metis.exceptions import VectorSchemaError
from metis.exceptions import VectorStoreInitError
from metis.vector_store.llama_index_backend import LlamaIndexVectorBackend

logger = logging.getLogger(__name__)


INDEX_STATE_TABLE = "index_state"
INDEX_STATE_KEY = "index"
HALFVEC_HNSW_DIST_METHODS = {
    "vector_l2_ops": "halfvec_l2_ops",
    "vector_ip_ops": "halfvec_ip_ops",
    "vector_cosine_ops": "halfvec_cosine_ops",
}


def normalize_hnsw_kwargs(hnsw_kwargs, *, use_halfvec):
    if hnsw_kwargs is None:
        return None
    normalized = dict(hnsw_kwargs)
    if use_halfvec:
        dist_method = normalized.get("hnsw_dist_method")
        if dist_method in HALFVEC_HNSW_DIST_METHODS:
            normalized["hnsw_dist_method"] = HALFVEC_HNSW_DIST_METHODS[dist_method]
    return normalized


def copy_hnsw_kwargs(hnsw_kwargs):
    if hnsw_kwargs is None:
        return None
    return hnsw_kwargs.copy()


class PGVectorStoreImpl(LlamaIndexVectorBackend):
    def __init__(
        self,
        connection_string,
        project_schema,
        embed_model_code,
        embed_model_docs,
        embed_dim,
        query_config=None,
        hnsw_kwargs=None,
        use_halfvec=False,
    ):
        self.connection_string = connection_string
        self.project_schema = project_schema
        self.embed_model_code = embed_model_code
        self.embed_model_docs = embed_model_docs
        self.embed_dim = embed_dim
        self.query_config = query_config or {}
        self.use_halfvec = bool(use_halfvec)
        self.hnsw_kwargs = normalize_hnsw_kwargs(
            hnsw_kwargs,
            use_halfvec=self.use_halfvec,
        )
        self._initialized = False

    def init(self):
        if self._initialized:
            return
        try:
            url = make_url(self.connection_string)
            db_name = url.database

            self.vector_store_code = PGVectorStore.from_params(
                database=db_name,
                host=url.host,
                password=url.password,
                port=url.port,
                user=url.username,
                table_name="code",
                schema_name=self.project_schema,
                embed_dim=self.embed_dim,
                hnsw_kwargs=copy_hnsw_kwargs(self.hnsw_kwargs),
                use_halfvec=self.use_halfvec,
            )
            self.vector_store_docs = PGVectorStore.from_params(
                database=db_name,
                host=url.host,
                password=url.password,
                port=url.port,
                user=url.username,
                table_name="docs",
                schema_name=self.project_schema,
                embed_dim=self.embed_dim,
                hnsw_kwargs=copy_hnsw_kwargs(self.hnsw_kwargs),
                use_halfvec=self.use_halfvec,
            )

            self.storage_context_code = StorageContext.from_defaults(
                vector_store=self.vector_store_code
            )
            self.storage_context_docs = StorageContext.from_defaults(
                vector_store=self.vector_store_docs
            )

            # LlamaIndex initializes PostgreSQL lazily and consumes HNSW setup
            # options. Finish setup before concurrent first-use queries can
            # race that initialization. An empty public add initializes storage
            # without writing nodes or making embedding/model requests.
            for store in (self.vector_store_code, self.vector_store_docs):
                store.initialization_fail_on_error = True
                store.add([])

            self._initialized = True
            logger.info("Postgres vector components initialized.")

        except Exception as e:
            logger.error(f"Error initializing PGVectorStore: {e}")
            raise VectorStoreInitError()

    def check_project_schema_exists(self):
        engine = None
        try:
            engine = create_engine(self.connection_string)
            with engine.connect() as conn:
                result = conn.execute(
                    text(
                        "SELECT schema_name FROM information_schema.schemata WHERE schema_name = :schema_name"
                    ),
                    {"schema_name": self.project_schema},
                )
                exists = result.fetchone() is not None
                if exists:
                    logger.info(
                        f"Project schema '{self.project_schema}' exists in the database."
                    )
                else:
                    logger.info(
                        f"Project schema '{self.project_schema}' does not exist in the database."
                    )
                return exists
        except Exception:
            logger.error(f"Error checking for project schema '{self.project_schema}'")
            raise VectorSchemaError()
        finally:
            if engine is not None:
                engine.dispose()

    def _state_schema(self):
        """Return the schema that holds the vector tables.

        PGVectorStore lowercases the schema name before it creates the schema,
        so the state table must use the same name as the vector tables.
        """
        store = getattr(self, "vector_store_code", None)
        schema = getattr(store, "schema_name", None)
        return schema or (self.project_schema or "public").lower()

    def _state_table(self):
        return Table(
            INDEX_STATE_TABLE,
            MetaData(schema=self._state_schema()),
            Column("key", Text, primary_key=True),
            Column("value", JSONB, nullable=False),
            Column(
                "updated_at",
                TIMESTAMP(timezone=True),
                server_default=func.now(),
                nullable=False,
            ),
        )

    def get_index_state(self):
        engine = None
        try:
            engine = create_engine(self.connection_string)
            table = self._state_table()
            with engine.connect() as conn:
                if not inspect(conn).has_table(table.name, schema=table.schema):
                    return None
                value = conn.execute(
                    select(table.c.value).where(table.c.key == INDEX_STATE_KEY)
                ).scalar()
            return json.loads(value) if isinstance(value, str) else value
        except Exception as exc:
            raise IndexStateError(
                f"cannot read the state of '{self.project_schema}'"
            ) from exc
        finally:
            if engine is not None:
                engine.dispose()

    def set_index_state(self, state):
        engine = None
        try:
            engine = create_engine(self.connection_string)
            table = self._state_table()
            upsert = insert(table).values(key=INDEX_STATE_KEY, value=state)
            upsert = upsert.on_conflict_do_update(
                index_elements=[table.c.key],
                set_={"value": upsert.excluded.value, "updated_at": func.now()},
            )
            with engine.begin() as conn:
                table.create(conn, checkfirst=True)
                conn.execute(upsert)
        except Exception as exc:
            raise IndexStateError(
                f"cannot write the state of '{self.project_schema}'"
            ) from exc
        finally:
            if engine is not None:
                engine.dispose()

    def close(self):
        self._initialized = False
        for attr in ("vector_store_code", "vector_store_docs"):
            store = getattr(self, attr, None)
            if store is None:
                continue
            close_fn = getattr(store, "close", None)
            if callable(close_fn):
                try:
                    close_fn()
                except Exception as e:
                    logger.warning(f"Error closing PG vector store '{attr}': {e}")
            for engine_attr in ("_engine", "engine"):
                candidate_engine = getattr(store, engine_attr, None)
                dispose_fn = getattr(candidate_engine, "dispose", None)
                if callable(dispose_fn):
                    try:
                        dispose_fn()
                    except Exception as e:
                        logger.warning(
                            f"Error disposing engine for PG vector store '{attr}': {e}"
                        )
            if hasattr(self, attr):
                delattr(self, attr)
        for attr in ("storage_context_code", "storage_context_docs"):
            if hasattr(self, attr):
                delattr(self, attr)

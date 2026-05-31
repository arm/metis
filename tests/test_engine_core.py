# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import pytest
import tempfile
import threading
from unittest.mock import Mock
from metis.engine import MetisEngine
from metis.exceptions import PluginNotFoundError, QueryEngineInitError
from metis.usage import UsageRuntime


def test_supported_languages():
    langs = MetisEngine.supported_languages()
    assert "c" in langs
    assert "python" in langs
    assert "rust" in langs
    assert "typescript" in langs


def test_get_existing_plugin(engine):
    plugin = engine.get_plugin_from_name("c")
    assert plugin.get_name().lower() == "c"


def test_get_missing_plugin_raises(engine):
    with pytest.raises(PluginNotFoundError):
        engine.get_plugin_from_name("nonexistent")


def test_init_and_get_query_engines_raises_on_missing_backend():
    bad_backend = Mock()
    bad_backend.init = Mock()
    bad_backend.get_query_engines = Mock(return_value=(None, None))
    engine = MetisEngine(
        vector_backend=bad_backend,
        llm_provider=Mock(),
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
    )
    with pytest.raises(QueryEngineInitError):
        engine._init_and_get_query_engines()


def test_init_and_get_default_unavailable_metisignore():
    bad_backend = Mock()
    bad_backend.init = Mock()
    bad_backend.get_query_engines = Mock(return_value=(None, None))
    engine = MetisEngine(
        vector_backend=bad_backend,
        llm_provider=Mock(),
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
        metisignore_file=".metisignore_file",
    )
    assert engine.metisignore_file == ".metisignore_file"
    assert engine.repository.load_metisignore() is None


def test_init_and_get_default_available_metisignore():
    bad_backend = Mock()
    bad_backend.init = Mock()
    bad_backend.get_query_engines = Mock(return_value=(None, None))
    engine = None
    with tempfile.NamedTemporaryFile(
        mode="w+t", encoding="utf-8", suffix=".yaml"
    ) as temp_file:
        engine = MetisEngine(
            vector_backend=bad_backend,
            llm_provider=Mock(),
            max_workers=2,
            max_token_length=2048,
            llama_query_model="gpt-test",
            similarity_top_k=3,
            response_mode="compact",
            metisignore_file=temp_file.name,
        )
        assert engine.repository.load_metisignore() is not None
        assert engine.metisignore_file == temp_file.name
    assert engine is not None


def test_init_and_get_query_engines_is_thread_safe():
    backend = Mock()
    backend.init = Mock()
    backend.get_query_engines = Mock(return_value=("code-qe", "docs-qe"))
    engine = MetisEngine(
        vector_backend=backend,
        llm_provider=Mock(),
        max_workers=4,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
    )

    results = []

    def _worker():
        results.append(engine._init_and_get_query_engines())

    threads = [threading.Thread(target=_worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert results == [("code-qe", "docs-qe")] * 8
    backend.init.assert_called_once()
    backend.get_query_engines.assert_called_once()


def test_engine_passes_usage_callback_manager_to_embed_models():
    backend = Mock()
    backend.init = Mock()
    backend.get_query_engines = Mock(return_value=("code-qe", "docs-qe"))
    llm_provider = Mock()
    llm_provider.get_embed_model_code.return_value = Mock()
    llm_provider.get_embed_model_docs.return_value = Mock()

    engine = MetisEngine(
        vector_backend=backend,
        llm_provider=llm_provider,
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
    )

    assert llm_provider.get_embed_model_code.call_args.kwargs == {
        "callback_manager": engine.usage_runtime.hooks.callback_manager
    }
    assert llm_provider.get_embed_model_docs.call_args.kwargs == {
        "callback_manager": engine.usage_runtime.hooks.callback_manager
    }


def test_create_query_engines_passes_usage_callback_manager():
    backend = Mock()
    backend.init = Mock()
    backend.get_query_engines = Mock(return_value=("code-qe", "docs-qe"))
    llm_provider = Mock()
    llm_provider.get_embed_model_code.return_value = Mock()
    llm_provider.get_embed_model_docs.return_value = Mock()

    engine = MetisEngine(
        vector_backend=backend,
        llm_provider=llm_provider,
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
    )

    engine._create_query_engines(5)

    assert (
        backend.get_query_engines.call_args.kwargs["callback_manager"]
        is engine.usage_runtime.hooks.callback_manager
    )
    assert (
        backend.get_query_engines.call_args.kwargs["callbacks"]
        == engine.usage_runtime.hooks.callbacks
    )


def test_review_graph_uses_usage_callbacks():
    backend = Mock()
    backend.init = Mock()
    backend.get_query_engines = Mock(return_value=("code-qe", "docs-qe"))
    llm_provider = Mock()
    llm_provider.get_embed_model_code.return_value = Mock()
    llm_provider.get_embed_model_docs.return_value = Mock()
    llm_provider.get_chat_model.return_value = Mock(with_structured_output=Mock())

    engine = MetisEngine(
        vector_backend=backend,
        llm_provider=llm_provider,
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
    )

    engine._get_review_graph()

    assert (
        llm_provider.get_chat_model.call_args.kwargs["callbacks"]
        == engine.usage_runtime.hooks.callbacks
    )


def test_engine_reuses_injected_runtime_and_backend_embed_models(tmp_path):
    backend = Mock()
    backend.init = Mock()
    backend.get_query_engines = Mock(return_value=("code-qe", "docs-qe"))
    backend.embed_model_code = object()
    backend.embed_model_docs = object()
    llm_provider = Mock()
    runtime = UsageRuntime(tmp_path)

    engine = MetisEngine(
        codebase_path=str(tmp_path),
        vector_backend=backend,
        llm_provider=llm_provider,
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
        usage_runtime=runtime,
    )

    assert engine.usage_runtime is runtime
    assert engine.get_embed_model_code() is backend.embed_model_code
    assert engine.get_embed_model_docs() is backend.embed_model_docs
    llm_provider.get_embed_model_code.assert_not_called()
    llm_provider.get_embed_model_docs.assert_not_called()


def test_engine_exposes_focused_services_without_compat_aliases():
    backend = Mock()
    backend.init = Mock()
    backend.get_query_engines = Mock(return_value=("code-qe", "docs-qe"))
    llm_provider = Mock()
    llm_provider.get_embed_model_code.return_value = Mock()
    llm_provider.get_embed_model_docs.return_value = Mock()

    engine = MetisEngine(
        vector_backend=backend,
        llm_provider=llm_provider,
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
    )

    engine.review.review_code = Mock(return_value=iter([{"file": "a.py"}]))
    engine.indexing.update_index = Mock()

    results = list(engine.review.review_code())

    assert engine.repository is not None
    assert engine.review is not None
    assert engine.indexing is not None
    assert not hasattr(engine, "review_service")
    assert not hasattr(engine, "indexing_service")
    assert results == [{"file": "a.py"}]
    engine.indexing.update_index("diff --git")
    engine.indexing.update_index.assert_called_once_with("diff --git")


def test_close_clears_query_cache_and_closes_backend():
    backend = Mock()
    backend.init = Mock()
    backend.get_query_engines = Mock(return_value=("code-qe", "docs-qe"))
    backend.close = Mock()
    llm_provider = Mock()
    llm_provider.get_embed_model_code.return_value = Mock()
    llm_provider.get_embed_model_docs.return_value = Mock()

    engine = MetisEngine(
        vector_backend=backend,
        llm_provider=llm_provider,
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
    )

    assert engine._init_and_get_query_engines() == ("code-qe", "docs-qe")
    assert backend.get_query_engines.call_count == 1

    engine.close()

    assert engine._state.qe_code is None
    assert engine._state.qe_docs is None
    backend.close.assert_called_once()

    assert engine._init_and_get_query_engines() == ("code-qe", "docs-qe")
    assert backend.get_query_engines.call_count == 2

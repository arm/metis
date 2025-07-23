# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import pytest
from unittest.mock import Mock
from metis.engine import MetisEngine
from metis.exceptions import PluginNotFoundError, QueryEngineInitError


def test_supported_languages():
    langs = MetisEngine.supported_languages()
    assert "c" in langs
    assert "python" in langs
    assert "rust" in langs


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

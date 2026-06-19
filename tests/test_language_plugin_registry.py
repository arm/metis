# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib
import inspect
import logging
import sys
import types
from types import SimpleNamespace
from unittest.mock import Mock

from llama_index.core.schema import Document
import pytest

from metis.configuration import load_plugin_config
from metis.engine.indexing_service import IndexingService


REQUIRED_PROMPT_KEYS = (
    "security_review",
    "security_review_file",
    "security_review_checks",
    "validation_review",
)


def _import_registry_api():
    try:
        module = importlib.import_module("metis.plugins.registry")
    except ModuleNotFoundError as exc:
        pytest.xfail(
            f"Planned lazy language plugin registry module is not available yet: {exc}"
        )

    missing = [
        name
        for name in (
            "LanguagePluginManifest",
            "LanguagePluginHandle",
            "LanguagePluginRegistry",
        )
        if not hasattr(module, name)
    ]
    if missing:
        pytest.fail(
            "metis.plugins.registry is missing planned API symbols: "
            + ", ".join(missing)
        )
    return module


def _make_manifest(registry_module, **overrides):
    data = {
        "name": "c",
        "aliases": ["c"],
        "extensions": [".c", ".h"],
        "filename_patterns": [],
        "priority": 0,
        "implementation": "tests.fake_plugins:FakePlugin",
        "config_resource": "metis.plugins.languages:c.yaml",
        "capabilities": {
            "reachability_review": True,
            "c_family_triage_evidence": True,
        },
        "prompt_profile": "c_family",
    }
    data.update(overrides)
    manifest_cls = registry_module.LanguagePluginManifest
    try:
        return manifest_cls(**data)
    except TypeError:
        if hasattr(manifest_cls, "model_validate"):
            return manifest_cls.model_validate(data)
        pytest.fail(
            "LanguagePluginManifest should accept the plan fields as keyword "
            "arguments or expose model_validate(data)."
        )


def _build_registry(registry_module, manifests, *, plugin_config=None):
    registry_cls = registry_module.LanguagePluginRegistry

    ctor = inspect.signature(registry_cls)
    if "manifests" in ctor.parameters:
        kwargs = {"manifests": manifests}
        if plugin_config is not None and "plugin_config" in ctor.parameters:
            kwargs["plugin_config"] = plugin_config
        return registry_cls(**kwargs)

    for factory_name in ("from_manifests", "from_config"):
        factory = getattr(registry_cls, factory_name, None)
        if factory is None:
            continue
        sig = inspect.signature(factory)
        kwargs = {}
        if "manifests" in sig.parameters:
            kwargs["manifests"] = manifests
        if "plugin_config" in sig.parameters:
            kwargs["plugin_config"] = plugin_config or {
                "docs": {},
                "general_prompts": {},
                "plugins": {},
            }
        if kwargs:
            return factory(**kwargs)

    pytest.fail(
        "LanguagePluginRegistry should expose a manifest-based construction path "
        "for unit tests, such as __init__(manifests=...) or from_manifests(...)."
    )


def _install_fake_plugin_module(monkeypatch, module_name: str):
    module = types.ModuleType(module_name)
    state = {"instances": 0}

    class FakePlugin:
        def __init__(self, *args, **kwargs):
            state["instances"] += 1
            self.args = args
            self.kwargs = kwargs

        def get_name(self):
            return "c"

        def can_handle(self, extension: str) -> bool:
            return extension.lower() in {".c", ".h"}

        def get_splitter(self):
            return None

        def get_prompts(self):
            return {"security_review": "fake"}

        def get_supported_extensions(self):
            return [".c", ".h"]

    module.FakePlugin = FakePlugin
    monkeypatch.setitem(sys.modules, module_name, module)
    return state


def test_supported_language_names_comes_from_manifests_without_importing_plugins(
    monkeypatch,
):
    registry_module = _import_registry_api()
    import_calls = []
    real_import_module = importlib.import_module

    def _tracking_import(name, package=None):
        import_calls.append(name)
        return real_import_module(name, package)

    monkeypatch.setattr(importlib, "import_module", _tracking_import)

    registry = _build_registry(
        registry_module,
        [
            _make_manifest(
                registry_module,
                name="c",
                aliases=["c"],
                extensions=[".c", ".h"],
                implementation="fake_registry_plugins.c_plugin:FakePlugin",
            ),
            _make_manifest(
                registry_module,
                name="python",
                aliases=["python", "py"],
                extensions=[".py"],
                capabilities={"reachability_review": False},
                implementation="fake_registry_plugins.python_plugin:FakePlugin",
            ),
        ],
    )

    assert registry.supported_language_names() == ["c", "python"]
    assert import_calls == []


def test_get_manifest_for_path_matches_extensions_and_systemverilog_suffix_patterns():
    registry_module = _import_registry_api()
    registry = _build_registry(
        registry_module,
        [
            _make_manifest(
                registry_module,
                name="systemverilog",
                aliases=["systemverilog", "sv"],
                extensions=[".sv", ".svh"],
                filename_patterns=[".sv.*", ".svh.*"],
                capabilities={"reachability_review": False},
                implementation="fake_registry_plugins.systemverilog_plugin:FakePlugin",
            )
        ],
    )

    manifest = registry.get_manifest_for_path("rtl/cache_ctrl.sv.vp")

    assert manifest is not None
    assert manifest.name == "systemverilog"
    assert registry.get_manifest_for_path("rtl/cache_ctrl.svh.pp").name == (
        "systemverilog"
    )
    assert registry.get_manifest_for_path("rtl/cache_ctrl.sv").name == "systemverilog"
    assert registry.get_manifest_for_path("rtl/cache_ctrl.vp") is None


def test_supports_reachability_file_uses_manifest_capabilities_without_loading_plugins(
    monkeypatch,
    caplog,
):
    registry_module = _import_registry_api()
    import_calls = []
    real_import_module = importlib.import_module

    def _tracking_import(name, package=None):
        import_calls.append(name)
        return real_import_module(name, package)

    monkeypatch.setattr(importlib, "import_module", _tracking_import)

    registry = _build_registry(
        registry_module,
        [
            _make_manifest(
                registry_module,
                name="c",
                extensions=[".c", ".h"],
                capabilities={"reachability_review": True},
                implementation="fake_registry_plugins.c_plugin:FakePlugin",
            ),
            _make_manifest(
                registry_module,
                name="python",
                aliases=["python"],
                extensions=[".py"],
                capabilities={"reachability_review": False},
                implementation="fake_registry_plugins.python_plugin:FakePlugin",
            ),
        ],
    )

    caplog.set_level(logging.DEBUG, logger="metis")
    assert registry.supports_reachability_file("src/test.c")
    assert not registry.supports_reachability_file("src/test.py")
    assert import_calls == []
    assert (
        "Matched language plugin manifest 'c' for path 'src/test.c'; "
        "module remains lazy until needed: fake_registry_plugins.c_plugin:FakePlugin"
        in caplog.text
    )


def test_get_plugin_for_path_imports_and_instantiates_only_selected_plugin_once(
    monkeypatch,
    caplog,
):
    registry_module = _import_registry_api()
    state = _install_fake_plugin_module(monkeypatch, "test_lazy_registry_plugin")
    import_calls = []
    real_import_module = importlib.import_module

    def _tracking_import(name, package=None):
        import_calls.append(name)
        return real_import_module(name, package)

    monkeypatch.setattr(importlib, "import_module", _tracking_import)

    registry = _build_registry(
        registry_module,
        [
            _make_manifest(
                registry_module,
                name="c",
                implementation="test_lazy_registry_plugin:FakePlugin",
            ),
            _make_manifest(
                registry_module,
                name="python",
                aliases=["python"],
                extensions=[".py"],
                capabilities={"reachability_review": False},
                implementation="test_lazy_registry_plugin:FakePlugin",
            ),
        ],
    )

    assert import_calls == []

    caplog.set_level(logging.DEBUG, logger="metis")
    plugin = registry.get_plugin_for_path("src/example.c")
    same_plugin = registry.get_plugin_for_extension(".c")

    assert plugin is same_plugin
    assert plugin.get_name() == "c"
    assert import_calls == ["test_lazy_registry_plugin"]
    assert state["instances"] == 1
    assert plugin.args[0]["plugins"]["c"]["supported_extensions"] == [
        ".c",
        ".h",
    ]
    assert (
        "Loaded language plugin module 'test_lazy_registry_plugin' for 'c' using 'FakePlugin'"
        in caplog.text
    )


def test_startup_plugin_config_excludes_language_prompt_configs():
    plugin_config = load_plugin_config()

    assert set(plugin_config) == {"docs", "general_prompts"}


def test_registry_loads_required_prompt_keys_for_supported_languages():
    registry_module = _import_registry_api()
    registry = registry_module.LanguagePluginRegistry.from_config(load_plugin_config())

    missing_by_language = {
        language: missing
        for language in registry.supported_language_names()
        if (
            missing := [
                key
                for key in REQUIRED_PROMPT_KEYS
                if key not in registry.get_prompts_for_language(language)
            ]
        )
    }

    assert registry.supported_language_names() == [
        "aarch64_assembly",
        "c",
        "cpp",
        "csharp",
        "go",
        "java",
        "javascript",
        "kotlin",
        "php",
        "python",
        "rust",
        "systemverilog",
        "tablegen",
        "terraform",
        "typescript",
        "verilog",
    ]
    assert missing_by_language == {}


def test_explicit_replacement_overrides_resolved_manifest_fields(monkeypatch):
    registry_module = _import_registry_api()
    builtin = _make_manifest(
        registry_module,
        name="c",
        implementation="builtin_plugins.c:CPlugin",
        extensions=[".c"],
    )
    external = _make_manifest(
        registry_module,
        name="c",
        implementation="external_plugins.c:CPlugin",
        extensions=[".cx"],
    )
    monkeypatch.setattr(registry_module, "_load_builtin_manifests", lambda: [builtin])
    monkeypatch.setattr(
        registry_module, "_load_entry_point_manifests", lambda: [external]
    )

    registry = registry_module.LanguagePluginRegistry.from_config(
        {
            "language_plugins": {
                "c": {
                    "implementation": "external_plugins.c:CPlugin",
                    "extensions": [".cx"],
                    "config_resource": "external_plugins:c.yaml",
                }
            }
        }
    )

    manifest = registry.get_manifest("c")
    assert manifest.implementation == "external_plugins.c:CPlugin"
    assert manifest.extensions == (".cx",)
    assert manifest.config_resource == "external_plugins:c.yaml"


def test_index_prepare_nodes_includes_suffix_pattern_code_files(tmp_path, monkeypatch):
    source = tmp_path / "unit.sv.vp"
    source.write_text("module unit; endmodule\n", encoding="utf-8")
    ignored = tmp_path / "notes.txt"
    ignored.write_text("not indexed\n", encoding="utf-8")
    captured = {}

    class Reader:
        def __init__(self, **kwargs):
            captured["input_files"] = list(kwargs["input_files"])

        def load_data(self):
            return [
                Document(
                    text=source.read_text(encoding="utf-8"),
                    id_=str(source),
                )
            ]

    class Splitter:
        def get_nodes_from_documents(self, docs):
            return ["code-node:" + docs[0].id_]

    class Plugin:
        def get_name(self):
            return "systemverilog"

    plugin = Plugin()
    repo = SimpleNamespace(
        get_language_name_for_path=lambda path: (
            "systemverilog" if str(path).endswith(".sv.vp") else None
        ),
        get_doc_splitter=lambda: Splitter(),
        load_metisignore=lambda: None,
        is_metisignored=lambda _path, spec=None: False,
        get_plugin_for_path=lambda path: (
            plugin if str(path).endswith(".sv.vp") else None
        ),
        get_splitter_cached=lambda _plugin: Splitter(),
    )
    vector_backend = Mock()
    config = SimpleNamespace(
        codebase_path=str(tmp_path),
        plugin_config={"docs": {"supported_extensions": [".md"]}},
        vector_backend=vector_backend,
    )
    state = SimpleNamespace(pending_nodes=None)
    monkeypatch.setattr("metis.engine.indexing_service.SimpleDirectoryReader", Reader)

    service = IndexingService(
        config,
        state,
        repo,
        get_embedding_models=lambda: (None, None),
    )
    list(service.index_prepare_nodes_iter())

    assert str(source) in captured["input_files"]
    assert str(ignored) not in captured["input_files"]
    assert state.pending_nodes[0] == [f"code-node:{tmp_path.name}/unit.sv.vp"]

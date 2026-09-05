# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import importlib
import logging
import sys
import types
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from llama_index.core.schema import Document

from metis.configuration import load_plugin_config
from metis.configuration import load_runtime_config
from metis.configuration import load_yaml
from metis.plugins import registry as registry_module
from metis.engine.capabilities.indexing import IndexingService
from metis.engine.runtime import EngineState
from metis.plugins.base import ConfigBackedLanguagePlugin

REQUIRED_PROMPT_KEYS = (
    "security_review",
    "security_review_file",
    "security_review_checks",
    "validation_review",
)


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
            "codegraph": True,
            "c_family_triage_evidence": True,
        },
        "prompt_profile": "c_family",
    }
    data.update(overrides)
    return registry_module.LanguagePluginManifest(**data)


def _build_registry(registry_module, manifests, *, plugin_config=None):
    return registry_module.LanguagePluginRegistry(
        manifests, plugin_config=plugin_config
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
                capabilities={"codegraph": False},
                implementation="fake_registry_plugins.python_plugin:FakePlugin",
            ),
        ],
    )

    assert registry.supported_language_names() == ["c", "python"]
    assert import_calls == []


def test_get_manifest_for_path_matches_extensions_and_systemverilog_suffix_patterns():
    registry = _build_registry(
        registry_module,
        [
            _make_manifest(
                registry_module,
                name="systemverilog",
                aliases=["systemverilog", "sv"],
                extensions=[".sv", ".svh"],
                filename_patterns=[".sv.*", ".svh.*"],
                capabilities={"codegraph": False},
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


def test_codegraph_provider_uses_manifest_capabilities_without_loading_plugins(
    monkeypatch,
    caplog,
):
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
                capabilities={"codegraph": True},
                implementation="fake_registry_plugins.c_plugin:FakePlugin",
            ),
            _make_manifest(
                registry_module,
                name="python",
                aliases=["python"],
                extensions=[".py"],
                capabilities={"codegraph": False},
                implementation="fake_registry_plugins.python_plugin:FakePlugin",
            ),
        ],
    )

    caplog.set_level(logging.DEBUG, logger="metis")
    assert registry.codegraph_registration_for_path("src/test.c") == "c"
    assert registry.codegraph_registration_for_path("src/test.py") is None
    assert import_calls == []
    assert (
        "Matched language plugin manifest 'c' for path 'src/test.c'; "
        "module remains lazy until needed: fake_registry_plugins.c_plugin:FakePlugin"
        in caplog.text
    )


def test_codegraph_capability_rejects_implementation_configuration():

    with pytest.raises(ValueError, match="codegraph as a boolean"):
        _make_manifest(
            registry_module,
            capabilities={"codegraph": {"provider": "private"}},
        )


def test_get_plugin_for_path_imports_and_instantiates_only_selected_plugin_once(
    monkeypatch,
    caplog,
):
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
                capabilities={"codegraph": False},
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


def test_builtin_perl_manifest_matches_only_supported_extensions() -> None:
    registry = registry_module.LanguagePluginRegistry.from_config(load_plugin_config())

    for path in (
        "bin/audit.PL",
        "lib/Security.pm",
        "t/authorization.t",
        "app/service.psgi",
    ):
        assert registry.language_name_for_path(path) == "perl"

    for path in ("cgi/legacy.cgi", "docs/Guide.pod", "bin/extensionless"):
        assert registry.language_name_for_path(path) is None


def test_builtin_perl_plugin_is_config_backed_and_cached() -> None:
    registry = registry_module.LanguagePluginRegistry.from_config(load_plugin_config())

    plugin = registry.get_plugin_for_path("lib/Security.pm")

    assert isinstance(plugin, ConfigBackedLanguagePlugin)
    assert plugin is registry.get_plugin("perl")
    assert plugin.get_supported_extensions() == [".pl", ".pm", ".t", ".psgi"]
    assert set(REQUIRED_PROMPT_KEYS) <= set(plugin.get_prompts())
    assert "snippet_security_summary" in plugin.get_prompts()
    assert "triage_navigation" in plugin.get_prompts()


def test_startup_plugin_config_excludes_language_prompt_configs():
    plugin_config = load_plugin_config()

    assert set(plugin_config) == {"docs", "general_prompts"}


def test_registry_loads_required_prompt_keys_for_supported_languages():
    registry = registry_module.LanguagePluginRegistry.from_config(load_plugin_config())

    assert registry.codegraph_registration_for_path("src/example.c") == "c"
    assert registry.codegraph_registration_for_path("src/example.cpp") == "cpp"
    assert registry.codegraph_registration_for_path("analysis.ipynb") is None
    assert registry.language_name_for_path("src/example.sol") == "solidity"
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
        "ipynb",
        "java",
        "javascript",
        "kotlin",
        "perl",
        "php",
        "python",
        "rust",
        "solidity",
        "systemverilog",
        "tablegen",
        "terraform",
        "typescript",
        "verilog",
    ]
    assert missing_by_language == {}


def test_explicit_replacement_overrides_resolved_manifest_fields(monkeypatch):
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


def test_entry_point_accepts_manifest_object(monkeypatch):
    manifest = _make_manifest(
        registry_module,
        name="private",
        aliases=["private"],
        extensions=[".private"],
    )
    entry_point = SimpleNamespace(name="private", load=lambda: manifest)
    monkeypatch.setattr(
        registry_module.metadata,
        "entry_points",
        lambda: SimpleNamespace(select=lambda **_kwargs: (entry_point,)),
    )

    assert registry_module._load_entry_point_manifests() == [manifest]


def test_plugin_constructor_type_error_is_not_retried_without_config(monkeypatch):
    module = types.ModuleType("broken_language_plugin")
    calls = []

    class BrokenPlugin:
        def __init__(self, _plugin_config):
            calls.append("configured")
            raise TypeError("invalid plugin configuration")

    module.BrokenPlugin = BrokenPlugin
    monkeypatch.setitem(sys.modules, module.__name__, module)
    registry = _build_registry(
        registry_module,
        [
            _make_manifest(
                registry_module,
                implementation="broken_language_plugin:BrokenPlugin",
            )
        ],
    )

    with pytest.raises(TypeError, match="invalid plugin configuration"):
        registry.get_plugin("c")
    assert calls == ["configured"]


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
    state = EngineState()
    monkeypatch.setattr(
        "metis.engine.capabilities.indexing.SimpleDirectoryReader", Reader
    )

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


@pytest.mark.parametrize("profile_source", ("inherits", "manifest"))
def test_raw_yaml_registers_config_only_language_with_external_profile(
    tmp_path, monkeypatch, profile_source
):
    package_name = f"language_contract_{profile_source}"
    package = tmp_path / package_name
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "shared.yaml").write_text(
        "prompts: {shared: inherited, overridden: old}\n", encoding="utf-8"
    )
    inheritance = (
        f"inherits: {package_name}:shared.yaml\n"
        if profile_source == "inherits"
        else ""
    )
    (package / "language.yaml").write_text(
        inheritance + "prompts: {local: local, overridden: new}\n", encoding="utf-8"
    )
    monkeypatch.syspath_prepend(str(tmp_path))
    profile = (
        f"    prompt_profile: {package_name}:shared.yaml\n"
        if profile_source == "manifest"
        else ""
    )
    config_path = tmp_path / "metis.yaml"
    config_path.write_text(
        "llm_provider: {name: ollama, model: test-model}\n"
        "language_plugins:\n"
        "  contract_demo:\n"
        "    extensions: [.contractdemo]\n"
        f"    config_resource: {package_name}:language.yaml\n" + profile,
        encoding="utf-8",
    )

    try:
        runtime = load_runtime_config(config_path)
        registry = registry_module.LanguagePluginRegistry.from_config(
            runtime["plugin_config"]
        )
        assert package_name not in sys.modules
        plugin = registry.get_plugin_for_path("sample.contractdemo")

        assert isinstance(plugin, ConfigBackedLanguagePlugin)
        assert plugin is registry.get_plugin("contract_demo")
        assert plugin.get_supported_extensions() == [".contractdemo"]
        assert plugin.get_prompts() == {
            "shared": "inherited",
            "local": "local",
            "overridden": "new",
        }
        sections = plugin.plugin_config["plugins"]
        assert list(sections) == ["contract_demo"]
        assert len(sections) == 1
        assert (
            sections.copy()
            == dict(sections)
            == {"contract_demo": sections["CONTRACT_DEMO"]}
        )

    finally:
        sys.modules.pop(package_name, None)


@pytest.mark.parametrize(
    "invalid_field",
    (
        "extensions: .demo",
        "priority: true",
        'capabilities: {codegraph: "false"}',
        "extension: [.demo]",
    ),
)
def test_language_manifest_rejects_malformed_raw_fields(tmp_path, invalid_field):
    path = tmp_path / "manifest.yaml"
    path.write_text(
        "name: demo\nconfig_resource: languages/c.yaml\n" + invalid_field + "\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError):
        registry_module.LanguagePluginManifest.from_mapping(load_yaml(path))


def test_language_override_uses_manifest_name_normalization(tmp_path):
    config_path = tmp_path / "metis.yaml"
    config_path.write_text(
        "llm_provider: {name: ollama, model: test-model}\n"
        "language_plugins:\n"
        '  " C ": {name: " c ", extensions: [.contract-c]}\n',
        encoding="utf-8",
    )

    runtime = load_runtime_config(config_path)
    registry = registry_module.LanguagePluginRegistry.from_config(
        runtime["plugin_config"]
    )

    manifest = registry.get_manifest_for_path("example.contract-c")
    assert manifest.name == "c"
    assert manifest.config_resource == "languages/c.yaml"


def test_language_override_rejects_duplicate_normalized_names(tmp_path):
    config_path = tmp_path / "metis.yaml"
    config_path.write_text(
        "llm_provider: {name: ollama, model: test-model}\n"
        "language_plugins:\n"
        "  C: {extensions: [.first]}\n"
        "  c: {extensions: [.second]}\n",
        encoding="utf-8",
    )
    runtime = load_runtime_config(config_path)

    with pytest.raises(ValueError, match="Duplicate language plugin override 'c'"):
        registry_module.LanguagePluginRegistry.from_config(runtime["plugin_config"])


@pytest.mark.parametrize(
    ("name", "nested_name"),
    [("c", "cpp"), ("new_language", "c"), ("c", None)],
)
def test_language_override_cannot_change_identity(name, nested_name):
    with pytest.raises(ValueError, match="name must"):
        registry_module.LanguagePluginRegistry.from_config(
            {
                "language_plugins": {
                    name: {
                        "name": nested_name,
                        "extensions": [".replacement"],
                        "config_resource": "languages/c.yaml",
                    }
                }
            }
        )


def test_language_registry_rejects_duplicate_normalized_names():
    with pytest.raises(ValueError, match="Duplicate language plugin name 'c'"):
        _build_registry(
            registry_module,
            [
                _make_manifest(registry_module),
                _make_manifest(registry_module, name=" C "),
            ],
        )


@pytest.mark.parametrize("priorities", [(0, 10), (10, 10)])
def test_language_aliases_use_priority_and_reject_ambiguity(priorities):
    manifests = [
        _make_manifest(
            registry_module, name=name, aliases=["shared"], priority=priority
        )
        for name, priority in zip(("first", "second"), priorities)
    ]
    for ordered in (manifests, manifests[::-1]):
        registry = _build_registry(registry_module, ordered)
        if priorities[0] == priorities[1]:
            with pytest.raises(ValueError, match="Ambiguous language plugin match"):
                registry.get_manifest("shared")
        else:
            assert registry.get_manifest("SHARED").name == "second"
        assert registry.get_manifest("first").name == "first"


def test_canonical_language_name_precedes_alias_priority():
    registry = _build_registry(
        registry_module,
        [
            _make_manifest(registry_module, name="first"),
            _make_manifest(
                registry_module, name="second", aliases=["first"], priority=100
            ),
        ],
    )
    assert registry.get_manifest("first").name == "first"


@pytest.mark.parametrize("section", ("splitting", "prompts"))
@pytest.mark.parametrize("source", ("language", "profile"))
def test_language_config_validates_merged_sections_before_caching(
    tmp_path, monkeypatch, section, source
):
    package_name = f"language_invalid_{section}_{source}"
    package = tmp_path / package_name
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    language_path = package / "language.yaml"
    profile_path = package / "profile.yaml"
    language_path.write_text(
        f"inherits: {package_name}:profile.yaml\n", encoding="utf-8"
    )
    profile_path.write_text("custom_setting: {preserved: true}\n", encoding="utf-8")
    malformed = language_path if source == "language" else profile_path
    with malformed.open("a", encoding="utf-8") as handle:
        handle.write(f"{section}: []\n")
    monkeypatch.syspath_prepend(str(tmp_path))
    registry = _build_registry(
        registry_module,
        [
            _make_manifest(
                registry_module,
                implementation="",
                config_resource=f"{package_name}:language.yaml",
            )
        ],
    )
    try:
        plugin = registry.get_plugin("c")
        for get_config in (
            plugin.get_prompts,
            lambda: registry.get_prompts_for_language("c"),
        ):
            with pytest.raises(
                ValueError, match=f"resource .*{section} must be a mapping"
            ):
                get_config()
        malformed.write_text(
            malformed.read_text(encoding="utf-8").replace(
                f"{section}: []", f"{section}: {{}}"
            ),
            encoding="utf-8",
        )
        assert plugin.get_prompts() == {}
        assert plugin.plugin_config["plugins"]["c"]["custom_setting"] == {
            "preserved": True
        }
    finally:
        sys.modules.pop(package_name, None)

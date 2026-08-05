# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from threading import Condition
from threading import Event
from types import SimpleNamespace

import metis.engine.nodes.codegraph.provider as providers
import pytest
from metis.engine.codegraph import CodeGraph
from metis.engine.codegraph import CodeGraphAnnotations
from metis.engine.codegraph import CodeGraphProviderContext
from metis.engine.codegraph import CodeGraphResult
from metis.engine.codegraph import FunctionNode
from metis.engine.codegraph import Tag
from metis.engine.nodes.codegraph import CodeGraphSemanticsCatalog
from metis.engine.nodes.codegraph import CodeGraphService
from metis.engine.nodes.reachability.context import ReachabilityContext
from metis.engine.nodes.reachability.options import ReachabilityReviewOptions
from metis.plugins.c_family.semantics import CFamilyCodeGraphSemantics


class _EntryPoints:
    def __init__(self, entries=()):
        self._entries = entries

    def select(self, *, group):
        assert group == providers.CODEGRAPH_PROVIDER_ENTRY_POINT_GROUP
        return self._entries


def _repository(files, registration_for_path):
    return SimpleNamespace(
        get_code_files=lambda **_kwargs: files,
        get_codegraph_registration=registration_for_path,
        get_language_name_for_path=lambda path: (
            "c" if str(path).endswith(".c") else "python"
        ),
        has_language_file_role=lambda _path, _role: False,
    )


def _provider(graph):
    return SimpleNamespace(
        build_graph=lambda **kwargs: CodeGraphResult(
            graph,
            processed_files=kwargs["files"],
        )
    )


def test_provider_discovery_is_lazy(monkeypatch):
    loaded = []
    entry = SimpleNamespace(
        name="python",
        load=lambda: loaded.append("python") or (lambda _context: object()),
    )
    monkeypatch.setattr(
        providers.metadata,
        "entry_points",
        lambda: _EntryPoints([entry]),
    )

    discovered = providers.discover_provider_factories(
        {"c_family": lambda _context: object()}
    )

    assert set(discovered) == {"c_family", "python"}
    assert loaded == []
    assert discovered["python"](object()) is not None
    assert loaded == ["python"]


def test_languages_with_one_provider_implementation_share_one_build(tmp_path):
    (tmp_path / "source.c").write_text("void source(void) {}\n", encoding="utf-8")
    (tmp_path / "target.cpp").write_text("void target() {}\n", encoding="utf-8")
    builds = []

    def build_graph(**kwargs):
        builds.append(kwargs["files"])
        return CodeGraphResult(CodeGraph(), kwargs["files"])

    def factory(_context):
        return SimpleNamespace(build_graph=build_graph)

    repository = _repository(
        ("source.c", "target.cpp"),
        lambda path: "cpp" if path.endswith(".cpp") else "c",
    )
    service = CodeGraphService(
        SimpleNamespace(codebase_path=str(tmp_path)),
        repository,
        {"c": factory, "cpp": factory},
    )

    service.materialize()

    assert builds == [("source.c", "target.cpp")]


def test_materialize_persists_and_reuses_codegraph(tmp_path):
    source = tmp_path / "module.py"
    source.write_text("def entry(): pass\n", encoding="utf-8")
    built = []
    graph = CodeGraph()
    graph.add_node(FunctionNode("module.py::entry", "module.py", "entry", 1))

    def factory(context):
        assert isinstance(context, CodeGraphProviderContext)

        def build_graph(**kwargs):
            built.append(kwargs["files"])
            return CodeGraphResult(graph, kwargs["files"])

        return SimpleNamespace(build_graph=build_graph)

    service = CodeGraphService(
        SimpleNamespace(codebase_path=str(tmp_path)),
        _repository(("module.py",), lambda _path: "python"),
        {"python": factory},
    )
    assert not (tmp_path / ".metis").exists()

    first = service.materialize()
    second = service.materialize()
    first_graph = service.load(first)
    first_graph.add_node(FunctionNode("new", "module.py", "new", 2))

    assert first == second
    assert built == [("module.py",)]
    assert (tmp_path / ".metis" / "codegraph.sqlite3").is_file()
    assert service.load(second).get_node("new") is None


def test_materialize_rebuilds_when_source_changes(tmp_path):
    source = tmp_path / "module.py"
    source.write_text("x", encoding="utf-8")
    calls = []

    def build_graph(**kwargs):
        calls.append(kwargs["files"])
        graph = CodeGraph()
        revision_name = f"entry_{len(calls)}"
        graph.add_node(
            FunctionNode(
                f"module.py::{revision_name}",
                "module.py",
                revision_name,
                1,
            )
        )
        return CodeGraphResult(graph, kwargs["files"])

    service = CodeGraphService(
        SimpleNamespace(codebase_path=str(tmp_path)),
        _repository(("module.py",), lambda _path: "python"),
        {"python": lambda _context: SimpleNamespace(build_graph=build_graph)},
    )

    first = service.materialize()
    original = source.stat()
    source.write_text("y", encoding="utf-8")
    os.utime(source, ns=(original.st_atime_ns, original.st_mtime_ns))
    second = service.materialize()

    assert len(calls) == 2
    assert second.revision > first.revision
    assert second.fingerprint != first.fingerprint
    with pytest.raises(ValueError, match="not the current canonical graph"):
        service.load(first)
    assert service.load(second).get_node("module.py::entry_2") is not None
    assert service.load(second).get_node("module.py::entry_1") is None


def test_load_rejects_corrupt_stored_codegraph(tmp_path):
    graph = CodeGraph()
    graph.add_node(FunctionNode("module.py::entry", "module.py", "entry", 1))
    service = CodeGraphService(
        SimpleNamespace(codebase_path=str(tmp_path)),
        _repository(("module.py",), lambda _path: "python"),
        {"python": lambda _context: _provider(graph)},
    )
    reference = service.materialize()
    with sqlite3.connect(tmp_path / ".metis" / "codegraph.sqlite3") as connection:
        connection.execute(
            "UPDATE canonical_codegraph SET graph = ? WHERE revision = ?",
            ("not-json", reference.revision),
        )

    with pytest.raises(RuntimeError, match="Stored CodeGraph.*is invalid"):
        service.load(reference)

    rebuilt = service.materialize()

    assert rebuilt.revision > reference.revision
    assert service.load(rebuilt).get_node("module.py::entry") is not None


def test_load_rejects_tampered_reference_metadata(tmp_path):
    service = CodeGraphService(
        SimpleNamespace(codebase_path=str(tmp_path)),
        _repository(("module.py",), lambda _path: "python"),
        {"python": lambda _context: _provider(CodeGraph())},
    )
    reference = service.materialize()
    tampered = reference.model_copy(update={"failed_files": ("module.py",)})

    with pytest.raises(ValueError, match="not the current canonical graph"):
        service.load(tampered)


def test_materialize_includes_suffix_pattern_sources(tmp_path):
    selections = []
    repository = _repository(("module.c.in",), lambda _path: "c_family")

    def get_code_files(**options):
        selections.append(options)
        return ("module.c.in",)

    repository.get_code_files = get_code_files
    service = CodeGraphService(
        SimpleNamespace(codebase_path=str(tmp_path)),
        repository,
        {"c_family": lambda _context: _provider(CodeGraph())},
    )

    reference = service.materialize()

    assert selections == [{"include_suffixed_sources": True}]
    assert reference.failed_files == ()


def test_materialize_reports_incomplete_provider_coverage(tmp_path):
    service = CodeGraphService(
        SimpleNamespace(codebase_path=str(tmp_path)),
        _repository(("module.py",), lambda _path: "python"),
        {
            "python": lambda _context: SimpleNamespace(
                build_graph=lambda **_kwargs: CodeGraphResult(CodeGraph(), ())
            )
        },
    )

    reference = service.materialize()

    assert reference.failed_files == ("module.py",)
    assert "invalid file coverage" in reference.diagnostics[0].message


def test_concurrent_materialize_serializes_canonical_builds(tmp_path):
    builds = []

    def build_graph(**_kwargs):
        builds.append("build")
        return CodeGraphResult(CodeGraph(), ("module.py",))

    service = CodeGraphService(
        SimpleNamespace(codebase_path=str(tmp_path)),
        _repository(("module.py",), lambda _path: "python"),
        {"python": lambda _context: SimpleNamespace(build_graph=build_graph)},
    )
    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(service.materialize)
        second = executor.submit(service.materialize)
        first_reference = first.result()
        second_reference = second.result()

    assert first_reference == second_reference
    assert builds == ["build"]


def test_concurrent_materialize_shares_an_incomplete_attempt(tmp_path):
    builds = []
    build_started = Event()
    caller_waiting = Event()
    release_build = Event()

    class TrackingCondition(Condition):
        def wait_for(self, predicate, timeout=None):
            caller_waiting.set()
            return super().wait_for(predicate, timeout)

    def build_graph(**_kwargs):
        builds.append("build")
        build_started.set()
        release_build.wait()
        return CodeGraphResult(CodeGraph(), ())

    service = CodeGraphService(
        SimpleNamespace(codebase_path=str(tmp_path)),
        _repository(("module.py",), lambda _path: "python"),
        {"python": lambda _context: SimpleNamespace(build_graph=build_graph)},
    )
    service._materialize_condition = TrackingCondition()
    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(service.materialize)
        build_started.wait()
        second = executor.submit(service.materialize)
        caller_waiting.wait()
        release_build.set()
        first_reference = first.result()
        second_reference = second.result()

    assert first_reference == second_reference
    assert first_reference.failed_files == ("module.py",)
    assert builds == ["build"]


def test_reachability_reads_deterministic_annotations_from_codegraph(tmp_path):
    graph = CodeGraph()
    graph.add_node(
        FunctionNode(
            "main.c::main",
            "main.c",
            "main",
            1,
            calls=["copy"],
        )
    )
    graph.add_node(
        FunctionNode(
            "main.c::copy",
            "main.c",
            "copy",
            2,
            calls=["memcpy"],
        )
    )
    graph.resolve_all_calls()
    repository = _repository(
        ("main.c",),
        lambda _path: "c_family",
    )
    service = CodeGraphService(
        SimpleNamespace(codebase_path=str(tmp_path)),
        repository,
        {"c_family": lambda _context: _provider(graph)},
        semantics=CodeGraphSemanticsCatalog(
            providers={"c_family": CFamilyCodeGraphSemantics()},
        ),
    )

    reference = service.materialize()
    loaded, paths = ReachabilityContext(service).graph_and_paths(
        codegraph=service.load(reference),
        options=ReachabilityReviewOptions(),
    )

    assert loaded.get_node("main.c::main").is_source is True
    assert loaded.get_node("main.c::copy").sink_type == "buffer_overflow"
    assert [path.path for path in paths] == [["main.c::main", "main.c::copy"]]


def test_file_without_codegraph_semantics_is_not_supported(tmp_path):
    service = CodeGraphService(
        SimpleNamespace(codebase_path=str(tmp_path)),
        _repository(("module.py",), lambda _path: "python"),
        {"python": lambda _context: _provider(CodeGraph())},
    )

    assert service.supports_file("module.py") is True
    assert service.supports_semantics("module.py") is False
    assert ReachabilityContext(service).supports_file("module.py") is False


def test_failed_codegraph_semantics_falls_back_and_retries(tmp_path):
    builds = []
    graph = CodeGraph()
    graph.add_node(FunctionNode("module.py::entry", "module.py", "entry", 1))

    class FlakySemantics:
        calls = 0

        def analyze_node(self, _facts):
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("temporary failure")
            return CodeGraphAnnotations()

    service = CodeGraphService(
        SimpleNamespace(codebase_path=str(tmp_path)),
        _repository(
            ("module.py",),
            lambda _path: "python",
        ),
        {
            "python": lambda _context: SimpleNamespace(
                build_graph=lambda **kwargs: (
                    builds.append(kwargs["files"])
                    or CodeGraphResult(graph, kwargs["files"])
                )
            )
        },
    )
    service._semantics = CodeGraphSemanticsCatalog(
        (SimpleNamespace(name="python", load=lambda: FlakySemantics),)
    )

    first = service.materialize()
    second = service.materialize()
    third = service.materialize()

    assert first.failed_files == ("module.py",)
    assert first.diagnostics[0].severity == "warning"
    assert second.failed_files == ()
    assert second.revision > first.revision
    assert third == second
    assert service.load(second).get_node("module.py::entry") is not None
    assert len(builds) == 2


def test_semantics_tags_are_applied_and_persisted(tmp_path):
    source = tmp_path / "module.py"
    source.write_text("def entry(): pass\n", encoding="utf-8")
    graph = CodeGraph()
    graph.add_node(FunctionNode("module.py::entry", "module.py", "entry", 1))

    class Semantics:
        def analyze_node(self, _facts):
            return CodeGraphAnnotations(
                tags={
                    "trust.domain": Tag(value="user", reason="crosses ioctl"),
                    "risk.churn": Tag(value="high"),
                },
            )

    service = CodeGraphService(
        SimpleNamespace(codebase_path=str(tmp_path)),
        _repository(
            ("module.py",),
            lambda _path: "python",
        ),
        {"python": lambda _context: _provider(graph)},
    )
    service._semantics = CodeGraphSemanticsCatalog(
        (SimpleNamespace(name="python", load=lambda: Semantics),)
    )

    reference = service.materialize()

    assert reference.failed_files == ()
    fresh = CodeGraphService(
        SimpleNamespace(codebase_path=str(tmp_path)),
        _repository((), lambda _path: None),
        {},
    )
    node = fresh.load(reference).get_node("module.py::entry")
    assert node.tags == {
        "trust.domain": Tag(value="user", reason="crosses ioctl"),
        "risk.churn": Tag(value="high"),
    }
    assert node.has_tag("trust.domain")
    assert not node.has_tag("risk.owner")

# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from threading import Condition
from threading import Event
from types import SimpleNamespace

import pytest

import metis.engine.nodes.codegraph.provider as providers
from metis.engine.codegraph import CallSite
from metis.engine.codegraph import CodeExpression
from metis.engine.codegraph import CodeGraph
from metis.engine.codegraph import CodeGraphAnnotations
from metis.engine.codegraph import CodeGraphProviderContext
from metis.engine.codegraph import CodeGraphResult
from metis.engine.codegraph import ControlCondition
from metis.engine.codegraph import FunctionNode
from metis.engine.codegraph import FunctionParameter
from metis.engine.codegraph import GlobalConstruct
from metis.engine.codegraph import LoopStructure
from metis.engine.codegraph import SymbolReference
from metis.engine.codegraph import Tag
from metis.engine.codegraph import ValueAssignment
from metis.engine.nodes.codegraph import CodeGraphSemanticsCatalog
from metis.engine.nodes.codegraph import CodeGraphService
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
    graph.add_node(
        FunctionNode(
            "module.py::entry",
            "module.py",
            "entry",
            1,
            parameter_count=2,
        )
    )

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
    assert service.load(second).nodes["module.py::entry"].parameter_count == 2
    with sqlite3.connect(tmp_path / ".metis" / "codegraph.sqlite3") as connection:
        metadata_columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(canonical_codegraph)")
        }
        stored_nodes = connection.execute(
            "SELECT COUNT(*) FROM codegraph_records WHERE kind = 'node'"
        ).fetchone()[0]

    assert "graph" not in metadata_columns
    assert stored_nodes == 1


def test_materialize_persists_semantic_codegraph_evidence(tmp_path):
    source = tmp_path / "module.c"
    source.write_text("void entry(int value) {}\n", encoding="utf-8")
    expression = CodeExpression(
        "state->value",
        1,
        12,
        24,
        identifiers=("state", "value"),
        field_paths=("state.value",),
        direct_field_path="state.value",
    )
    condition = ControlCondition(expression, True)
    call = CallSite(
        symbol="sink",
        line=1,
        argument_count=1,
        start_byte=30,
        end_byte=40,
        target_ids=("module.c::sink",),
        arguments=(expression,),
        conditions=(condition,),
        result=expression,
    )
    assignment = ValueAssignment(
        target=expression,
        value=expression,
        operator="=",
        line=1,
        start_byte=12,
        end_byte=24,
        conditions=(condition,),
    )
    loop = LoopStructure(
        condition=expression,
        line=1,
        start_byte=10,
        end_byte=45,
        written_identifiers=("value",),
        addressed_identifiers=("state",),
    )
    graph = CodeGraph()
    graph.add_node(
        FunctionNode(
            "module.c::entry",
            "module.c",
            "entry",
            1,
            parameters=(FunctionParameter("state", ""),),
            call_sites=[call],
            assignments=[assignment],
            loops=[loop],
        )
    )
    graph.add_node(FunctionNode("module.c::sink", "module.c", "sink", 1))
    global_reference = SymbolReference("sink", 1, target_ids=("module.c::sink",))
    global_construct = GlobalConstruct(
        "module.c::callback",
        "module.c",
        "callback",
        1,
        initializer="sink",
        referenced_functions=["sink"],
        references=[global_reference],
    )
    graph.add_global(global_construct)
    graph.add_public_declarations({"entry": ["module.h:1"]})
    service = CodeGraphService(
        SimpleNamespace(codebase_path=str(tmp_path)),
        _repository(("module.c",), lambda _path: "c"),
        {"c": lambda _context: _provider(graph)},
    )

    loaded_graph = service.load(service.materialize())
    loaded = loaded_graph.nodes["module.c::entry"]

    assert loaded.call_sites == [call]
    assert loaded.parameters == (FunctionParameter("state", ""),)
    assert loaded.assignments == [assignment]
    assert loaded.loops == [loop]
    assert loaded_graph.globals["module.c::callback"] == global_construct
    assert loaded_graph.public_declarations == {"entry": ["module.h:1"]}


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
    assert service.load(first).get_node("module.py::entry_1") is not None
    assert service.load(second).get_node("module.py::entry_2") is not None
    assert service.load(second).get_node("module.py::entry_1") is None


def test_load_rejects_incomplete_stored_codegraph(tmp_path):
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
            "DELETE FROM codegraph_records WHERE kind = 'node' AND identity = ?",
            ("module.py::entry",),
        )

    with pytest.raises(RuntimeError, match="Stored CodeGraph.*is invalid"):
        service.load(reference)

    rebuilt = service.materialize()

    assert rebuilt.revision > reference.revision
    assert service.load(rebuilt).get_node("module.py::entry") is not None


def test_materialize_replaces_main_branch_store_schema(tmp_path):
    store_path = tmp_path / ".metis" / "codegraph.sqlite3"
    store_path.parent.mkdir()
    with sqlite3.connect(store_path) as connection:
        connection.execute(
            """
            CREATE TABLE canonical_codegraph (
                revision INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT NOT NULL UNIQUE,
                producer_version TEXT NOT NULL,
                content_hash TEXT NOT NULL
            )
            """
        )
        connection.execute("PRAGMA user_version = 1")

    graph = CodeGraph()
    graph.add_node(FunctionNode("module.py::entry", "module.py", "entry", 1))
    service = CodeGraphService(
        SimpleNamespace(codebase_path=str(tmp_path)),
        _repository(("module.py",), lambda _path: "python"),
        {"python": lambda _context: _provider(graph)},
    )

    loaded = service.load(service.materialize())
    with sqlite3.connect(store_path) as connection:
        columns = {
            row[1]
            for row in connection.execute("PRAGMA table_info(canonical_codegraph)")
        }
        schema_version = connection.execute("PRAGMA user_version").fetchone()[0]

    assert loaded.get_node("module.py::entry") is not None
    assert columns == {
        "revision",
        "fingerprint",
        "producer_version",
        "content_hash",
    }
    assert schema_version == 2


def test_failed_persistence_keeps_previous_graph(tmp_path):
    source = tmp_path / "module.py"
    source.write_text("first", encoding="utf-8")
    builds = 0

    def build_graph(**kwargs):
        nonlocal builds
        builds += 1
        graph = CodeGraph()
        name = "first" if builds == 1 else "blocked"
        graph.add_node(FunctionNode(f"module.py::{name}", "module.py", name, 1))
        return CodeGraphResult(graph, kwargs["files"])

    service = CodeGraphService(
        SimpleNamespace(codebase_path=str(tmp_path)),
        _repository(("module.py",), lambda _path: "python"),
        {"python": lambda _context: SimpleNamespace(build_graph=build_graph)},
    )
    first = service.materialize()
    store_path = tmp_path / ".metis" / "codegraph.sqlite3"
    with sqlite3.connect(store_path) as connection:
        connection.execute(
            """
            CREATE TRIGGER reject_blocked_node
            BEFORE INSERT ON codegraph_records
            WHEN NEW.kind = 'node' AND NEW.identity = 'module.py::blocked'
            BEGIN
                SELECT RAISE(ABORT, 'blocked');
            END
            """
        )
    source.write_text("second", encoding="utf-8")

    with pytest.raises(RuntimeError, match="Unable to persist CodeGraph store"):
        service.materialize()

    with sqlite3.connect(store_path) as connection:
        stored_names = tuple(
            row[0]
            for row in connection.execute(
                """
                SELECT identity FROM codegraph_records
                WHERE kind = 'node' ORDER BY position
                """
            )
        )

    assert stored_names == ("module.py::first",)
    assert service.load(first).get_node("module.py::first") is not None


def test_load_rejects_tampered_reference_metadata(tmp_path):
    service = CodeGraphService(
        SimpleNamespace(codebase_path=str(tmp_path)),
        _repository(("module.py",), lambda _path: "python"),
        {"python": lambda _context: _provider(CodeGraph())},
    )
    reference = service.materialize()
    tampered = reference.model_copy(update={"failed_files": ("module.py",)})

    with pytest.raises(ValueError, match="reference does not exist"):
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


def test_concurrent_different_file_seeds_keep_both_graphs(tmp_path):
    for name in ("first.py", "second.py"):
        (tmp_path / name).write_text(f"def {name[:-3]}(): pass\n", encoding="utf-8")

    def build_graph(**kwargs):
        graph = CodeGraph()
        path = os.path.basename(kwargs["files"][0])
        name = path[:-3]
        graph.add_node(FunctionNode(f"{path}::{name}", path, name, 1))
        return CodeGraphResult(graph, kwargs["files"])

    repository = _repository((), lambda _path: "python")
    repository.is_code_file_selected = lambda path, **_kwargs: (
        tmp_path / path
    ).is_file()
    service = CodeGraphService(
        SimpleNamespace(codebase_path=str(tmp_path)),
        repository,
        {"python": lambda _context: SimpleNamespace(build_graph=build_graph)},
    )

    with ThreadPoolExecutor(max_workers=2) as executor:
        first_future = executor.submit(service.materialize, seed_file="first.py")
        second_future = executor.submit(service.materialize, seed_file="second.py")
        first = first_future.result()
        second = second_future.result()

    assert service.load(first).get_node("first.py::first") is not None
    assert service.load(second).get_node("second.py::second") is not None


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

    loaded = service.load(service.materialize())

    assert loaded.get_node("main.c::main").is_source is True
    assert loaded.get_node("main.c::copy").sink_type == "buffer_overflow"


def test_semantics_receives_structured_relationship_facts(tmp_path):
    source = tmp_path / "main.c"
    source.write_text("void target(void) {}\n", encoding="utf-8")
    graph = CodeGraph()
    target = FunctionNode("main.c::target", "main.c", "target", 1)
    caller = FunctionNode(
        "main.c::caller",
        "main.c",
        "caller",
        2,
        calls=["target"],
        call_sites=[
            CallSite(
                "target",
                2,
                0,
                target_ids=(target.unique_name,),
            )
        ],
        references=[
            SymbolReference(
                "target",
                2,
                target_ids=(target.unique_name,),
            )
        ],
    )
    graph.add_node(caller)
    graph.add_node(target)
    graph.resolve_all_calls()
    captured = {}

    class CapturingSemantics:
        def analyze_node(self, facts):
            captured[facts.name] = facts
            return CodeGraphAnnotations()

    service = CodeGraphService(
        SimpleNamespace(codebase_path=str(tmp_path)),
        _repository(("main.c",), lambda _path: "c_family"),
        {"c_family": lambda _context: _provider(graph)},
        semantics=CodeGraphSemanticsCatalog(
            providers={"c_family": CapturingSemantics()},
        ),
    )

    service.materialize()

    assert captured["caller"].call_sites == tuple(caller.call_sites)
    assert captured["caller"].references == tuple(caller.references)


def test_file_without_codegraph_semantics_is_not_supported(tmp_path):
    service = CodeGraphService(
        SimpleNamespace(codebase_path=str(tmp_path)),
        _repository(("module.py",), lambda _path: "python"),
        {"python": lambda _context: _provider(CodeGraph())},
    )

    assert service.supports_file("module.py") is True
    assert service.supports_semantics("module.py") is False


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

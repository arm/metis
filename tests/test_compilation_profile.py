# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import os
import random
import shlex
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from metis.engine import MetisEngine
from metis.engine.capabilities.builtins import builtin_capability_registrations
from metis.engine.capabilities.contracts import CapabilityContext
from metis.engine.capabilities.navigation import NavigationCapability
from metis.engine.capabilities.navigation import NavigationCapabilityConfiguration
from metis.engine.nodes.triage.workflow import workflow as triage_workflow
from metis.engine.stages.triage.models import TriageDecisionModel
from metis.engine.codegraph import CodeGraphReference
from metis.engine.concurrency import JobScheduler
from metis.engine.nodes.codegraph import CodeGraphService
from metis.engine.nodes.codegraph.progress import CODEGRAPH_REUSED
from metis.engine.nodes.compilation_profile import service as compilation_profile
from metis.engine.nodes.compilation_profile.database import CompilationUnit
from metis.engine.nodes.compilation_profile.database import load_compilation_database
from metis.engine.nodes.simple_llm_review.service import SimpleLlmReviewService
from metis.engine.repository import EngineRepository
from metis.engine.source import SourceMap
from metis.plugins.c_family.codegraph import CFamilyCodeGraphProvider
from metis.plugins.registry import LanguagePluginRegistry
from metis.sarif.writer import generate_sarif


def _compiler() -> str:
    if os.name == "nt":
        pytest.skip("GNU-compatible preprocessing test")
    compiler = next(
        (path for name in ("gcc", "clang", "cc") if (path := shutil.which(name))),
        None,
    )
    if compiler is None:
        pytest.skip("No GCC-compatible compiler is installed")
    return compiler


def _entry(
    directory: Path,
    source: Path | str,
    *arguments: str,
    compiler: str | None = None,
    command: bool = False,
) -> dict[str, object]:
    argv = [compiler or _compiler(), *arguments, "-c", str(source)]
    return {
        "directory": str(directory),
        "file": str(source),
        ("command" if command else "arguments"): shlex.join(argv) if command else argv,
    }


def _build_profile(
    root: Path,
    node_jobs,
    entries: list[dict[str, object]],
    *,
    timeout: int = 30,
):
    path = root / "compile_commands.json"
    path.write_text(json.dumps(entries))
    database = load_compilation_database(
        codebase_path=str(root),
        compile_commands_path=path.name,
    )
    return compilation_profile.build_profiled_source(
        codebase_path=str(root),
        database=database,
        timeout_seconds=timeout,
        jobs=node_jobs,
    )


def _graph(
    root: Path,
    files: list[Path],
    artifact=None,
    *,
    progress_callback=None,
):
    repository = EngineRepository(
        SimpleNamespace(codebase_path=str(root)), SimpleNamespace()
    )
    repository.get_code_files = lambda **_kwargs: [str(path) for path in files]
    repository.get_codegraph_registration = lambda _path: "c"
    repository.get_language_name_for_path = lambda path: (
        "cpp" if Path(path).suffix in {".cc", ".cpp", ".cxx", ".hpp"} else "c"
    )
    repository.has_language_file_role = lambda path, role: (
        role == ("header" if Path(path).suffix in {".h", ".hpp"} else "source")
    )
    if artifact is not None:
        repository.install_profiled_source(artifact)
    service = CodeGraphService(
        SimpleNamespace(codebase_path=str(root)),
        repository,
        {"c": CFamilyCodeGraphProvider},
    )
    reference = service.materialize(progress_callback=progress_callback)
    return repository, service.load(reference), reference


def _node(graph, name: str):
    matches = [node for node in graph.nodes.values() if node.name == name]
    assert len(matches) == 1
    return matches[0]


@pytest.mark.parametrize("command", (False, True), ids=("arguments", "command"))
@pytest.mark.parametrize("suffix", [".c", ".cpp"])
@pytest.mark.parametrize("newline", [b"\n", b"\r\n"])
@pytest.mark.parametrize("final_newline", [False, True])
def test_real_database_profiles_read_only_project_and_drives_codegraph(
    tmp_path: Path,
    node_jobs,
    command: bool,
    suffix: str,
    newline: bytes,
    final_newline: bool,
    monkeypatch,
) -> None:
    root = tmp_path / "project with spaces"
    build = root / "build dir"
    sources = root / "source dir"
    generated = root / "generated headers"
    for directory in (build, sources, generated):
        directory.mkdir(parents=True)
    header = generated / "config.h"
    header.write_text("// header\n\n#define VALUE 7\n")
    source = sources / ("máin file" + suffix)
    source.write_bytes(
        b'const char *line_text = "#line 100"; /* #line 200 \xff\f */\r\n'
        b"// #line 300\r\n"
        b'#include "config.h"\r\n'
        b"#define WRAP(value) \\\r\n  value\r\n"
        b"#if FEATURE\r\n"
        b"void target(void) {}\r\n"
        b"void active(void) { WRAP(target()); VALUE; }\r\n"
        b"#else\r\nvoid inactive(void) {}\r\n#endif"
    )
    source.write_bytes(
        source.read_bytes().replace(b"\r\n", newline)
        + (newline if final_newline else b"")
    )
    arguments = (
        "-DFEATURE=1",
        "-I",
        "../generated headers",
        "-g",
        "-Werror",
        "-MD",
        "--dependencies",
        "--user-dependencies",
        "--write-dependencies",
        "--write-user-dependencies",
        "--print-missing-file-dependencies",
        "--no-line-commands",
        "--dump=M",
        "-Wp,-MMD,forwarded.d",
        "--output=discarded.o",
        "-MF",
        "deps/main.d",
        "-fdirectives-only",
        "-save-stats=cwd",
        "-fdeps-file=deps.json",
        "-dependency-file",
        str(build / "dependencies"),
        "-serialize-diagnostics",
        str(build / "diagnostics"),
        "-serialize-diagnostics=diagnostics-attached",
        "-o",
        "objects/main.o",
    )
    entry = _entry(build, f"../source dir/{source.name}", *arguments, command=command)
    entry["directory"] = "build dir"
    artifact = _build_profile(root, node_jobs, [entry])
    raw = source.read_bytes()
    canonical = artifact.canonical_sources[source.relative_to(root).as_posix()]

    assert len(canonical) == len(raw)
    assert canonical.count(b"\n") == raw.count(b"\n")
    assert canonical.index(b"void active") == raw.index(b"void active")
    assert b"  value" + newline in canonical
    assert b"WRAP(target())" in canonical
    assert b"void inactive" not in canonical
    assert "generated headers/config.h" in artifact.canonical_sources
    assert not any(build.rglob("*"))

    _repository, graph, _reference = _graph(root, [source, header], artifact)
    active = _node(graph, "active")
    assert active.resolved_calls == [_node(graph, "target").unique_name]
    assert not any(node.name == "inactive" for node in graph.nodes.values())
    assert raw[active.start_byte : active.end_byte].startswith(b"void active")
    source_map = SourceMap.for_bytes(active.file_path, canonical, anchor_source=raw)
    anchor = source_map.resolve_issue(
        snippet="WRAP(target())", start_line=10, end_line=10
    )
    assert (anchor.start_line, anchor.end_line) == (8, 8)
    assert anchor.start_byte == raw.index(b"void active")
    assert anchor.symbol == f"{active.file_path}::active"
    sarif = generate_sarif(
        {
            "reviews": [
                {
                    "file": active.file_path,
                    "file_path": str(source),
                    "reviews": [{"issue": "Active call", "anchor": anchor.to_dict()}],
                }
            ]
        }
    )
    region = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "region"
    ]
    assert (region["startLine"], region["endLine"]) == (8, 8)
    nav = NavigationCapability(
        codebase_path=str(root),
        timeout_seconds=8,
        max_chars=16000,
        repository=_repository,
    )
    path = source.relative_to(root).as_posix()
    assert "inactive" not in nav.cat(path)
    assert nav.sed(path, 8, 8) == "8: " + source_map.lines[7]
    assert nav.grep("void active", path) == f"{path}:8:{source_map.lines[7]}"
    assert nav.sed("generated headers/config.h", 3, 3) == "3: #define VALUE 7"
    decision = TriageDecisionModel(
        status="valid",
        reason="Coordinate check.",
        evidence=[f"{path}:6-11"],
        resolution_chain=["active body"],
    )
    monkeypatch.setattr(
        triage_workflow, "_triage_decision", lambda *a, **kw: (decision, "ok")
    )
    workflow = triage_workflow.TriageWorkflow(Mock(), "offline", nav)
    state = {
        "source_observations": [
            {
                "tool": "sed",
                "arguments": {"path": path, "start_line": 6, "end_line": 11},
                "output": nav.sed(path, 6, 11),
            }
        ]
    }
    assert workflow._decide(state)["decision_source"] == "model"
    source.write_bytes(raw + b"/* drift */")
    result = workflow._decide(state)
    assert result["decision_source"] == "validation_failure"
    assert result["decision"].status == "inconclusive"


def test_compiler_option_values_are_not_treated_as_flags(tmp_path, node_jobs):
    includes = tmp_path / "-output-headers"
    includes.mkdir()
    (includes / "config.h").write_text("#define FEATURE 1\n")
    (tmp_path / "-options.h").write_text("#define FORCED 1\n")
    source = tmp_path / "source.c"
    source.write_text(
        '#include "config.h"\n'
        "#if FEATURE && FORCED\nvoid active(void) {}\n"
        "#else\nvoid inactive(void) {}\n#endif\n"
    )
    artifact = _build_profile(
        tmp_path,
        node_jobs,
        [_entry(tmp_path, source, "-I", includes.name, "-include", "-options.h")],
    )
    assert b"void active" in artifact.canonical_sources[source.name]
    assert b"void inactive" not in artifact.canonical_sources[source.name]


def test_precompiled_header_mode_is_rejected_before_preprocessing(
    tmp_path, node_jobs, monkeypatch
):
    compiler = _compiler()
    header = tmp_path / "config.h"
    header.write_text("#define FEATURE 1\nint helper(void) { return 7; }\n")
    source = tmp_path / "source.c"
    source.write_text("#if FEATURE\nint caller(void) { return helper(); }\n#endif\n")
    subprocess.run(
        [compiler, "-x", "c-header", str(header), "-o", str(header) + ".gch"],
        check=True,
        capture_output=True,
        timeout=30,
    )
    preprocess = Mock(side_effect=AssertionError("Unsupported compiler mode executed"))
    monkeypatch.setattr(compilation_profile.subprocess, "run", preprocess)

    with pytest.raises(ValueError, match="unsupported argument '-fpch-preprocess'"):
        _build_profile(
            tmp_path,
            node_jobs,
            [
                _entry(
                    tmp_path,
                    source,
                    "-include",
                    str(header),
                    "-fpch-preprocess",
                    compiler=compiler,
                )
            ],
        )
    preprocess.assert_not_called()


@pytest.mark.parametrize("location", ("unit", "header", "external_header"))
@pytest.mark.parametrize(
    "source_bytes",
    (b"void active(void) {}\r", b"/* first\rsecond */\nvoid active(void) {}\n"),
    ids=("cr_line_ending", "embedded_cr"),
)
def test_profile_rejects_ambiguous_line_endings(
    tmp_path, node_jobs, location, source_bytes
):
    root = tmp_path / "project"
    root.mkdir()
    source = root / "sample.c"
    source.write_text('#include "header.h"\n')
    directory = tmp_path if location == "external_header" else root
    invalid = source if location == "unit" else directory / "header.h"
    invalid.write_bytes(source_bytes)

    with pytest.raises(RuntimeError, match="LF or CRLF") as error:
        _build_profile(root, node_jobs, [_entry(root, source, "-I", str(directory))])
    assert invalid.name in str(error.value)


def test_fully_inactive_source_skips_llm_review(tmp_path, node_jobs):
    source = tmp_path / "sample.c"
    source.write_bytes(b"#if 0\nvoid inactive(void) {}\n#endif\n")
    artifact = _build_profile(tmp_path, node_jobs, [_entry(tmp_path, source)])
    assert not artifact.canonical_sources[source.name].strip()
    repository, codegraph, _ = _graph(tmp_path, [source], artifact)
    assert not codegraph.nodes
    repository.get_plugin_for_path = lambda _: SimpleNamespace(get_prompts=dict)
    graph = Mock()
    graph.review.return_value = None
    service = SimpleLlmReviewService(
        SimpleNamespace(codebase_path=str(tmp_path)), repository, lambda *_: graph
    )

    assert service._review_file_standard(str(source)) is None
    graph.review.assert_not_called()


@pytest.mark.parametrize(
    "arguments, message",
    (
        (("-I",), "requires a value"),
        (("-include",), "requires a value"),
        (("-MF",), "requires a value"),
        (("--output",), "requires a value"),
        (("-I", "@flags.rsp"), "unsupported argument"),
        (("-o", "@flags.rsp"), "unsupported argument"),
    ),
)
def test_compiler_option_values_are_validated(tmp_path, arguments, message):
    unit = CompilationUnit("test", tmp_path, tmp_path / "source.c", ("cc", *arguments))
    with pytest.raises(ValueError, match=message):
        compilation_profile._sanitized_argv(unit)


@pytest.mark.parametrize(
    "payload",
    (b"{", b"[]", b"[{}]"),
)
def test_invalid_compilation_databases_fail_closed(
    tmp_path: Path,
    payload: bytes,
) -> None:
    database = tmp_path / "compile_commands.json"
    database.write_bytes(payload)

    with pytest.raises(ValueError, match="[Cc]ompilation database"):
        load_compilation_database(
            codebase_path=str(tmp_path),
            compile_commands_path=database.name,
        )


def test_compiler_selection_and_failures_are_reported(
    tmp_path: Path,
    node_jobs,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.c"
    source.write_text("void active(void) {}\n")
    missing = _entry(tmp_path, source, compiler="missing-compiler")
    with pytest.raises(FileNotFoundError, match="not available on PATH"):
        _build_profile(tmp_path, node_jobs, [missing])

    broken = tmp_path / "broken.c"
    broken.write_text('#include "missing-header.h"\n')
    with pytest.raises(RuntimeError, match="missing-header.h"):
        _build_profile(tmp_path, node_jobs, [_entry(tmp_path, broken)])
    with pytest.raises(FileNotFoundError, match=r"source does not exist: .*missing\.c"):
        _build_profile(tmp_path, node_jobs, [_entry(tmp_path, tmp_path / "missing.c")])

    with monkeypatch.context() as context:
        context.setattr(
            compilation_profile.subprocess,
            "run",
            lambda *args, **kwargs: compilation_profile.subprocess.CompletedProcess(
                args[0],
                1,
                stdout=b"",
                stderr=b"header error: " + b"x" * 6000 + b"omitted-tail",
            ),
        )
        with pytest.raises(RuntimeError, match="header error") as error:
            _build_profile(tmp_path, node_jobs, [_entry(tmp_path, source)])
        assert "diagnostics truncated" in str(error.value)
        assert "omitted-tail" not in str(error.value)
        assert len(str(error.value)) < 4300

    def time_out(*args, **kwargs):
        assert kwargs["timeout"] == 7
        raise compilation_profile.subprocess.TimeoutExpired(args[0], 1)

    monkeypatch.setattr(compilation_profile.subprocess, "run", time_out)
    with pytest.raises(RuntimeError, match="TimeoutExpired"):
        _build_profile(tmp_path, node_jobs, [_entry(tmp_path, source)], timeout=7)


@pytest.mark.parametrize(
    "directive",
    (
        "#line 100",
        "#define LINE 100\n#line LINE",
        "#/**/line 100",
        "#li\\\nne 100",
        '# 100 "generated.c"',
        "%:line 100",
        "??=line 100",
        "#li??/\nne 100",
        "#\fline 100",
        "#\vline 100",
    ),
)
def test_source_line_directive_spellings_are_rejected(
    tmp_path: Path,
    node_jobs,
    directive: str,
) -> None:
    source = tmp_path / "source.c"
    source.write_text(f"{directive}\nvoid active(void) {{}}\n")

    with pytest.raises(RuntimeError, match="do not support source #line"):
        _build_profile(tmp_path, node_jobs, [_entry(tmp_path, source)])


def test_external_line_directive_cannot_add_project_files(
    tmp_path: Path,
    node_jobs,
) -> None:
    root = tmp_path / "project"
    sdk = tmp_path / "sdk"
    root.mkdir()
    sdk.mkdir()
    victim = root / "victim.h"
    victim.write_text("void victim(void) {}\n")
    header = sdk / "external.h"
    clean = sdk / "clean.h"
    clean.write_text("#define CLEAN 1\n")
    header.write_text("#define VALUE 1\n")
    source = root / "source.c"
    source.write_text('#include "external.h"\nvoid active(void) {}\n')
    entry = _entry(root, source, "-I", str(sdk))

    _build_profile(root, node_jobs, [entry])
    for directive in (
        f'#line 1 "{victim}"',
        f'# 1 "{victim}" 1',
        f'# 1 "{victim}" 3',
        f'# 1 "{clean}" 1\n# 1 "{victim}" 1',
    ):
        header.write_text(f"{directive}\nvoid injected(void) {{}}\n")
        with pytest.raises(RuntimeError, match="#line directives"):
            _build_profile(root, node_jobs, [entry])


def test_cpp_raw_strings_do_not_hide_or_create_line_directives(
    tmp_path: Path,
    node_jobs,
) -> None:
    source = tmp_path / "source.cpp"
    source.write_text(
        'const char *text = R"TAG(\n" text\n#line 5\n)TAG";\nvoid active() {}\n'
    )
    _build_profile(tmp_path, node_jobs, [_entry(tmp_path, source)])

    source.write_text(
        'const char *text = R"TAG(")TAG";\n'
        '#line 100 "generated.cpp"\nvoid active() {}\n'
    )
    with pytest.raises(RuntimeError, match="do not support source #line"):
        _build_profile(tmp_path, node_jobs, [_entry(tmp_path, source)])


@pytest.mark.parametrize(
    "argument",
    (
        "@flags.rsp",
        "--",
        "-save-temps=obj",
        "-ftime-trace",
        "-Xclang",
        "-Xpreprocessor",
        "-Wp,-MD,deps.d,-DFEATURE=1",
        "-Wp,-unknown",
    ),
)
def test_opaque_or_side_effecting_arguments_are_rejected(
    tmp_path: Path,
    node_jobs,
    argument: str,
) -> None:
    source = tmp_path / "source.c"
    source.write_text("void active(void) {}\n")

    with pytest.raises(ValueError, match="unsupported argument"):
        _build_profile(tmp_path, node_jobs, [_entry(tmp_path, source, argument)])


def test_multi_profile_headers_are_ambiguous_and_deterministic(
    tmp_path: Path,
    node_jobs,
) -> None:
    header = tmp_path / "variant.h"
    header.write_text(
        "#if MODE\nstatic void enabled(void) {}\n"
        "#else\nstatic void disabled(void) {}\n#endif\n"
        "static int sized(void) { return SIZE; }\n",
    )
    entries = []
    for mode, size in ((0, 4), (1, 8)):
        source = tmp_path / f"source_{mode}.c"
        source.write_text('#include "variant.h"\n')
        entries.append(
            _entry(
                tmp_path,
                source,
                f"-DMODE={mode}",
                f"-DSIZE={size}",
                "-I",
                str(tmp_path),
            )
        )

    threaded = _build_profile(tmp_path, node_jobs, entries)
    scheduler = JobScheduler(1)
    try:
        serial = _build_profile(tmp_path, scheduler.limit(1), entries)
    finally:
        scheduler.close()
    assert threaded.reference.fingerprint == serial.reference.fingerprint
    assert set(threaded.raw_sources) - set(threaded.canonical_sources) == {"variant.h"}
    assert "variant.h" not in threaded.canonical_sources
    assert "variant.h" in threaded.raw_sources
    repository, graph, _reference = _graph(tmp_path, [header], threaded)
    assert not graph.nodes
    view = repository.source_view_for_path(str(header))
    assert view is not None and view.canonical == header.read_bytes()
    (tmp_path / "other.c").write_text("void reference_only(void) {}\n")
    nav = NavigationCapability(
        codebase_path=str(tmp_path),
        timeout_seconds=8,
        max_chars=16000,
        repository=repository,
    )
    assert "enabled" in nav.cat("variant.h") and "disabled" in nav.cat("variant.h")
    assert nav.grep("void enabled", "variant.h").startswith("variant.h:2:")
    assert nav.grep("void disabled", "variant.h").startswith("variant.h:4:")
    assert "reference_only" in nav.cat("other.c")
    assert "reference_only" in nav.grep("reference_only", "other.c")

    header.write_text(header.read_text() + "/* source drift */\n")
    changed = _build_profile(tmp_path, node_jobs, entries)
    assert changed.reference.compile_commands_sha256 == (
        threaded.reference.compile_commands_sha256
    )
    assert changed.reference.fingerprint != threaded.reference.fingerprint


def test_repeated_profile_views_expand_once_and_converge(
    tmp_path: Path,
    node_jobs,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "source.c"
    source.write_bytes(b"static int value = \\\n    1;\n")

    def preprocess(unit, **_kwargs):
        active = frozenset({1, 2} if "-DMODE=2" in unit.argv else {1})
        return compilation_profile._ProfiledUnit(
            unit.profile_id,
            frozenset({source.name}),
            {source.name: active},
            frozenset(),
        )

    expand = Mock(wraps=compilation_profile._include_line_continuations)
    monkeypatch.setattr(compilation_profile, "_preprocess", preprocess)
    monkeypatch.setattr(compilation_profile, "_include_line_continuations", expand)
    artifact = _build_profile(
        tmp_path,
        node_jobs,
        [_entry(tmp_path, source, f"-DMODE={mode}") for mode in range(3)],
    )

    assert expand.call_count == 2
    assert artifact.reference.source_views == 3
    assert artifact.reference.active_line_count == 2
    assert artifact.reference.ambiguous_files == 0
    assert artifact.canonical_sources[source.name] == source.read_bytes()


def test_inactive_line_mask_matches_bytewise_reference() -> None:
    random_source = random.Random(19)
    sources = [b"", bytes(range(256)), b"first\r\nsecond\rlast\n"]
    sources.extend(
        random_source.randbytes(random_source.randrange(2000)) for _ in range(200)
    )
    for source in sources:
        active = {
            line
            for line in range(source.count(b"\n") + 3)
            if random_source.randrange(2)
        }
        expected = bytearray(source)
        line = 1
        for index, value in enumerate(source):
            if value == 10:
                line += 1
            elif value != 13 and line not in active:
                expected[index] = 32
        assert compilation_profile._mask_inactive_lines(source, active) == expected


def test_profile_fingerprint_distinguishes_ambiguous_from_inactive_source() -> None:
    raw = {"variant.h": b"#if FEATURE\nvoid active(void);\n#endif\n"}

    assert compilation_profile._fingerprint(raw, {}) != (
        compilation_profile._fingerprint(raw, {"variant.h": b""})
    )


def test_profile_install_invalidates_raw_graph_cache_and_reuses_profiled_graph(
    tmp_path: Path,
    node_jobs,
) -> None:
    source = tmp_path / "source.c"
    source.write_text(
        "#if FEATURE\nvoid active(void) {}\n#else\nvoid inactive(void) {}\n#endif\n",
    )
    unprofiled = tmp_path / "unprofiled.c"
    unprofiled.write_text("void unprofiled(void) {}\n")
    artifact = _build_profile(
        tmp_path,
        node_jobs,
        [_entry(tmp_path, source, "-DFEATURE=1")],
    )
    _raw_repository, raw_graph, raw_reference = _graph(tmp_path, [source, unprofiled])
    repository, profiled_graph, profiled_reference = _graph(
        tmp_path,
        [source, unprofiled],
        artifact,
    )

    assert "source.c::inactive" in raw_graph.nodes
    assert "unprofiled.c::unprofiled" in raw_graph.nodes
    assert any(node.name == "active" for node in profiled_graph.nodes.values())
    assert not any(node.name == "inactive" for node in profiled_graph.nodes.values())
    assert not any(node.name == "unprofiled" for node in profiled_graph.nodes.values())
    assert repository.analysis_source_for_path(str(unprofiled)) == b""
    assert raw_reference.fingerprint != profiled_reference.fingerprint
    different = _build_profile(
        tmp_path,
        node_jobs,
        [_entry(tmp_path, source, "-DFEATURE=0")],
    )
    equivalent = _build_profile(
        tmp_path,
        node_jobs,
        [_entry(tmp_path, source, "-DFEATURE=1", "-g")],
    )
    assert different.reference.fingerprint != artifact.reference.fingerprint
    assert equivalent.reference.fingerprint == artifact.reference.fingerprint
    unprofiled.write_text("void changed_outside_the_build(void) {}\n")
    events: list[dict[str, object]] = []
    _repository, persisted, reused_reference = _graph(
        tmp_path,
        [source, unprofiled],
        equivalent,
        progress_callback=events.append,
    )
    assert reused_reference == profiled_reference
    assert persisted.nodes.keys() == profiled_graph.nodes.keys()
    assert [event["event"] for event in events] == [CODEGRAPH_REUSED]

    _, _, narrower = _graph(tmp_path, [source], equivalent)
    assert narrower.fingerprint != profiled_reference.fingerprint

    expanded = _build_profile(
        tmp_path,
        node_jobs,
        [_entry(tmp_path, source, "-DFEATURE=1"), _entry(tmp_path, unprofiled)],
    )
    _, expanded_graph, expanded_reference = _graph(
        tmp_path, [source, unprofiled], expanded
    )
    assert expanded_reference.fingerprint != profiled_reference.fingerprint
    assert "unprofiled.c::changed_outside_the_build" in expanded_graph.nodes

    source.write_text(source.read_text().replace("inactive", "changed_"))
    with pytest.raises(RuntimeError, match="changed after initialization"):
        repository.source_view_for_path(str(source))
    with pytest.raises(RuntimeError, match="changed after initialization"):
        _graph(tmp_path, [source, unprofiled], equivalent)


def test_initialize_reuses_stored_graph_until_source_changes(
    tmp_path: Path,
    dummy_backend,
    dummy_llm,
    dummy_embedding_provider,
    capability_settings,
    monkeypatch,
) -> None:
    source = tmp_path / "source.c"
    source.write_text("void target(void) {}\nvoid active(void) { target(); }\n")
    assembly = tmp_path / "startup.S"
    assembly.write_text("nop\n")
    database = tmp_path / "compile_commands.json"
    ignored = _entry(tmp_path, assembly, compiler="missing-compiler")
    ignored["directory"] = str(tmp_path / "missing-build-directory")
    database.write_text(json.dumps([_entry(tmp_path, source), ignored]))
    options = {
        "codebase_path": str(tmp_path),
        "vector_backend": dummy_backend,
        "llm_provider": dummy_llm,
        "embedding_provider": dummy_embedding_provider,
        "max_workers": 2,
        "max_token_length": 2048,
        "llama_query_model": "gpt-test",
        "similarity_top_k": 3,
        "capability_settings": capability_settings,
        "execution_config": {
            "stages": {
                "initialize": {
                    "outputs": {
                        "profiled_source": "compilation_profile.profiled_source",
                        "codegraph": "codegraph.codegraph",
                    },
                    "nodes": {
                        "compilation_profile": {},
                        "codegraph": {"depends_on": ["compilation_profile"]},
                    },
                }
            },
            "node_configuration": {
                "initialize": {
                    "compilation_profile": {
                        "compile_commands_path": database.name,
                    }
                }
            },
        },
    }
    engine = MetisEngine(**options)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(
                CFamilyCodeGraphProvider,
                "__metis_cache_identity__",
                "metis.plugins.c_family.codegraph:CFamilyCodeGraphProvider:2",
            )
            legacy = engine.init_codebase()
        initialized = engine.init_codebase()
        assert (
            legacy["codegraph"]["fingerprint"]
            != initialized["codegraph"]["fingerprint"]
        )
        assert (tmp_path / ".metis" / "codegraph.sqlite3").is_file()
        with monkeypatch.context() as patch:
            rebuild = Mock(side_effect=AssertionError("Unchanged graph was rebuilt"))
            patch.setattr(CFamilyCodeGraphProvider, "build_graph", rebuild)
            repeated = engine.init_codebase()
            fresh = MetisEngine(**options)
            try:
                restored = fresh.init_codebase()
                reference = CodeGraphReference.model_validate(restored["codegraph"])
                loaded = fresh.execution._codegraphs.load(reference)
                assert _node(loaded, "active").resolved_calls == [
                    _node(loaded, "target").unique_name
                ]
            finally:
                fresh.close()
            rebuild.assert_not_called()
        source.write_text("void changed(void) {}\n")
        changed = engine.init_codebase()
    finally:
        engine.close()

    assert initialized["profiled_source"]["profiled_files"] == 1
    assert initialized["profiled_source"]["translation_units"] == 1
    assert repeated == initialized
    assert restored == initialized
    assert initialized["codegraph"]["fingerprint"]
    assert (
        changed["codegraph"]["fingerprint"] != initialized["codegraph"]["fingerprint"]
    )


@pytest.mark.parametrize("name", ["source.c", "source.inc", "source"])
def test_navigation_factory_tracks_late_profile_install_and_rejects_drift(
    tmp_path, node_jobs, name
):
    source = tmp_path / name
    source.write_text("#if 0\nvoid inactive(void);\n#endif\nvoid active(void) {}\n")
    unit = tmp_path / "unit.c"
    unit.write_text(f'#include "{name}"\n')
    artifact = _build_profile(tmp_path, node_jobs, [_entry(tmp_path, unit)])
    repository = EngineRepository(
        SimpleNamespace(
            codebase_path=str(tmp_path),
            language_registry=LanguagePluginRegistry.from_config(),
        ),
        SimpleNamespace(),
    )
    registration = next(
        r
        for r in builtin_capability_registrations(Mock(), Mock(), repository)
        if r.manifest.name == "navigation"
    )
    nav = registration.factory(
        CapabilityContext(tmp_path, repository, 4, 2048),
        NavigationCapabilityConfiguration(timeout_seconds=8, max_chars=16000),
    )
    assert "inactive" in nav.cat(name)
    repository.install_profiled_source(artifact)
    assert (repository.source_view_for_path(str(source)) is None) == (
        name != "source.c"
    )
    assert "inactive" not in nav.cat(name)
    assert nav.sed(name, -2, -1) == nav.cat(name).rsplit("\n", 1)[0]
    assert nav.grep("inactive", name) == ""
    with ThreadPoolExecutor(max_workers=4) as pool:
        assert (
            list(pool.map(lambda _: nav.grep("void active", name), range(4)))
            == [f"{name}:4:void active(void) {{}}"] * 4
        )
    cached = nav._profile_cache
    assert cached is not None
    assert nav._source_snapshot() is cached[1]
    source.write_text(source.read_text() + "void changed(void);\n")
    for operation in [
        lambda: nav.cat(name),
        lambda: nav.sed(name, 1, 4),
        lambda: nav.grep("active", name),
    ]:
        with pytest.raises(RuntimeError, match="changed after initialization"):
            operation()
    refreshed = _build_profile(tmp_path, node_jobs, [_entry(tmp_path, unit)])
    repository.install_profiled_source(refreshed)
    assert nav.grep("changed", name) == f"{name}:5:void changed(void);"
    refreshed_cache = nav._profile_cache
    assert refreshed_cache is not None and refreshed_cache != cached
    for payload in [
        '{"source.c": ["bad", "fake"]}',
        json.dumps({"source.c": ("0" * 64, 123)}),
        '{"source.c": [], "source.c": []}',
    ]:
        nav._profile_cache = (refreshed_cache[0], payload)
        with pytest.raises(RuntimeError, match="ValidationError|ValueError"):
            nav.grep("active", name)


def test_navigation_profile_filters_before_clipping(tmp_path, node_jobs):
    source = tmp_path / "source.c"
    source.write_text(
        "#if 0\n" + "void inactive(void);\n" * 100 + "#endif\nvoid active(void) {}\n"
    )
    artifact = _build_profile(tmp_path, node_jobs, [_entry(tmp_path, source)])
    repository, _, _ = _graph(tmp_path, [source], artifact)
    nav = NavigationCapability(
        codebase_path=str(tmp_path),
        timeout_seconds=8,
        max_chars=80,
        repository=repository,
    )
    assert nav.grep("void", ".") == "source.c:103:void active(void) {}"
    assert nav.sed("source.c", 103, 103) == "103: void active(void) {}"
    assert nav.sed("source.c", 103, 10**30) == "103: void active(void) {}"
    assert nav.sed("source.c", 10**30, 10**30) == ""

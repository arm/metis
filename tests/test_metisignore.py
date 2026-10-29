# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import Mock
import errno
import os
import threading

import pathspec
import pytest

import metis.engine.capabilities.indexing as indexing_service_mod
from metis.engine import MetisEngine
from metis.engine import ExecutionGraphError
from metis.engine.nodes.simple_llm_review.service import SimpleLlmReviewService
from metis.generated_artifacts import generated_artifact_publication


def _build_engine(
    tmp_path,
    dummy_backend,
    dummy_llm,
    capability_settings,
    **kwargs,
):
    class _EmbeddingProvider:
        def get_embed_model_code(self, **_kwargs):
            return object()

        def get_embed_model_docs(self, **_kwargs):
            return object()

    return MetisEngine(
        codebase_path=str(tmp_path),
        vector_backend=dummy_backend,
        llm_provider=dummy_llm,
        embedding_provider=_EmbeddingProvider(),
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        capability_settings=capability_settings,
        **kwargs,
    )


def test_get_code_files_supports_default_metisignore_allowlist(
    tmp_path, dummy_backend, dummy_llm, capability_settings
):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "keep.py").write_text("print('keep')\n", encoding="utf-8")
    (tmp_path / "src" / "drop.py").write_text("print('drop')\n", encoding="utf-8")
    (tmp_path / ".metisignore").write_text("*\n!src/\n!src/keep.py\n", encoding="utf-8")

    engine = _build_engine(tmp_path, dummy_backend, dummy_llm, capability_settings)

    files = sorted(
        Path(path).relative_to(tmp_path).as_posix()
        for path in engine.repository.get_code_files()
    )
    assert files == ["src/keep.py"]


def test_direct_code_file_selection_respects_metisignore(
    tmp_path, dummy_backend, dummy_llm, capability_settings
):
    (tmp_path / "keep.py").write_text("print('keep')\n", encoding="utf-8")
    (tmp_path / "drop.py").write_text("print('drop')\n", encoding="utf-8")
    (tmp_path / ".metisignore").write_text("drop.py\n", encoding="utf-8")
    engine = _build_engine(tmp_path, dummy_backend, dummy_llm, capability_settings)

    assert engine.repository.is_code_file_selected("keep.py") is True
    assert engine.repository.is_code_file_selected("drop.py") is False


def test_default_language_discovery_preserves_review_boundaries(
    tmp_path, dummy_backend, dummy_llm, capability_settings
):
    for name in ("keep.r", "excluded.r", "ignored.b", "README.md"):
        (tmp_path / name).touch()
    (tmp_path / ".metisignore").write_text(
        "ignored.b\n.metisignore\n", encoding="utf-8"
    )
    report = tmp_path / "review.json"
    with generated_artifact_publication(tmp_path, report):
        report.write_text('{"reviews": []}', encoding="utf-8")

    engine = _build_engine(
        tmp_path,
        dummy_backend,
        dummy_llm,
        capability_settings,
        review_code_exclude_paths=["excluded.r"],
    )
    try:
        assert {
            Path(path).name
            for path in engine.repository.get_code_files(include_suffixed_sources=True)
        } == {"keep.r"}
    finally:
        engine.close()


@pytest.mark.parametrize("root_path", ["missing", "file", "missing/..", "file/.."])
def test_engine_rejects_invalid_codebase_roots(
    tmp_path, dummy_backend, dummy_llm, capability_settings, root_path
):
    (tmp_path / "file").write_text("not a directory", encoding="utf-8")
    with pytest.raises(NotADirectoryError, match="Codebase path"):
        engine = _build_engine(
            tmp_path / root_path,
            dummy_backend,
            dummy_llm,
            capability_settings,
        )
        engine.close()


@pytest.mark.parametrize("entrypoint", ["api", "config"])
@pytest.mark.parametrize(
    "target",
    [
        "missing",
        "source.c",
        "missing/..",
        "source.c/..",
        "../outside",
        "escape",
        "empty",
        "alias",
        "parent_alias",
        "absolute_alias",
        "root_alias",
        "unreadable",
        "nested",
        "ignored_nested",
        "reincluded_nested",
    ],
)
def test_directory_review_validates_scope(
    tmp_path,
    dummy_backend,
    dummy_llm,
    capability_settings,
    monkeypatch,
    entrypoint,
    target,
):
    root = tmp_path / "repository"
    root.mkdir()
    (root / "source.c").write_text("int source;\n", encoding="utf-8")
    (root / "empty").mkdir()
    source_dir = root / "src"
    source_dir.mkdir()
    for name in ("keep.c", "ignored.c"):
        (source_dir / name).write_text("int source;\n", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.c").write_text("int secret;\n", encoding="utf-8")
    (root / "escape").symlink_to(outside, target_is_directory=True)
    (root / "alias").symlink_to(source_dir, target_is_directory=True)
    (root / ".metisignore").write_text(
        "alias/ignored.c\nsrc/ignored.c\n", encoding="utf-8"
    )
    requested_target = target
    if target == "parent_alias":
        nested = source_dir / "nested"
        nested.mkdir()
        (root / "parent_alias").symlink_to(nested, target_is_directory=True)
        requested_target = "parent_alias/.."
    elif target == "absolute_alias":
        alias = tmp_path / "absolute_alias"
        alias.symlink_to(source_dir, target_is_directory=True)
        requested_target = str(alias)
    elif target == "root_alias":
        requested_target = str(source_dir)
        alias = tmp_path / "checkout"
        alias.symlink_to(root, target_is_directory=True)
        root = alias
    blocked = None
    if target in {"unreadable", "nested", "ignored_nested", "reincluded_nested"}:
        blocked = root / target
        if target != "unreadable":
            blocked /= "unreadable"
        blocked.mkdir(parents=True)
        (blocked / "hidden.c").write_text("int hidden;\n", encoding="utf-8")
        if target in {"ignored_nested", "reincluded_nested"}:
            (blocked.parent / "keep.c").write_text("int keep;\n", encoding="utf-8")
            patterns = f"{target}/unreadable/\n"
            if target == "reincluded_nested":
                patterns += f"!{target}/unreadable/hidden.c\n"
            (root / ".metisignore").write_text(patterns, encoding="utf-8")
    engine = _build_engine(
        root,
        dummy_backend,
        dummy_llm,
        capability_settings,
        review_code_include_paths=["alias/"] if target == "alias" else [],
        execution_config={
            "inputs": {"review_request": {"mode": "dir", "target": requested_target}},
            "stages": {
                "review": {
                    "nodes": {
                        "simple_llm_review": {},
                        "finding_dedup": {},
                        "result": {"formats": ["sarif"]},
                    }
                }
            },
        },
    )
    graph = engine._get_review_graph()

    def review(request, **kwargs):
        result = {
            "file": request["relative_file"],
            "file_path": request["file_path"],
            "reviews": [{"issue": "Check source"}],
        }
        kwargs.get("emit", lambda _value: None)(result)
        return result

    graph.review = Mock(side_effect=review)
    walk = Mock(wraps=os.walk)
    monkeypatch.setattr("metis.engine.repository.os.walk", walk)
    try:
        if blocked is not None:
            blocked.chmod(0)
            try:
                list(blocked.iterdir())
            except PermissionError:
                pass
            else:
                pytest.skip("Directory permissions do not restrict this user")
        if target not in {
            "empty",
            "alias",
            "parent_alias",
            "absolute_alias",
            "root_alias",
            "ignored_nested",
        }:
            with pytest.raises(ExecutionGraphError) as error:
                if entrypoint == "api":
                    engine.execute_review("dir", target=requested_target)
                else:
                    engine.execute_graph()
            if blocked is not None:
                message = "Permission denied"
                walk.assert_called_once()
            else:
                message = (
                    "Path escapes codebase"
                    if target in {"../outside", "escape"}
                    else "Path parent is not a directory"
                    if target in {"missing/..", "source.c/.."}
                    else "Review directory not found"
                )
                walk.assert_not_called()
            assert any(
                message in item.message for item in error.value.result.diagnostics
            )
            graph.review.assert_not_called()
        else:
            outputs = (
                engine.execute_review("dir", target=requested_target)
                if entrypoint == "api"
                else engine.execute_graph().outputs["review"]
            )
            if target == "empty":
                assert outputs["findings"] == {"reviews": []}
                graph.review.assert_not_called()
            else:
                relative_file = "alias/keep.c" if target == "alias" else "src/keep.c"
                if target == "ignored_nested":
                    relative_file = "ignored_nested/keep.c"
                assert outputs["findings"]["reviews"][0]["file"] == relative_file
                graph.review.assert_called_once()
                request = graph.review.call_args.args[0]
                assert request["file_path"] == str(root / relative_file)
        dummy_llm.get_chat_model.assert_not_called()
    finally:
        if blocked is not None:
            blocked.chmod(0o700)
        engine.close()


def test_concurrent_review_selection_reuses_compiled_scopes(
    tmp_path, dummy_backend, dummy_llm, capability_settings, monkeypatch
):
    names = [f"selected-{index}.py" for index in range(16)]
    for name in [*names, "omitted.py"]:
        (tmp_path / name).touch()
    (tmp_path / ".metisignore").write_text("/omitted.py\n", encoding="utf-8")
    includes = [f"/selected-{index}.py" for index in range(1024)]
    engine = _build_engine(
        tmp_path,
        dummy_backend,
        dummy_llm,
        capability_settings,
        review_code_include_paths=includes,
        review_code_exclude_paths=["/never.py"],
    )
    compiled = []
    from_lines = pathspec.GitIgnoreSpec.from_lines

    def compile_spec(lines, **kwargs):
        patterns = tuple(lines)
        compiled.append(patterns)
        assert kwargs == {"backend": "simple"}
        return from_lines(patterns, **kwargs)

    monkeypatch.setattr(pathspec.GitIgnoreSpec, "from_lines", compile_spec)
    with ThreadPoolExecutor(max_workers=4) as pool:
        inventories = list(
            pool.map(lambda _: engine.repository.get_code_files(), range(8))
        )

    expected = sorted(str(tmp_path / name) for name in names)
    assert all(sorted(files) == expected for files in inventories)
    assert compiled == [("/omitted.py\n",), tuple(includes), ("/never.py",)]
    assert engine.repository.is_code_file_selected(names[0])
    assert len(compiled) == 3


def test_review_scope_cache_observes_ordered_pattern_changes(
    tmp_path, dummy_backend, dummy_llm, capability_settings
):
    names = {"first.py", "second.py", "third.py"}
    for name in names:
        (tmp_path / name).touch()
    engine = _build_engine(
        tmp_path,
        dummy_backend,
        dummy_llm,
        capability_settings,
        review_code_include_paths=["*.py", "!second.py"],
        review_code_exclude_paths=["third.py"],
    )

    def selected():
        return {Path(path).name for path in engine.repository.get_code_files()}

    assert selected() == {"first.py"}
    engine._config.review_code_include_paths.append("second.py")
    assert selected() == {"first.py", "second.py"}
    engine._config.review_code_exclude_paths[:] = ["*.py", "!second.py"]
    assert selected() == {"second.py"}
    engine._config.review_code_include_paths = ["first.py"]
    assert selected() == set()
    engine._config.review_code_exclude_paths = []
    assert selected() == {"first.py"}
    engine._config.review_code_include_paths = []
    assert selected() == names
    engine._config.review_code_include_paths = ["# comment"]
    assert selected() == set()


@pytest.mark.parametrize(
    "name",
    [
        "unicode-文.py",
        pytest.param(
            "undecodable-\udcff.py",
            marks=pytest.mark.skipif(os.name == "nt", reason="POSIX byte filename"),
        ),
    ],
)
def test_review_scope_preserves_unicode_and_literal_matching(
    tmp_path, dummy_backend, dummy_llm, capability_settings, name
):
    try:
        (tmp_path / name).touch()
    except OSError as exc:
        if exc.errno in {errno.EILSEQ, errno.EPERM} and "\udcff" in name:
            pytest.skip("Filesystem or sandbox rejects undecodable byte filenames")
        raise
    for filename in ("bracket[one].py", "bracketo.py", "ignored.py"):
        (tmp_path / filename).touch()
    (tmp_path / ".metisignore").write_text("/ignored.py\n", encoding="utf-8")
    engine = _build_engine(
        tmp_path,
        dummy_backend,
        dummy_llm,
        capability_settings,
        review_code_include_paths=["*.py"],
        review_code_exclude_paths=[
            "*.py",
            "!unicode-*.py",
            "!undecodable-*.py",
            r"!bracket\[one\].py",
            "!ignored.py",
        ],
    )

    assert {Path(path).name for path in engine.repository.get_code_files()} == {
        name,
        "bracket[one].py",
    }


def test_perl_files_follow_repository_review_selection_rules(
    tmp_path, dummy_backend, dummy_llm, capability_settings
):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "keep.pl").write_text("print qq(keep\\n);\n", encoding="utf-8")
    (tmp_path / "src" / "app.psgi").write_text(
        "sub { [200, [], ['ok']] };\n", encoding="utf-8"
    )
    (tmp_path / "src" / "ignored.pm").write_text("package Ignored;\n", encoding="utf-8")
    (tmp_path / "src" / "excluded.t").write_text("use Test::More;\n", encoding="utf-8")
    (tmp_path / "src" / "legacy.cgi").write_text(
        "print qq(legacy);\n", encoding="utf-8"
    )
    (tmp_path / "outside.pm").write_text("package Outside;\n", encoding="utf-8")
    (tmp_path / ".metisignore").write_text("src/ignored.pm\n", encoding="utf-8")

    engine = _build_engine(
        tmp_path,
        dummy_backend,
        dummy_llm,
        capability_settings,
        review_code_include_paths=["src/"],
        review_code_exclude_paths=["src/excluded.t"],
    )

    files = sorted(
        Path(path).relative_to(tmp_path).as_posix()
        for path in engine.repository.get_code_files(include_suffixed_sources=True)
    )

    assert files == ["src/app.psgi", "src/keep.pl", "src/legacy.cgi"]


def test_concurrent_metisignore_load_waits_for_initialized_spec(
    tmp_path,
    dummy_backend,
    dummy_llm,
    capability_settings,
    monkeypatch,
):
    metisignore = tmp_path / ".metisignore"
    metisignore.write_text("drop.py\n", encoding="utf-8")
    engine = _build_engine(tmp_path, dummy_backend, dummy_llm, capability_settings)
    real_open = open
    opened = threading.Event()
    release = threading.Event()
    second_finished = threading.Event()
    results = []

    def slow_open(path, *args, **kwargs):
        if Path(path) == metisignore:
            opened.set()
            release.wait(timeout=2)
        return real_open(path, *args, **kwargs)

    def load_first() -> None:
        results.append(engine.repository.load_metisignore())

    def load_second() -> None:
        results.append(engine.repository.load_metisignore())
        second_finished.set()

    monkeypatch.setattr("builtins.open", slow_open)
    first = threading.Thread(target=load_first)
    second = threading.Thread(target=load_second)
    first.start()
    assert opened.wait(timeout=1)
    second.start()
    assert not second_finished.wait(timeout=0.05)
    release.set()
    first.join(timeout=1)
    second.join(timeout=1)

    assert len(results) == 2
    assert all(spec is not None for spec in results)


def test_count_index_items_respects_metisignore_allowlist(
    tmp_path, dummy_backend, dummy_llm, capability_settings
):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "keep.py").write_text("print('keep')\n", encoding="utf-8")
    (tmp_path / "src" / "drop.py").write_text("print('drop')\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("# keep\n", encoding="utf-8")
    (tmp_path / "notes.md").write_text("# drop\n", encoding="utf-8")
    (tmp_path / ".metisignore").write_text(
        "*\n!src/\n!src/keep.py\n!README.md\n", encoding="utf-8"
    )

    engine = _build_engine(tmp_path, dummy_backend, dummy_llm, capability_settings)

    assert engine.indexing.count_index_items() == 2


def test_index_prepare_nodes_respects_nested_metisignore_allowlist(
    tmp_path,
    dummy_backend,
    dummy_llm,
    monkeypatch,
    capability_settings,
):
    (tmp_path / ".metisignore").write_text(
        "*\n!src/\n!src/keep.py\n!README.md\n", encoding="utf-8"
    )

    engine = _build_engine(tmp_path, dummy_backend, dummy_llm, capability_settings)

    for name in ("src/keep.py", "src/drop.py", "README.md", "notes.md"):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("inert text\n", encoding="utf-8")

    captured = {}

    def _fake_prepare_nodes_iter(code_docs, doc_docs, *_args):
        captured["code_ids"] = [doc.id_ for doc in code_docs]
        captured["doc_ids"] = [doc.id_ for doc in doc_docs]
        if False:
            yield None
        return (["code-node"], ["doc-node"])

    monkeypatch.setattr(
        indexing_service_mod, "prepare_nodes_iter", _fake_prepare_nodes_iter
    )

    engine.indexing.index_prepare_nodes()

    assert captured == {
        "code_ids": [f"{tmp_path.name}/src/keep.py"],
        "doc_ids": [f"{tmp_path.name}/README.md"],
    }
    assert engine._state.pending_nodes == (["code-node"], ["doc-node"])


def test_review_patch_respects_metisignore_allowlist(
    tmp_path, dummy_backend, dummy_llm, monkeypatch, capability_settings
):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "keep.py").write_text("print('keep')\n", encoding="utf-8")
    (tmp_path / "src" / "drop.py").write_text("print('drop')\n", encoding="utf-8")
    (tmp_path / ".metisignore").write_text("*\n!src/\n!src/keep.py\n", encoding="utf-8")

    patch = """--- a/src/keep.py
+++ b/src/keep.py
@@ -1 +1,2 @@
 print('keep')
+print('still-keep')
--- a/src/drop.py
+++ b/src/drop.py
@@ -1 +1,2 @@
 print('drop')
+print('should-not-review')
"""
    patch_file = tmp_path / "change.diff"
    patch_file.write_text(patch, encoding="utf-8")

    engine = _build_engine(tmp_path, dummy_backend, dummy_llm, capability_settings)
    reviewed = []

    class _DummyReviewGraph:
        def review(self, req, *, collect_navigation_evidence=False):
            reviewed.append(req["relative_file"])
            return {
                "file": req["relative_file"],
                "reviews": [{"issue": f"issue in {req['relative_file']}"}],
            }

    import metis.engine.nodes.simple_llm_review.service as review_service_mod

    monkeypatch.setattr(
        engine,
        "_get_review_graph",
        lambda _index=None, _model=None: _DummyReviewGraph(),
    )
    monkeypatch.setattr(
        review_service_mod, "summarize_changes", lambda *args, **kwargs: "summary"
    )

    service = SimpleLlmReviewService(
        engine._config,
        engine.repository,
        lambda index, model: engine._get_review_graph(index, model),
    )
    result = service.review_patch(str(patch_file))

    assert reviewed == ["src/keep.py"]
    assert [review["file"] for review in result["reviews"]] == ["src/keep.py"]
    assert result["overall_changes"] == "summary"

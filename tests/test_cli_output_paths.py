# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from pathlib import Path

import pytest

from metis.cli.utils import output_files_for_formats
from metis.cli.utils import save_output
from metis.generated_artifacts import generated_artifact_paths


@pytest.mark.parametrize("format_name", ["html", "csv"])
@pytest.mark.parametrize("source_kind", ["json", "sarif"])
@pytest.mark.parametrize("invalid", [False, True])
def test_file_backed_exports_register_only_successful_replacements(
    tmp_path, format_name, source_kind, invalid
):
    source = tmp_path / f"input.{source_kind}"
    payload = (
        '{"reviews":[]}' if source_kind == "json" else '{"version":"2.1.0","runs":[]}'
    )
    source.write_text("invalid" if invalid else payload)
    target = tmp_path / f"report.{format_name}"
    target.write_text("previous report")
    options = {f"{source_kind}_path": source, "codebase_path": tmp_path, "quiet": True}
    if invalid:
        with pytest.raises(ValueError):
            save_output(target, None, **options)
        assert target.read_text() == "previous report"
        assert generated_artifact_paths(tmp_path) == frozenset()
    else:
        save_output(target, None, **options)
        assert target.read_text() != "previous report"
        assert generated_artifact_paths(tmp_path) == frozenset({target.resolve()})


def test_companion_outputs_preserve_dotted_basename(tmp_path: Path):
    unrelated = tmp_path / "report.sarif"
    unrelated.write_text("previous report", encoding="utf-8")
    formats = ("json", "sarif", "html", "csv")

    paths = output_files_for_formats(
        [str(tmp_path / "report.v1.json")], formats, command="review"
    )
    save_output(paths, {"reviews": []}, quiet=True)

    assert paths == [
        str(tmp_path / f"report.v1.{format_name}") for format_name in formats
    ]
    assert all(Path(path).is_file() for path in paths)
    assert unrelated.read_text(encoding="utf-8") == "previous report"


def test_html_output_preserves_explicit_suffix_case(tmp_path: Path):
    output = tmp_path / "report.HtMl"

    save_output(output, {"reviews": []}, quiet=True)

    assert {path.name for path in tmp_path.iterdir()} == {output.name}
    assert "<!DOCTYPE html>" in output.read_text(encoding="utf-8")


@pytest.mark.parametrize("names", [("Report", "report"), ("café", "cafe\u0301")])
def test_filesystem_aliases_cannot_overwrite_another_stage(tmp_path, names):
    from metis.cli.output import save_graph_outputs

    (tmp_path / names[0]).touch()
    if not (tmp_path / names[1]).exists():
        pytest.skip("filesystem preserves these distinct spellings")
    outputs = {
        name: {
            "formats": ["sarif"],
            "sarif": {"version": "2.1.0", "runs": []},
            "filename": str(tmp_path / filename),
        }
        for name, filename in [("review", names[0]), ("triage", names[1])]
    }
    with pytest.raises(ValueError, match="distinct"):
        save_graph_outputs(None, outputs, True)
    assert not list(tmp_path.glob("*.sarif"))


@pytest.mark.parametrize("names", [("Report", "report"), ("café", "cafe\u0301")])
def test_explicit_output_aliases_follow_filesystem_rules(tmp_path, names):
    (tmp_path / names[0]).touch()
    paths = [str(tmp_path / f"{name}.json") for name in names]
    if (tmp_path / names[1]).exists():
        with pytest.raises(ValueError, match="unique"):
            output_files_for_formats(paths, ("json",), command="review")
    else:
        assert output_files_for_formats(paths, ("json",), command="review") == paths

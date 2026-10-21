# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pathlib import Path
import re
from typing import Any

from metis.engine.stages.triage.models import TriageDecisionModel
from metis.utils import resolve_path_within_root
from metis.utils import source_lines


class SourceEvidence:
    def __init__(self, root: str | Path | None, observations: list[dict[str, Any]]):
        self.root = Path(root).resolve() if root is not None else None
        self.observed: dict[Path, dict[int, tuple[str, bool]]] = {}
        self.errors: list[str] = []
        for observation in observations:
            self.observe(
                observation["tool"], observation["arguments"], observation["output"]
            )
        self.initial = {path: dict(lines) for path, lines in self.observed.items()}

    def reset_tools(self) -> None:
        self.observed = {path: dict(lines) for path, lines in self.initial.items()}

    def observe(self, name: str, arguments: dict[str, Any], output: str) -> None:
        if self.root is None or name not in {"sed", "cat", "grep"}:
            return
        for row in source_lines(output):
            if name == "grep":
                match = re.fullmatch(r"(.+?):([1-9][0-9]*):(.*)", row)
                if match is None:
                    continue
                path, number, content = match.groups()
            else:
                match = re.fullmatch(r"\s*([1-9][0-9]*): (.*)", row)
                if match is None:
                    continue
                number, content = match.groups()
                path = arguments.get("path")
                if not isinstance(path, str):
                    continue
            try:
                line = int(number)
                if name == "sed" and not (
                    int(arguments["start_line"]) <= line <= int(arguments["end_line"])
                ):
                    continue
                resolved = resolve_path_within_root(self.root, path)
            except (KeyError, OSError, RuntimeError, TypeError, ValueError):
                continue
            observed = self.observed.setdefault(resolved, {})
            trims_whitespace = name == "grep"
            if trims_whitespace:
                content = content.rstrip()
            if line not in observed or len(content) >= len(observed[line][0]):
                observed[line] = (content, trims_whitespace)

    def validate(self, decision: TriageDecisionModel) -> list[str]:
        errors: list[str] = []
        if decision.status in {"valid", "invalid"}:
            if not decision.evidence:
                errors.append("MISSING_EVIDENCE")
            if not decision.resolution_chain:
                errors.append("MISSING_RESOLUTION_CHAIN")
        requested: dict[Path, dict[str, range]] = {}
        for citation in decision.evidence:
            path, separator, location = citation.rpartition(":")
            match = re.fullmatch(r"([1-9][0-9]*)(?:-([1-9][0-9]*))?", location)
            if not separator or not path or match is None:
                errors.append(f"INVALID_CITATION:{citation}")
                continue
            try:
                if self.root is None:
                    raise ValueError("No codebase root")
                resolved = resolve_path_within_root(self.root, path)
                first = int(match[1])
                last = int(match[2] or match[1])
            except (OSError, RuntimeError, ValueError):
                errors.append(f"INVALID_CITATION:{citation}")
                continue
            observed = self.observed.get(resolved, {})
            if (
                last < first
                or last - first + 1 > len(observed)
                or any(line not in observed for line in range(first, last + 1))
            ):
                errors.append(f"UNOBSERVED_CITATION:{citation}")
                continue
            requested.setdefault(resolved, {})[citation] = range(first, last + 1)
        for path, citations in requested.items():
            needed = {line for lines in citations.values() for line in lines}
            final_line = max(needed)
            matched: set[int] = set()
            try:
                with path.open(encoding="utf-8", errors="ignore") as source:
                    for line, content in enumerate(source, start=1):
                        if line in needed:
                            expected, trims_whitespace = self.observed[path][line]
                            actual = content.removesuffix("\n")
                            if trims_whitespace:
                                actual = actual.rstrip()
                            if actual == expected:
                                matched.add(line)
                        if line >= final_line:
                            break
            except OSError:
                errors.extend(
                    f"SOURCE_UNAVAILABLE:{citation}" for citation in citations
                )
                continue
            for citation, lines in citations.items():
                if any(line not in matched for line in lines):
                    errors.append(f"SOURCE_CHANGED:{citation}")
        self.errors = errors
        return errors

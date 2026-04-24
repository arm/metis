# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Any
import logging

from metis.engine.analysis.c_family_helpers import parse_includes_from_text
from metis.engine.analysis.review_obligations import build_unit_obligations
from metis.engine.analysis.review_risk import score_unit_risk, should_review_with_llm
from metis.engine.analysis.static_selectors import inventory_summary
from metis.engine.analysis.static_xref import expand_unit_xref

logger = logging.getLogger("metis")

INVENTORY_SCHEMA_VERSION = 2

FUNCTION_NODE_TYPES = {"function_definition", "method_definition"}
TYPE_NODE_TYPES = {
    "class_specifier",
    "class_declaration",
    "struct_specifier",
    "enum_specifier",
}
CALL_NODE_TYPES = {"call_expression"}
IDENTIFIER_NODE_TYPES = {
    "identifier",
    "field_identifier",
    "type_identifier",
    "namespace_identifier",
}
REFERENCE_SKIP_TYPES = {"comment", "string_literal", "raw_string_literal"}
MACRO_DEF_RE = re.compile(r"^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)", re.M)
MACRO_USE_RE = re.compile(r"\b[A-Z_][A-Z0-9_]{2,}\b")


@dataclass
class StaticUnit:
    unit_id: str
    file_path: str
    kind: str
    name: str
    start_line: int
    end_line: int
    signature: str = ""
    calls: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    risk_signals: list[str] = field(default_factory=list)
    analysis: dict[str, Any] = field(default_factory=dict)


@dataclass
class StaticFile:
    file_path: str
    language: str
    sha256: str
    parse_status: str
    units: list[str] = field(default_factory=list)
    includes: list[str] = field(default_factory=list)
    macro_definitions: list[str] = field(default_factory=list)
    macro_uses: list[str] = field(default_factory=list)
    error: str = ""


@dataclass
class StaticInventory:
    version: int
    generated_at: str
    codebase_path: str
    files: dict[str, StaticFile] = field(default_factory=dict)
    units: dict[str, StaticUnit] = field(default_factory=dict)
    symbols: dict[str, dict[str, list[str]]] = field(default_factory=dict)
    call_edges: list[dict[str, Any]] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "generated_at": self.generated_at,
            "codebase_path": self.codebase_path,
            "files": {key: asdict(value) for key, value in self.files.items()},
            "units": {key: asdict(value) for key, value in self.units.items()},
            "symbols": self.symbols,
            "call_edges": self.call_edges,
            "summary": self.summary,
        }


def default_inventory_path(codebase_path: str | Path) -> Path:
    return Path(codebase_path) / ".metis" / "static_inventory.json"


def write_inventory(inventory: StaticInventory, output_path: str | Path) -> Path:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(inventory.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path


def build_static_inventory(repository, *, output_path: str | Path | None = None):
    codebase_path = Path(repository._config.codebase_path).resolve()
    logger.debug("Building static inventory for codebase: %s", codebase_path)
    inventory = StaticInventory(
        version=INVENTORY_SCHEMA_VERSION,
        generated_at=datetime.now(timezone.utc).isoformat(),
        codebase_path=str(codebase_path),
    )

    code_files = sorted(repository.get_code_files())
    logger.debug("Static inventory discovered %d code file(s)", len(code_files))
    if not code_files:
        logger.warning(
            "Static inventory found no code files under %s. Check --codebase-path, supported extensions, and .metisignore.",
            codebase_path,
        )

    for full_path in code_files:
        file_path = Path(full_path)
        try:
            rel_path = file_path.resolve().relative_to(codebase_path).as_posix()
        except ValueError:
            rel_path = file_path.as_posix()
        ext = file_path.suffix.lower()
        plugin = repository.get_plugin_for_extension(ext)
        language = plugin.get_name() if plugin else ""
        text = file_path.read_text(encoding="utf-8", errors="ignore")
        file_record = _analyze_file(rel_path=rel_path, language=language, text=text)
        inventory.files[rel_path] = file_record
        units = _extract_units(rel_path=rel_path, language=language, text=text)
        for unit in units:
            inventory.units[unit.unit_id] = unit
            file_record.units.append(unit.unit_id)
            _add_symbol_definition(inventory, unit.name, unit.unit_id)
            for reference in unit.references:
                _add_symbol_reference(inventory, reference, unit.unit_id)
            for callee in unit.calls:
                inventory.call_edges.append(
                    {
                        "caller": unit.unit_id,
                        "caller_file_path": unit.file_path,
                        "callee_symbol": callee,
                        "line": unit.start_line,
                        "kind": "direct",
                    }
                )

    _resolve_call_edges(inventory)
    _attach_unit_analysis(inventory)
    inventory.summary = inventory_summary(inventory)

    path = write_inventory(
        inventory, output_path or default_inventory_path(codebase_path)
    )
    logger.debug(
        "Static inventory summary: files=%d units=%d high=%d medium=%d llm_candidates=%d unknown_obligations=%d",
        inventory.summary["files"],
        inventory.summary["units"],
        inventory.summary["high_risk_units"],
        inventory.summary["medium_risk_units"],
        inventory.summary["llm_candidate_units"],
        inventory.summary["unknown_obligations"],
    )
    return inventory, path


def _attach_unit_analysis(inventory: StaticInventory) -> None:
    for unit in inventory.units.values():
        xref = expand_unit_xref(inventory, unit.unit_id)
        risk = score_unit_risk(unit, xref)
        obligations = build_unit_obligations(unit, xref, risk)
        unit.analysis = {
            "risk": {
                "score": risk.score,
                "level": risk.level,
                "reasons": list(risk.reasons),
                "unresolved_calls": list(risk.unresolved_calls),
                "should_call_llm": should_review_with_llm(risk),
            },
            "xref": {
                "caller_count": len(xref.callers),
                "callee_count": len(xref.callees),
                "unresolved_calls": list(xref.unresolved_calls),
            },
            "obligations": [
                {
                    "name": obligation.name,
                    "status": obligation.status,
                    "evidence": list(obligation.evidence),
                    "unresolved_hops": list(obligation.unresolved_hops),
                    "needed_context": list(obligation.needed_context),
                }
                for obligation in obligations
            ],
        }


def _resolve_call_edges(inventory: StaticInventory) -> None:
    for edge in inventory.call_edges:
        caller_id = str(edge.get("caller") or "")
        caller_unit = inventory.units.get(caller_id)
        callee_symbol = str(edge.get("callee_symbol") or "")
        resolved_units, resolution_scope = _resolve_call_targets(
            inventory,
            caller_unit=caller_unit,
            callee_symbol=callee_symbol,
        )
        edge["resolved_units"] = resolved_units
        edge["resolution_scope"] = resolution_scope


def _resolve_call_targets(
    inventory: StaticInventory,
    *,
    caller_unit: StaticUnit | None,
    callee_symbol: str,
) -> tuple[list[str], str]:
    if not callee_symbol:
        return [], "empty_symbol"

    defs = [
        unit_id
        for unit_id in (inventory.symbols.get(callee_symbol) or {}).get(
            "definitions", []
        )
        if getattr(inventory.units.get(unit_id), "kind", "") == "function"
    ]
    if not defs:
        return [], "unresolved"

    caller_file_path = getattr(caller_unit, "file_path", "")
    same_file_defs = [
        unit_id
        for unit_id in defs
        if getattr(inventory.units.get(unit_id), "file_path", "") == caller_file_path
    ]
    if len(same_file_defs) == 1:
        return same_file_defs, "same_file_unique"
    if len(same_file_defs) > 1:
        return [], "same_file_ambiguous"
    if len(defs) == 1:
        return defs, "global_unique"
    return [], "global_ambiguous"


def _analyze_file(*, rel_path: str, language: str, text: str) -> StaticFile:
    return StaticFile(
        file_path=rel_path,
        language=language,
        sha256=hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest(),
        parse_status="parsed",
        includes=parse_includes_from_text(text),
        macro_definitions=sorted(set(MACRO_DEF_RE.findall(text))),
        macro_uses=sorted(set(MACRO_USE_RE.findall(text))),
    )


def _extract_units(*, rel_path: str, language: str, text: str) -> list[StaticUnit]:
    parser = _get_parser(language)
    if parser is None:
        logger.debug(
            "Static inventory skipping AST extraction for %s: no parser for language=%s",
            rel_path,
            language or "<none>",
        )
        return []
    tree = parser.parse(bytes(text, "utf-8"))
    source = bytes(text, "utf-8")
    units: list[StaticUnit] = []
    _walk_units(tree.root_node, source, rel_path, units)
    return units


def _get_parser(language: str):
    if not language:
        return None
    try:
        from tree_sitter_language_pack import get_parser

        return get_parser(language)
    except Exception as exc:
        logger.debug(
            "Static inventory could not load Tree-sitter parser for %s: %s",
            language,
            exc,
        )
        return None


def _walk_units(node, source: bytes, rel_path: str, units: list[StaticUnit]) -> None:
    node_type = str(getattr(node, "type", "") or "")
    if node_type in FUNCTION_NODE_TYPES:
        unit = _unit_from_function(node, source, rel_path)
        if unit is not None:
            units.append(unit)
            return
    if node_type in TYPE_NODE_TYPES:
        unit = _unit_from_type(node, source, rel_path)
        if unit is not None:
            units.append(unit)
    for child in getattr(node, "children", []) or []:
        _walk_units(child, source, rel_path, units)


def _unit_from_function(node, source: bytes, rel_path: str) -> StaticUnit | None:
    name = _function_name(node, source)
    if not name:
        return None
    start = _node_line(node)
    end = _node_end_line(node)
    text = _node_text(node, source)
    return StaticUnit(
        unit_id=f"{rel_path}::{name}:{start}-{end}",
        file_path=rel_path,
        kind="function",
        name=name,
        start_line=start,
        end_line=end,
        signature=_signature(text),
        calls=_collect_calls(node, source),
        references=_collect_references(node, source),
        risk_signals=_risk_signals(text),
    )


def _unit_from_type(node, source: bytes, rel_path: str) -> StaticUnit | None:
    name = _first_identifier(node, source)
    if not name:
        return None
    start = _node_line(node)
    end = _node_end_line(node)
    return StaticUnit(
        unit_id=f"{rel_path}::{name}:{start}-{end}",
        file_path=rel_path,
        kind="type",
        name=name,
        start_line=start,
        end_line=end,
        signature=_signature(_node_text(node, source)),
        references=_collect_references(node, source),
    )


def _function_name(node, source: bytes) -> str:
    declarator = _child_by_field(node, "declarator")
    return _first_identifier(declarator or node, source)


def _collect_calls(node, source: bytes) -> list[str]:
    calls: list[str] = []

    def visit(current):
        if str(getattr(current, "type", "") or "") in CALL_NODE_TYPES:
            function_node = _child_by_field(current, "function") or current
            symbol = _first_identifier(function_node, source)
            if symbol and symbol not in calls:
                calls.append(symbol)
        for child in getattr(current, "children", []) or []:
            visit(child)

    visit(node)
    return calls


def _collect_references(node, source: bytes) -> list[str]:
    refs: list[str] = []

    def visit(current):
        node_type = str(getattr(current, "type", "") or "")
        if node_type in REFERENCE_SKIP_TYPES:
            return
        if node_type in IDENTIFIER_NODE_TYPES:
            symbol = _node_text(current, source).strip()
            if symbol and symbol not in refs:
                refs.append(symbol)
        for child in getattr(current, "children", []) or []:
            visit(child)

    visit(node)
    return refs[:80]


def _risk_signals(text: str) -> list[str]:
    lowered = text.lower()
    signals = []
    checks = {
        "copy_or_format": (
            "memcpy",
            "memmove",
            "strcpy",
            "strncpy",
            "sprintf",
            "snprintf",
        ),
        "allocation_or_free": ("malloc", "calloc", "realloc", "free", "new ", "delete"),
        "lock_or_concurrency": ("lock", "mutex", "atomic", "spinlock", "unlock"),
        "pointer_arithmetic": ("->", "*", "++", "--"),
        "array_index": ("[", "]"),
        "indirect_call": ("->", ")."),
        "parser_or_decoder": ("parse", "decode", "deserialize", "read", "recv"),
        "auth_or_policy": ("auth", "permission", "priv", "access", "policy"),
        "mmio_or_register": ("mmio", "regmap", "writel", "readl", "ioread", "iowrite"),
    }
    for name, terms in checks.items():
        if any(term in lowered for term in terms):
            signals.append(name)
    return signals


def _add_symbol_definition(
    inventory: StaticInventory, symbol: str, unit_id: str
) -> None:
    if not symbol:
        return
    entry = inventory.symbols.setdefault(symbol, {"definitions": [], "references": []})
    if unit_id not in entry["definitions"]:
        entry["definitions"].append(unit_id)


def _add_symbol_reference(
    inventory: StaticInventory, symbol: str, unit_id: str
) -> None:
    if not symbol:
        return
    entry = inventory.symbols.setdefault(symbol, {"definitions": [], "references": []})
    if unit_id not in entry["references"]:
        entry["references"].append(unit_id)


def _child_by_field(node, name: str):
    try:
        return node.child_by_field_name(name)
    except Exception:
        return None


def _first_identifier(node, source: bytes) -> str:
    if node is None:
        return ""
    node_type = str(getattr(node, "type", "") or "")
    if node_type in IDENTIFIER_NODE_TYPES:
        return _node_text(node, source).strip()
    for child in getattr(node, "children", []) or []:
        found = _first_identifier(child, source)
        if found:
            return found
    return ""


def _node_text(node, source: bytes) -> str:
    start = int(getattr(node, "start_byte", 0) or 0)
    end = int(getattr(node, "end_byte", 0) or 0)
    return source[start:end].decode("utf-8", errors="ignore")


def _node_line(node) -> int:
    return int(getattr(node, "start_point", (0, 0))[0]) + 1


def _node_end_line(node) -> int:
    end = getattr(node, "end_point", None)
    if isinstance(end, tuple) and end:
        return int(end[0]) + 1
    return _node_line(node)


def _signature(text: str) -> str:
    first = str(text or "").split("{", 1)[0].strip()
    return " ".join(first.split())[:240]

# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from .c_family_packet_context import (
    build_c_family_indirect_call_context,
    build_c_family_macro_expansion_context,
    build_c_family_type_context,
    c_family_neighbor_signal_score,
    is_c_family_file,
)
from .static_inventory import (
    INVENTORY_SCHEMA_VERSION,
    StaticInventory,
    default_inventory_path,
)
from .static_selectors import units_for_file

MAX_SELECTED_SOURCE_LINES = 80
MAX_NEIGHBOR_SOURCE_LINES = 30
MAX_CALLER_CONTEXTS = 1
MAX_CALLEE_CONTEXTS = 2
MAX_MACRO_CONTEXTS = 4
MAX_MACRO_EXPANSION_CONTEXTS = 4
MAX_TYPE_CONTEXTS = 3
MAX_INDIRECT_CONTEXTS = 3


def load_inventory_for_codebase(codebase_path: str | Path) -> dict[str, Any] | None:
    path = default_inventory_path(codebase_path)
    if not path.is_file():
        return None
    import json

    return json.loads(path.read_text(encoding="utf-8"))


def inventory_schema_supported(inventory: dict[str, Any] | StaticInventory) -> bool:
    version = (
        getattr(inventory, "version", None)
        if isinstance(inventory, StaticInventory)
        else inventory.get("version")
    )
    if version is None:
        return False
    try:
        return int(str(version)) >= INVENTORY_SCHEMA_VERSION
    except Exception:
        return False


def inventory_file_is_fresh(
    inventory: dict[str, Any] | StaticInventory,
    *,
    file_path: str,
    codebase_path: str | Path,
) -> bool:
    rel_path = _normalize_file_path(file_path, codebase_path)
    file_record = _inventory_file_record(inventory, rel_path)
    if not isinstance(file_record, dict):
        return False

    abs_path = Path(codebase_path).resolve() / rel_path
    if not abs_path.is_file():
        return False

    expected_sha = str(file_record.get("sha256") or "")
    if not expected_sha:
        return False

    current_sha = hashlib.sha256(
        abs_path.read_text(encoding="utf-8", errors="ignore").encode(
            "utf-8", errors="ignore"
        )
    ).hexdigest()
    return current_sha == expected_sha


def build_review_packets_from_inventory(
    inventory: dict[str, Any] | StaticInventory,
    *,
    file_path: str,
    codebase_path: str | Path,
    max_packets: int = 20,
) -> list[str]:
    units = _units_for_file(inventory, file_path=file_path, codebase_path=codebase_path)
    selected = [unit for unit in units if _should_include_unit(unit)]
    selected.sort(
        key=lambda unit: (
            -int(_risk(unit).get("score") or 0),
            int(_unit_get(unit, "start_line", 0) or 0),
        )
    )
    return [
        _format_packet(unit, inventory=inventory, codebase_path=codebase_path)
        for unit in selected[:max_packets]
    ]


def _units_for_file(
    inventory: dict[str, Any] | StaticInventory,
    *,
    file_path: str,
    codebase_path: str | Path,
) -> list[Any]:
    rel_path = _normalize_file_path(file_path, codebase_path)
    if isinstance(inventory, StaticInventory):
        return units_for_file(inventory, rel_path)
    raw_units = inventory.get("units") or {}
    if not isinstance(raw_units, dict):
        return []
    return [
        unit
        for unit in raw_units.values()
        if isinstance(unit, dict) and unit.get("file_path") == rel_path
    ]


def _normalize_file_path(file_path: str, codebase_path: str | Path) -> str:
    path = Path(file_path)
    base = Path(codebase_path).resolve()
    try:
        return path.resolve().relative_to(base).as_posix()
    except Exception:
        return path.as_posix()


def _should_include_unit(unit: Any) -> bool:
    risk = _risk(unit)
    if bool(risk.get("should_call_llm", False)):
        return True
    return any(
        obligation.get("status") == "unknown" for obligation in _obligations(unit)
    )


def _format_packet(
    unit: Any,
    *,
    inventory: dict[str, Any] | StaticInventory,
    codebase_path: str | Path,
) -> str:
    risk = _risk(unit)
    obligations = _obligations(unit)
    lines = [
        "STATIC_REVIEW_PACKET",
        f"UNIT: {_unit_get(unit, 'unit_id', '')}",
        f"FILE: {_unit_get(unit, 'file_path', '')}",
        f"KIND: {_unit_get(unit, 'kind', '')}",
        f"NAME: {_unit_get(unit, 'name', '')}",
        f"LINES: {_unit_get(unit, 'start_line', '')}-{_unit_get(unit, 'end_line', '')}",
        f"SIGNATURE: {_unit_get(unit, 'signature', '')}",
        "",
        "RISK:",
        f"- score: {risk.get('score', 0)}",
        f"- level: {risk.get('level', 'none')}",
        f"- should_call_llm: {bool(risk.get('should_call_llm', False))}",
    ]
    for reason in risk.get("reasons") or []:
        lines.append(f"- reason: {reason}")

    xref = _analysis(unit).get("xref") or {}
    lines.extend(
        [
            "",
            "XREF:",
            f"- caller_count: {xref.get('caller_count', 0)}",
            f"- callee_count: {xref.get('callee_count', 0)}",
        ]
    )
    for call in xref.get("unresolved_calls") or []:
        lines.append(f"- unresolved_call: {call}")

    lines.extend(["", "OBLIGATIONS:"])
    for obligation in obligations:
        lines.append(
            f"- {obligation.get('name', '')}: {obligation.get('status', 'unknown')}"
        )
        for item in obligation.get("needed_context") or []:
            lines.append(f"  needed: {item}")
        for item in obligation.get("unresolved_hops") or []:
            lines.append(f"  unresolved: {item}")
        for item in obligation.get("evidence") or []:
            lines.append(f"  evidence: {item}")

    calls = _unit_get(unit, "calls", []) or []
    if calls:
        lines.extend(["", "CALLS:"])
        lines.extend(f"- {call}" for call in calls[:20])

    references = _unit_get(unit, "references", []) or []
    if references:
        lines.extend(["", "REFERENCES:"])
        lines.extend(f"- {ref}" for ref in references[:30])

    source_text = _excerpt_for_unit(
        unit,
        codebase_path=codebase_path,
        max_lines=MAX_SELECTED_SOURCE_LINES,
    )
    if source_text:
        lines.extend(["", "SOURCE:"])
        lines.extend(_indent_block(source_text))

    caller_context = _neighbor_context_blocks(
        inventory,
        unit,
        codebase_path=codebase_path,
        relation="caller",
        limit=MAX_CALLER_CONTEXTS,
    )
    if caller_context:
        lines.extend(["", "CALLER_CONTEXT:"])
        lines.extend(caller_context)

    callee_context = _neighbor_context_blocks(
        inventory,
        unit,
        codebase_path=codebase_path,
        relation="callee",
        limit=MAX_CALLEE_CONTEXTS,
    )
    if callee_context:
        lines.extend(["", "CALLEE_CONTEXT:"])
        lines.extend(callee_context)

    macro_context = _macro_context_blocks(
        inventory,
        unit,
        codebase_path=codebase_path,
        limit=MAX_MACRO_CONTEXTS,
    )
    if macro_context:
        lines.extend(["", "MACRO_CONTEXT:"])
        lines.extend(macro_context)

    macro_expansion_context = _macro_expansion_context_blocks(
        unit,
        codebase_path=codebase_path,
        limit=MAX_MACRO_EXPANSION_CONTEXTS,
    )
    if macro_expansion_context:
        lines.extend(["", "MACRO_EXPANSION_CONTEXT:"])
        lines.extend(macro_expansion_context)

    type_context = _type_context_blocks(
        unit,
        codebase_path=codebase_path,
        limit=MAX_TYPE_CONTEXTS,
    )
    if type_context:
        lines.extend(["", "TYPE_CONTEXT:"])
        lines.extend(type_context)

    indirect_context = _indirect_call_context_blocks(
        inventory,
        unit,
        codebase_path=codebase_path,
        limit=MAX_INDIRECT_CONTEXTS,
    )
    if indirect_context:
        lines.extend(["", "INDIRECT_CALL_CONTEXT:"])
        lines.extend(indirect_context)

    return "\n".join(str(line) for line in lines).strip()


def _unit_get(unit: Any, key: str, default: Any = None) -> Any:
    if isinstance(unit, dict):
        return unit.get(key, default)
    return getattr(unit, key, default)


def _analysis(unit: Any) -> dict[str, Any]:
    value = _unit_get(unit, "analysis", {}) or {}
    return value if isinstance(value, dict) else {}


def _risk(unit: Any) -> dict[str, Any]:
    value = _analysis(unit).get("risk") or {}
    return value if isinstance(value, dict) else {}


def _obligations(unit: Any) -> list[dict[str, Any]]:
    value = _analysis(unit).get("obligations") or []
    return value if isinstance(value, list) else []


def _inventory_unit_map(inventory: dict[str, Any] | StaticInventory) -> dict[str, Any]:
    if isinstance(inventory, StaticInventory):
        return inventory.units
    value = inventory.get("units") or {}
    return value if isinstance(value, dict) else {}


def _inventory_file_map(inventory: dict[str, Any] | StaticInventory) -> dict[str, Any]:
    if isinstance(inventory, StaticInventory):
        return {key: dict(value.__dict__) for key, value in inventory.files.items()}
    value = inventory.get("files") or {}
    return value if isinstance(value, dict) else {}


def _inventory_file_record(
    inventory: dict[str, Any] | StaticInventory,
    file_path: str,
) -> dict[str, Any] | None:
    record = _inventory_file_map(inventory).get(file_path)
    if record is None:
        return None
    if isinstance(record, dict):
        return record
    return getattr(record, "__dict__", None)


def _inventory_call_edges(
    inventory: dict[str, Any] | StaticInventory,
) -> list[dict[str, Any]]:
    if isinstance(inventory, StaticInventory):
        return inventory.call_edges
    value = inventory.get("call_edges") or []
    return value if isinstance(value, list) else []


def _neighbor_context_blocks(
    inventory: dict[str, Any] | StaticInventory,
    unit: Any,
    *,
    codebase_path: str | Path,
    relation: str,
    limit: int,
) -> list[str]:
    blocks: list[str] = []
    raw_neighbors = (
        _caller_units(inventory, unit)
        if relation == "caller"
        else _callee_units(inventory, unit)
    )
    neighbors = _rank_neighbor_units(
        unit,
        raw_neighbors,
        relation=relation,
        codebase_path=codebase_path,
    )
    for neighbor in neighbors[:limit]:
        excerpt = _excerpt_for_unit(
            neighbor,
            codebase_path=codebase_path,
            max_lines=MAX_NEIGHBOR_SOURCE_LINES,
        )
        if not excerpt:
            continue
        label = "caller" if relation == "caller" else "callee"
        blocks.append(
            f"- {label}: {_unit_get(neighbor, 'name', '')} "
            f"({_unit_get(neighbor, 'file_path', '')}:"
            f"{_unit_get(neighbor, 'start_line', '')}-{_unit_get(neighbor, 'end_line', '')})"
        )
        blocks.append("  SOURCE:")
        blocks.extend(_indent_block(excerpt, prefix="    "))
    return blocks


def _caller_units(
    inventory: dict[str, Any] | StaticInventory,
    unit: Any,
) -> list[Any]:
    unit_id = str(_unit_get(unit, "unit_id", "") or "")
    units = _inventory_unit_map(inventory)
    seen: set[str] = set()
    out: list[Any] = []
    for edge in _inventory_call_edges(inventory):
        resolved = list(edge.get("resolved_units") or [])
        if unit_id not in resolved:
            continue
        caller_id = str(edge.get("caller") or "")
        if not caller_id or caller_id in seen:
            continue
        caller = units.get(caller_id)
        if caller is None:
            continue
        seen.add(caller_id)
        out.append(caller)
    return out


def _callee_units(
    inventory: dict[str, Any] | StaticInventory,
    unit: Any,
) -> list[Any]:
    unit_id = str(_unit_get(unit, "unit_id", "") or "")
    units = _inventory_unit_map(inventory)
    seen: set[str] = set()
    out: list[Any] = []
    for edge in _inventory_call_edges(inventory):
        if str(edge.get("caller") or "") != unit_id:
            continue
        for resolved_unit in list(edge.get("resolved_units") or []):
            resolved_id = str(resolved_unit or "")
            if not resolved_id or resolved_id in seen:
                continue
            callee = units.get(resolved_id)
            if callee is None:
                continue
            seen.add(resolved_id)
            out.append(callee)
    return out


def _rank_neighbor_units(
    unit: Any,
    neighbors: list[Any],
    *,
    relation: str,
    codebase_path: str | Path,
) -> list[Any]:
    unit_file = str(_unit_get(unit, "file_path", "") or "")
    unit_start = int(_unit_get(unit, "start_line", 0) or 0)
    return sorted(
        neighbors,
        key=lambda neighbor: (
            _unit_get(neighbor, "file_path", "") != unit_file,
            -_neighbor_signal_score(
                unit,
                neighbor,
                relation=relation,
                codebase_path=codebase_path,
            ),
            int(_unit_get(neighbor, "end_line", 0) or 0)
            - int(_unit_get(neighbor, "start_line", 0) or 0),
            abs(int(_unit_get(neighbor, "start_line", 0) or 0) - unit_start),
            _unit_get(neighbor, "name", ""),
        ),
    )


def _neighbor_signal_score(
    unit: Any,
    neighbor: Any,
    *,
    relation: str,
    codebase_path: str | Path,
) -> int:
    if not is_c_family_file(str(_unit_get(unit, "file_path", "") or "")):
        unit_refs = {
            str(ref).lower()
            for ref in (_unit_get(unit, "references", []) or [])
            if str(ref).strip()
        }
        text = " ".join(
            [
                str(_unit_get(neighbor, "name", "") or "").lower(),
                " ".join(
                    str(ref).lower()
                    for ref in (_unit_get(neighbor, "references", []) or [])
                ),
                " ".join(
                    str(call).lower()
                    for call in (_unit_get(neighbor, "calls", []) or [])
                ),
            ]
        )
        return sum(1 for ref in unit_refs if ref and ref in text)
    return c_family_neighbor_signal_score(
        unit,
        neighbor,
        relation=relation,
        codebase_path=codebase_path,
        excerpt_for_unit=_excerpt_for_unit,
    )


def _excerpt_for_unit(
    unit: Any,
    *,
    codebase_path: str | Path,
    max_lines: int,
) -> str:
    file_path = str(_unit_get(unit, "file_path", "") or "")
    start_line = int(_unit_get(unit, "start_line", 0) or 0)
    end_line = int(_unit_get(unit, "end_line", 0) or 0)
    if not file_path or start_line <= 0 or end_line < start_line:
        return ""

    abs_path = Path(codebase_path).resolve() / file_path
    if not abs_path.is_file():
        return ""

    lines = abs_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    excerpt_lines = lines[start_line - 1 : end_line]
    if not excerpt_lines:
        return ""
    if len(excerpt_lines) <= max_lines:
        return "\n".join(excerpt_lines)

    clipped = excerpt_lines[:max_lines]
    clipped.append(
        f"... [truncated {len(excerpt_lines) - max_lines} line(s) of "
        f"{_unit_get(unit, 'name', 'unit')}]"
    )
    return "\n".join(clipped)


def _macro_context_blocks(
    inventory: dict[str, Any] | StaticInventory,
    unit: Any,
    *,
    codebase_path: str | Path,
    limit: int,
) -> list[str]:
    file_path = str(_unit_get(unit, "file_path", "") or "")
    file_record = _inventory_file_record(inventory, file_path)
    if not file_path or not isinstance(file_record, dict):
        return []

    references = {str(ref) for ref in (_unit_get(unit, "references", []) or [])}
    macro_names = [
        name
        for name in list(file_record.get("macro_definitions") or [])
        if str(name) in references
    ][:limit]
    if not macro_names:
        return []

    abs_path = Path(codebase_path).resolve() / file_path
    if not abs_path.is_file():
        return []

    file_lines = abs_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    blocks: list[str] = []
    for name in macro_names:
        definition = _find_macro_definition_block(file_lines, str(name))
        if not definition:
            continue
        blocks.append(f"- macro: {name}")
        blocks.extend(_indent_block(definition, prefix="    "))
    return blocks


def _type_context_blocks(
    unit: Any,
    *,
    codebase_path: str | Path,
    limit: int,
) -> list[str]:
    return build_c_family_type_context(
        unit,
        codebase_path=codebase_path,
        limit=limit,
    )


def _macro_expansion_context_blocks(
    unit: Any,
    *,
    codebase_path: str | Path,
    limit: int,
) -> list[str]:
    return build_c_family_macro_expansion_context(
        unit,
        codebase_path=codebase_path,
        limit=limit,
    )


def _indirect_call_context_blocks(
    inventory: dict[str, Any] | StaticInventory,
    unit: Any,
    *,
    codebase_path: str | Path,
    limit: int,
) -> list[str]:
    return build_c_family_indirect_call_context(
        inventory,
        unit,
        codebase_path=codebase_path,
        limit=limit,
    )


def _find_macro_definition_block(lines: list[str], name: str) -> str:
    marker = f"#define {name}"
    for index, line in enumerate(lines):
        stripped = line.strip()
        if not stripped.startswith("#"):
            continue
        normalized = " ".join(stripped.split())
        if marker not in normalized:
            continue
        block = [line]
        cursor = index + 1
        while block[-1].rstrip().endswith("\\") and cursor < len(lines):
            block.append(lines[cursor])
            cursor += 1
        return "\n".join(block)
    return ""


def _indent_block(text: str, *, prefix: str = "  ") -> list[str]:
    if not text:
        return []
    return [
        f"{prefix}{line}" if line else prefix.rstrip() for line in text.splitlines()
    ]

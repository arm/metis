# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class UnitXref:
    unit_id: str
    unit: Any | None = None
    file: Any | None = None
    callers: list[dict[str, Any]] = field(default_factory=list)
    callees: list[dict[str, Any]] = field(default_factory=list)
    symbol_definitions: dict[str, list[str]] = field(default_factory=dict)
    symbol_references: dict[str, list[str]] = field(default_factory=dict)
    unresolved_calls: list[str] = field(default_factory=list)
    includes: list[str] = field(default_factory=list)
    macro_definitions: list[str] = field(default_factory=list)
    macro_uses: list[str] = field(default_factory=list)


def expand_unit_xref(inventory: Any, unit_id: str) -> UnitXref:
    unit = inventory.units.get(unit_id)
    file_record = inventory.files.get(unit.file_path) if unit is not None else None
    xref = UnitXref(unit_id=unit_id, unit=unit, file=file_record)
    if unit is None:
        return xref

    xref.callers = find_callers(inventory, unit.name, unit_id=unit_id)
    xref.callees = find_callees(inventory, unit_id)
    xref.unresolved_calls = [
        edge["callee_symbol"] for edge in xref.callees if not edge.get("resolved_units")
    ]

    for symbol in unit.references:
        definitions = find_symbol_definitions(
            inventory,
            symbol,
            caller_unit_id=unit_id,
        )
        references = find_symbol_references(inventory, symbol)
        if definitions:
            xref.symbol_definitions[symbol] = definitions
        if references:
            xref.symbol_references[symbol] = references

    if file_record is not None:
        xref.includes = list(file_record.includes)
        xref.macro_definitions = list(file_record.macro_definitions)
        xref.macro_uses = [
            macro for macro in file_record.macro_uses if macro in set(unit.references)
        ]

    return xref


def find_callers(
    inventory: Any,
    symbol: str,
    *,
    unit_id: str | None = None,
) -> list[dict[str, Any]]:
    callers: list[dict[str, Any]] = []
    if not symbol:
        return callers
    for edge in inventory.call_edges:
        resolved_units = list(edge.get("resolved_units") or [])
        if unit_id:
            if unit_id not in resolved_units:
                continue
        elif edge.get("callee_symbol") != symbol:
            continue
        caller_id = str(edge.get("caller") or "")
        caller = inventory.units.get(caller_id)
        callers.append(
            {
                "caller": caller_id,
                "caller_name": caller.name if caller else "",
                "file_path": caller.file_path if caller else "",
                "line": edge.get("line", 0),
                "kind": edge.get("kind", "direct"),
            }
        )
    return callers


def find_callees(inventory: Any, unit_id: str) -> list[dict[str, Any]]:
    callees: list[dict[str, Any]] = []
    caller = inventory.units.get(unit_id)
    for edge in inventory.call_edges:
        if edge.get("caller") != unit_id:
            continue
        callee_symbol = str(edge.get("callee_symbol") or "")
        resolved_units = list(edge.get("resolved_units") or [])
        if not resolved_units:
            resolved_units = find_symbol_definitions(
                inventory,
                callee_symbol,
                caller_unit_id=unit_id,
            )
        callees.append(
            {
                "callee_symbol": callee_symbol,
                "line": edge.get("line", 0),
                "kind": edge.get("kind", "direct"),
                "resolved_units": resolved_units,
                "resolution_scope": edge.get("resolution_scope", ""),
                "caller_file_path": getattr(caller, "file_path", ""),
            }
        )
    return callees


def find_symbol_definitions(
    inventory: Any,
    symbol: str,
    *,
    caller_unit_id: str | None = None,
    caller_file_path: str | None = None,
) -> list[str]:
    entry = inventory.symbols.get(symbol) or {}
    definitions = list(entry.get("definitions") or [])
    if caller_unit_id is None and caller_file_path is None:
        return definitions

    if caller_file_path is None and caller_unit_id is not None:
        caller = inventory.units.get(caller_unit_id)
        caller_file_path = getattr(caller, "file_path", "")

    same_file_defs = [
        unit_id
        for unit_id in definitions
        if getattr(inventory.units.get(unit_id), "file_path", "") == caller_file_path
    ]
    if len(same_file_defs) == 1:
        return same_file_defs
    if len(same_file_defs) > 1:
        return []
    if len(definitions) == 1:
        return definitions
    return []


def find_symbol_references(inventory: Any, symbol: str) -> list[str]:
    entry = inventory.symbols.get(symbol) or {}
    return list(entry.get("references") or [])

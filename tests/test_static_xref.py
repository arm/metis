# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from types import SimpleNamespace

from metis.engine.analysis.static_inventory import build_static_inventory
from metis.engine.analysis.static_xref import (
    expand_unit_xref,
    find_callers,
    find_callees,
)


class _Plugin:
    def get_name(self):
        return "c"


class _Repository:
    def __init__(self, root, files):
        self._config = SimpleNamespace(codebase_path=str(root))
        self._files = [str(path) for path in files]

    def get_code_files(self):
        return list(self._files)

    def get_plugin_for_extension(self, ext):
        return _Plugin() if ext == ".c" else None


def _build_inventory(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    c_file = src / "main.c"
    c_file.write_text(
        '#include "main.h"\n'
        "#define MAX_LEN 16\n"
        "\n"
        "int helper(int value) {\n"
        "    return value + 1;\n"
        "}\n"
        "\n"
        "int handle_packet(char *dst, const char *src, int len) {\n"
        "    helper(len);\n"
        "    memcpy(dst, src, len);\n"
        "    return 0;\n"
        "}\n"
        "\n"
        "int entry(char *dst, const char *src, int len) {\n"
        "    return handle_packet(dst, src, len);\n"
        "}\n",
        encoding="utf-8",
    )
    inventory, _path = build_static_inventory(
        _Repository(tmp_path, [c_file]),
        output_path=tmp_path / ".metis" / "static_inventory.json",
    )
    return inventory


def test_find_callers_and_callees(tmp_path):
    inventory = _build_inventory(tmp_path)
    handle_id = next(
        unit.unit_id
        for unit in inventory.units.values()
        if unit.name == "handle_packet"
    )

    callers = find_callers(inventory, "handle_packet")
    callees = find_callees(inventory, handle_id)

    assert [caller["caller_name"] for caller in callers] == ["entry"]
    assert {callee["callee_symbol"] for callee in callees} >= {"helper", "memcpy"}
    helper = next(callee for callee in callees if callee["callee_symbol"] == "helper")
    assert helper["resolved_units"]
    memcpy = next(callee for callee in callees if callee["callee_symbol"] == "memcpy")
    assert memcpy["resolved_units"] == []


def test_expand_unit_xref_includes_file_and_unresolved_call_context(tmp_path):
    inventory = _build_inventory(tmp_path)
    handle_id = next(
        unit.unit_id
        for unit in inventory.units.values()
        if unit.name == "handle_packet"
    )

    xref = expand_unit_xref(inventory, handle_id)

    assert xref.unit.name == "handle_packet"
    assert xref.file.file_path == "src/main.c"
    assert xref.includes == ["main.h"]
    assert "MAX_LEN" in xref.macro_definitions
    assert "memcpy" in xref.unresolved_calls
    assert "helper" in xref.symbol_definitions


def test_scoped_resolution_prefers_same_file_and_leaves_ambiguous_globals_unresolved(
    tmp_path,
):
    src = tmp_path / "src"
    src.mkdir()
    a_file = src / "a.c"
    b_file = src / "b.c"
    c_file = src / "c.c"
    a_file.write_text(
        "int sanitize(int value) {\n"
        "    return value + 1;\n"
        "}\n"
        "\n"
        "int call_local(int value) {\n"
        "    return sanitize(value);\n"
        "}\n",
        encoding="utf-8",
    )
    b_file.write_text(
        "int sanitize(int value) {\n" "    return value - 1;\n" "}\n",
        encoding="utf-8",
    )
    c_file.write_text(
        "int call_global(int value) {\n" "    return sanitize(value);\n" "}\n",
        encoding="utf-8",
    )
    inventory, _path = build_static_inventory(
        _Repository(tmp_path, [a_file, b_file, c_file]),
        output_path=tmp_path / ".metis" / "static_inventory.json",
    )

    local_caller_id = next(
        unit.unit_id for unit in inventory.units.values() if unit.name == "call_local"
    )
    global_caller_id = next(
        unit.unit_id for unit in inventory.units.values() if unit.name == "call_global"
    )

    local_callees = find_callees(inventory, local_caller_id)
    global_callees = find_callees(inventory, global_caller_id)

    assert local_callees[0]["resolved_units"] == ["src/a.c::sanitize:1-3"]
    assert local_callees[0]["resolution_scope"] == "same_file_unique"
    assert global_callees[0]["resolved_units"] == []
    assert global_callees[0]["resolution_scope"] == "global_ambiguous"

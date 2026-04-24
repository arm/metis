# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from types import SimpleNamespace

from metis.engine import MetisEngine
from metis.engine.analysis.static_inventory import build_static_inventory
from metis.engine.analysis.review_packets import build_review_packets_from_inventory


class _Plugin:
    def __init__(self, name):
        self._name = name

    def get_name(self):
        return self._name


class _Repository:
    def __init__(self, root, files):
        self._config = SimpleNamespace(codebase_path=str(root))
        self._files = [str(path) for path in files]

    def get_code_files(self):
        return list(self._files)

    def get_plugin_for_extension(self, ext):
        if ext == ".c":
            return _Plugin("c")
        return None


def test_build_static_inventory_writes_json_sidecar(tmp_path):
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
        "}\n",
        encoding="utf-8",
    )
    out_path = tmp_path / ".metis" / "static_inventory.json"

    inventory, path = build_static_inventory(
        _Repository(tmp_path, [c_file]),
        output_path=out_path,
    )

    assert path == out_path
    assert path.exists()
    assert inventory.version >= 2
    assert "src/main.c" in inventory.files
    file_record = inventory.files["src/main.c"]
    assert file_record.includes == ["main.h"]
    assert "MAX_LEN" in file_record.macro_definitions
    assert any(unit.name == "handle_packet" for unit in inventory.units.values())
    handle = next(
        unit for unit in inventory.units.values() if unit.name == "handle_packet"
    )
    assert "helper" in handle.calls
    assert "memcpy" in handle.calls
    assert "copy_or_format" in handle.risk_signals
    assert handle.analysis["risk"]["score"] >= 50
    assert handle.analysis["risk"]["should_call_llm"] is True
    obligation_names = {
        obligation["name"] for obligation in handle.analysis["obligations"]
    }
    assert "bounds_or_capacity" in obligation_names
    assert inventory.summary["files"] == 1
    assert inventory.summary["units"] >= 2
    assert inventory.summary["medium_risk_units"] >= 1
    assert inventory.summary["llm_candidate_units"] >= 1
    assert inventory.summary["unknown_obligations"] >= 1
    assert "handle_packet" in inventory.symbols
    assert any(edge["callee_symbol"] == "memcpy" for edge in inventory.call_edges)


def test_init_static_inventory_respects_metisignore(tmp_path, dummy_backend, dummy_llm):
    src = tmp_path / "src"
    src.mkdir()
    (src / "keep.py").write_text("def keep():\n    return 1\n", encoding="utf-8")
    (src / "drop.py").write_text("def drop():\n    return 2\n", encoding="utf-8")
    (tmp_path / ".metisignore").write_text("*\n!src/\n!src/keep.py\n", encoding="utf-8")
    engine = MetisEngine(
        codebase_path=str(tmp_path),
        vector_backend=dummy_backend,
        llm_provider=dummy_llm,
        max_workers=2,
        max_token_length=2048,
        llama_query_model="gpt-test",
        similarity_top_k=3,
        response_mode="compact",
    )

    inventory, path = engine.init_static_inventory()

    assert path == tmp_path / ".metis" / "static_inventory.json"
    assert sorted(inventory.files) == ["src/keep.py"]
    assert "src/drop.py" not in inventory.files


def test_build_review_packets_from_inventory_selects_file_units(tmp_path):
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

    packets = build_review_packets_from_inventory(
        inventory,
        file_path=str(c_file),
        codebase_path=tmp_path,
    )

    assert packets
    packet = next(item for item in packets if "UNIT: src/main.c::handle_packet" in item)
    assert "STATIC_REVIEW_PACKET" in packet
    assert "bounds_or_capacity" in packet
    assert "SOURCE:" in packet
    assert "memcpy(dst, src, len);" in packet
    assert "CALLER_CONTEXT:" in packet
    assert "return handle_packet(dst, src, len);" in packet
    assert "CALLEE_CONTEXT:" in packet
    assert "return value + 1;" in packet


def test_build_review_packets_include_type_indirect_and_ranked_neighbor_context(
    tmp_path,
):
    src = tmp_path / "src"
    src.mkdir()
    c_file = src / "dispatch.c"
    c_file.write_text(
        "#define MAX_LEN 16\n"
        "\n"
        "typedef struct packet_ops {\n"
        "    int (*copy)(char *dst, const char *src, int len);\n"
        "} packet_ops;\n"
        "\n"
        "int checked_copy(char *dst, const char *src, int len) {\n"
        "    return len;\n"
        "}\n"
        "\n"
        "packet_ops OPS = {\n"
        "    .copy = checked_copy,\n"
        "};\n"
        "\n"
        "int helper_noise(int len) {\n"
        "    return len + 1;\n"
        "}\n"
        "\n"
        "int copy_guard_helper(int len) {\n"
        "    if (len > MAX_LEN) {\n"
        "        return -1;\n"
        "    }\n"
        "    return len;\n"
        "}\n"
        "\n"
        "int validate_packet_len(int len) {\n"
        "    if (len > MAX_LEN) {\n"
        "        return -1;\n"
        "    }\n"
        "    return 0;\n"
        "}\n"
        "\n"
        "int dispatch(packet_ops *ops, char *dst, const char *src, int len) {\n"
        "    helper_noise(len);\n"
        "    validate_packet_len(len);\n"
        "    copy_guard_helper(len);\n"
        "    return ops->copy(dst, src, len);\n"
        "}\n"
        "\n"
        "int dispatch_bound(char *dst, const char *src, int len) {\n"
        "    packet_ops *ops = &OPS;\n"
        "    validate_packet_len(len);\n"
        "    return ops->copy(dst, src, len);\n"
        "}\n"
        "\n"
        "int entry_unchecked(packet_ops *ops, char *dst, const char *src, int len) {\n"
        "    return dispatch(ops, dst, src, len);\n"
        "}\n"
        "\n"
        "int entry_checked(packet_ops *ops, char *dst, const char *src, int len) {\n"
        "    if (len > MAX_LEN) {\n"
        "        return -1;\n"
        "    }\n"
        "    return dispatch(ops, dst, src, len);\n"
        "}\n",
        encoding="utf-8",
    )
    inventory, _path = build_static_inventory(
        _Repository(tmp_path, [c_file]),
        output_path=tmp_path / ".metis" / "static_inventory.json",
    )

    packets = build_review_packets_from_inventory(
        inventory,
        file_path=str(c_file),
        codebase_path=tmp_path,
    )

    dispatch_packet = next(item for item in packets if "NAME: dispatch" in item)
    dispatch_bound_packet = next(
        item for item in packets if "NAME: dispatch_bound" in item
    )

    assert "TYPE_CONTEXT:" in dispatch_packet
    assert "typedef struct packet_ops" in dispatch_packet
    assert "INDIRECT_CALL_CONTEXT:" in dispatch_packet
    assert "expression: ops->copy(...)" in dispatch_packet
    assert "status: unresolved" in dispatch_packet
    assert "resolved_target: checked_copy" not in dispatch_packet
    assert "CALLER_CONTEXT:" in dispatch_packet
    caller_context = dispatch_packet.split("CALLER_CONTEXT:", 1)[1].split(
        "CALLEE_CONTEXT:", 1
    )[0]
    assert "entry_checked" in caller_context
    assert "entry_unchecked" not in caller_context
    assert "CALLEE_CONTEXT:" in dispatch_packet
    callee_context = dispatch_packet.split("CALLEE_CONTEXT:", 1)[1].split(
        "TYPE_CONTEXT:", 1
    )[0]
    assert "validate_packet_len" in callee_context
    assert "copy_guard_helper" in callee_context
    assert "helper_noise" not in callee_context
    assert "resolved_target: checked_copy" in dispatch_bound_packet
    assert "resolution_kind: initializer_field_binding" in dispatch_bound_packet


def test_build_review_packets_include_macro_expansion_and_fp_alias_resolution(
    tmp_path,
):
    src = tmp_path / "src"
    src.mkdir()
    c_file = src / "macro_dispatch.c"
    c_file.write_text(
        "#define MAX_LEN 16\n"
        "#define ACTIVE_LIMIT MAX_LEN\n"
        "#define CHECKED_COPY_ALIAS checked_copy\n"
        "#define ACTIVE_COPY CHECKED_COPY_ALIAS\n"
        "\n"
        "typedef int (*copy_fn)(char *dst, const char *src, int len);\n"
        "\n"
        "int checked_copy(char *dst, const char *src, int len) {\n"
        "    return len;\n"
        "}\n"
        "\n"
        "int dispatch_macro(char *dst, const char *src, int len) {\n"
        "    copy_fn fp = ACTIVE_COPY;\n"
        "    if (len > ACTIVE_LIMIT) {\n"
        "        return -1;\n"
        "    }\n"
        "    memcpy(dst, src, len);\n"
        "    return (*fp)(dst, src, len);\n"
        "}\n",
        encoding="utf-8",
    )
    inventory, _path = build_static_inventory(
        _Repository(tmp_path, [c_file]),
        output_path=tmp_path / ".metis" / "static_inventory.json",
    )

    packets = build_review_packets_from_inventory(
        inventory,
        file_path=str(c_file),
        codebase_path=tmp_path,
    )

    packet = next(item for item in packets if "NAME: dispatch_macro" in item)

    assert "MACRO_EXPANSION_CONTEXT:" in packet
    assert "macro: ACTIVE_COPY" in packet
    assert "expansion_chain: ACTIVE_COPY -> CHECKED_COPY_ALIAS" in packet
    assert "terminal: checked_copy" in packet
    assert "macro: ACTIVE_LIMIT" in packet
    assert "terminal: 16" in packet
    assert "INDIRECT_CALL_CONTEXT:" in packet
    assert "expression: (*fp)(...)" in packet or "expression: fp(...)" in packet
    assert "resolved_target: checked_copy" in packet

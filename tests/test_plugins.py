# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from llama_index.core.schema import Document
import pytest

from metis.plugins.aarch64_assembly_plugin import AArch64AssemblyPlugin
from metis.plugins.c_plugin import CPlugin
from metis.plugins.cpp_plugin import CppPlugin
from metis.plugins.go_plugin import GoPlugin
from metis.plugins.javascript_plugin import JavaScriptPlugin
from metis.plugins.php_plugin import PHPPlugin
from metis.plugins.python_plugin import PythonPlugin
from metis.plugins.ruby_plugin import RubyPlugin
from metis.plugins.rust_plugin import RustPlugin
from metis.plugins.solidity_plugin import SolidityPlugin
from metis.plugins.systemverilog_plugin import SystemVerilogPlugin
from metis.plugins.tb_plugin import TableGenPlugin
from metis.plugins.terraform_plugin import TerraformPlugin
from metis.plugins.typescript_plugin import TypeScriptPlugin
from metis.plugins.verilog_plugin import VerilogPlugin


def test_c_plugin_exposes_triage_analyzer_factory():
    plugin = CPlugin(plugin_config={"plugins": {}})
    factory = plugin.get_triage_analyzer_factory()
    assert callable(factory)


def test_cpp_plugin_exposes_triage_analyzer_factory():
    plugin = CppPlugin(plugin_config={"plugins": {}})
    factory = plugin.get_triage_analyzer_factory()
    assert callable(factory)


def test_python_plugin_exposes_generic_triage_analyzer_factory():
    plugin = PythonPlugin(plugin_config={"plugins": {}})
    factory = plugin.get_triage_analyzer_factory()
    assert callable(factory)


def test_reachability_capabilities_are_plugin_declared():
    c_plugin = CPlugin(plugin_config={"plugins": {}})
    cpp_plugin = CppPlugin(plugin_config={"plugins": {}})
    python_plugin = PythonPlugin(plugin_config={"plugins": {}})

    assert c_plugin.supports_reachability_review()
    assert cpp_plugin.supports_reachability_review()
    assert not python_plugin.supports_reachability_review()

    assert c_plugin.supports_c_family_triage_evidence()
    assert cpp_plugin.supports_c_family_triage_evidence()
    assert not python_plugin.supports_c_family_triage_evidence()


def test_aarch64_assembly_splitter_parses_source_text():
    plugin = AArch64AssemblyPlugin(plugin_config={"plugins": {}})
    splitter = plugin.get_splitter()

    nodes = splitter.get_nodes_from_documents(
        [Document(text="start:\n    mov x0, x0\n    ret\n", id_="example.s")]
    )

    assert nodes
    assert "mov x0, x0" in nodes[0].text


@pytest.mark.parametrize(
    ("plugin_cls", "text"),
    [
        (CPlugin, "int main(void) { return 0; }\n"),
        (CppPlugin, "int main() { return 0; }\n"),
        (GoPlugin, "package main\nfunc main() {}\n"),
        (JavaScriptPlugin, "function main() { return 0; }\n"),
        (PHPPlugin, "<?php function main() { return 0; }\n"),
        (PythonPlugin, "def main():\n    return 0\n"),
        (RubyPlugin, "def main\n  0\nend\n"),
        (RustPlugin, "fn main() { }\n"),
        (SolidityPlugin, "pragma solidity ^0.8.0; contract C {}\n"),
        (SystemVerilogPlugin, "module top; endmodule\n"),
        (TableGenPlugin, "class X;\n"),
        (TerraformPlugin, 'resource "x" "y" {}\n'),
        (TypeScriptPlugin, "function main(): number { return 0; }\n"),
        (VerilogPlugin, "module top; endmodule\n"),
    ],
)
def test_builtin_code_splitters_use_compatible_treesitter_parser(plugin_cls, text):
    plugin = plugin_cls(plugin_config={"plugins": {}})
    splitter = plugin.get_splitter()

    nodes = splitter.get_nodes_from_documents(
        [Document(text=text, id_=f"src/example.{plugin.get_name()}")]
    )

    assert nodes
    assert nodes[0].text.strip()

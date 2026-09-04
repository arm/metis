# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import json
from unittest.mock import Mock

import pytest
from llama_index.core.schema import Document

from metis.configuration import load_plugin_config
from metis.plugins.aarch64_assembly_plugin import AArch64AssemblyPlugin
from metis.plugins.ipynb_plugin import IpynbPlugin
from metis.plugins.registry import LanguagePluginRegistry


@pytest.mark.parametrize("parser_available", (True, False))
def test_aarch64_assembly_splitter_parses_source_text(monkeypatch, parser_available):
    if not parser_available:
        monkeypatch.setattr(
            "metis.plugins.aarch64_assembly_plugin.build_code_splitter",
            Mock(side_effect=RuntimeError("parser unavailable")),
        )
    plugin = AArch64AssemblyPlugin(plugin_config={"plugins": {}})
    splitter = plugin.get_splitter()

    nodes = splitter.get_nodes_from_documents(
        [Document(text="start:\n    mov x0, x0\n    ret\n", id_="example.s")]
    )

    assert nodes
    assert "mov x0, x0" in nodes[0].text


def test_ipynb_splitter_extracts_code_cells_without_console_output(capsys):
    plugin = IpynbPlugin(
        plugin_config={
            "plugins": {
                "ipynb": {
                    "supported_extensions": [".ipynb"],
                    "splitting": {
                        "chunk_lines": 40,
                        "chunk_lines_overlap": 15,
                        "max_chars": 1500,
                    },
                }
            }
        }
    )
    notebook = json.dumps(
        {
            "cells": [
                {"cell_type": "markdown", "source": ["Ignore me"]},
                {"cell_type": "code", "source": ["value = 1\n"]},
                {"cell_type": "code", "source": ["print(value)\n"]},
            ]
        }
    )

    nodes = plugin.get_splitter().get_nodes_from_documents(
        [Document(text=notebook, metadata={"project": "demo"}, id_="demo.ipynb")]
    )

    assert nodes
    extracted = "\n".join(node.text for node in nodes)
    assert "value = 1" in extracted
    assert "print(value)" in extracted
    assert all(node.metadata["project"] == "demo" for node in nodes)
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize(
    ("language", "text"),
    [
        ("c", "int main(void) { return 0; }\n"),
        ("cpp", "int main() { return 0; }\n"),
        ("csharp", "class Program { static void Main() { } }\n"),
        ("go", "package main\nfunc main() {}\n"),
        ("java", "class Main { public static void main(String[] args) {} }\n"),
        ("javascript", "function main() { return 0; }\n"),
        ("kotlin", "fun main() {}\n"),
        (
            "perl",
            "use strict;\nuse warnings;\nsub main { return 0; }\nmain();\n",
        ),
        ("php", "<?php function main() { return 0; }\n"),
        ("python", "def main():\n    return 0\n"),
        ("rust", "fn main() { }\n"),
        ("solidity", "pragma solidity ^0.8.0; contract C {}\n"),
        ("systemverilog", "module top; endmodule\n"),
        ("tablegen", "class X;\n"),
        ("terraform", 'resource "x" "y" {}\n'),
        ("typescript", "function main(): number { return 0; }\n"),
        ("verilog", "module top; endmodule\n"),
    ],
)
def test_builtin_code_splitters_use_compatible_treesitter_parser(
    language: str,
    text: str,
) -> None:
    registry = LanguagePluginRegistry.from_config(load_plugin_config())
    plugin = registry.get_plugin(language)

    assert plugin is not None
    splitter = plugin.get_splitter()

    nodes = splitter.get_nodes_from_documents(
        [Document(text=text, id_=f"src/example.{plugin.get_name()}")]
    )

    assert nodes
    assert nodes[0].text.strip()

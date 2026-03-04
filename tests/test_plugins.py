# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from metis.plugins.c_plugin import CPlugin
from metis.plugins.cpp_plugin import CppPlugin
from metis.plugins.python_plugin import PythonPlugin


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

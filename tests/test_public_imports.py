# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Public extension contracts must import independently of engine orchestration."""

from itertools import permutations
import os
from pathlib import Path
import subprocess
import sys
from textwrap import dedent

import pytest


@pytest.mark.parametrize(
    "order",
    permutations(
        ("metis.execution_nodes", "metis.execution_stages", "metis.capabilities")
    ),
)
def test_public_contracts_import_concurrently_without_loading_engine(order):
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            dedent(
                """
                from concurrent.futures import ThreadPoolExecutor
                import importlib
                import sys
                from threading import Barrier

                start = Barrier(6, timeout=5)

                def load(name):
                    start.wait()
                    return importlib.import_module(name)

                with ThreadPoolExecutor(max_workers=6) as executor:
                    modules = list(executor.map(load, sys.argv[1:]))

                assert "metis.engine.core" not in sys.modules
                for module in modules:
                    namespace = {}
                    exec(f"from {module.__name__} import *", namespace)
                    assert namespace.keys() - {"__builtins__"} == set(module.__all__)
                    for name in module.__all__:
                        assert namespace[name] is getattr(module, name)

                from metis.engine import ExecutionGraphError, MetisEngine, TriageOptions
                from metis.engine import core
                from metis.runtime_settings import TriageOptions as RuntimeTriageOptions

                assert ExecutionGraphError is core.ExecutionGraphError
                assert MetisEngine is core.MetisEngine
                assert TriageOptions is RuntimeTriageOptions
                namespace = {}
                exec("from metis.engine import *", namespace)
                assert namespace.keys() - {"__builtins__"} == {
                    "ExecutionGraphError", "MetisEngine", "TriageOptions"
                }
                assert namespace["MetisEngine"] is MetisEngine
                engine = importlib.import_module("metis.engine")
                assert not hasattr(engine, "missing_extension_contract")
                """
            ),
            *order,
            *order,
        ],
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


@pytest.mark.parametrize("order", [("output", "utils"), ("utils", "output")])
def test_cli_output_imports_preserve_legacy_aliases(order):
    environment = dict(os.environ)
    environment["PYTHONPATH"] = str(Path(__file__).resolve().parents[1] / "src")
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            dedent(
                """
                import importlib
                import sys

                for name in sys.argv[1:]:
                    importlib.import_module(f"metis.cli.{name}")
                from metis.cli import output
                from metis.cli import utils

                names = (
                    "METIS_VERSION REPORT_TEMPLATE export_csv export_html export_sarif "
                    "output_format output_path_identity output_files_for_formats "
                    "graph_output_files save_output"
                ).split()
                for name in names:
                    assert getattr(utils, name) is getattr(output, name)
                for name in ("entry", "commands"):
                    importlib.import_module(f"metis.cli.{name}")
                assert output.graph_output_files(None, {}, quiet=True) == {
                    "review": [], "triage": []
                }
                """
            ),
            *order,
        ],
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr

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

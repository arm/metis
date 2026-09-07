# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Compile the skill's configuration recipes without executing or using a provider."""

from contextlib import closing
from importlib.resources import files
from pathlib import Path

import pytest

from metis.configuration import load_yaml
from metis.configuration import normalize_engine_config
from metis.engine import MetisEngine


ASSETS = Path(__file__).resolve().parents[1] / "skills/metis-review/assets"


def _recipe_runtime(graph, triage):
    config = load_yaml(ASSETS / "quick-review.yaml")
    if graph:
        config["metis_engine"]["execution"] = load_yaml(
            ASSETS / "graph-assisted-execution.yaml"
        )
    stages = config["metis_engine"]["execution"]["stages"]
    if triage:
        stages["triage"] = load_yaml(ASSETS / "triage-stage.yaml")
        if graph:
            stages["triage"]["inputs"]["codegraph"] = "initialize.codegraph"
    return normalize_engine_config(
        config,
        engine_defaults=load_yaml(files("metis") / "metis.yaml")["metis_engine"],
    )


@pytest.mark.parametrize("graph", [False, True], ids=["quick", "graph"])
@pytest.mark.parametrize("triage", [False, True], ids=["review", "with-triage"])
def test_skill_recipes_compile_real_stages_and_nodes(tmp_path, graph, triage):
    with closing(
        MetisEngine(
            codebase_path=str(tmp_path),
            llm_provider=object(),  # Any attempted provider operation fails immediately.
            llama_query_model="offline",
            **_recipe_runtime(graph, triage),
        )
    ) as engine:
        expected = {
            ("review", "simple_llm_review"),
            ("review", "finding_dedup"),
            ("review", "result"),
        }
        if graph:
            expected.update({("initialize", "codegraph"), ("review", "reachability")})
        if triage:
            expected.update({("triage", "triage"), ("triage", "result")})
        assert engine.execution.configuration.selected_nodes() == expected
        assert set(engine.capabilities) == ({"navigation"} if triage else set())


def test_graph_recipe_requires_codegraph_input(tmp_path):
    runtime = _recipe_runtime(graph=True, triage=False)
    runtime["execution_config"]["stages"]["review"]["inputs"].pop("codegraph")
    with pytest.raises(ValueError, match="reachability.*unbound inputs: codegraph"):
        MetisEngine(
            codebase_path=str(tmp_path),
            llm_provider=object(),
            llama_query_model="offline",
            **runtime,
        )

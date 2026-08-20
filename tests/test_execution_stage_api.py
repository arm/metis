# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import pytest

import metis.execution_stages as execution_stages
from metis.engine.stages.catalog import StageCatalog


class _BuiltinCollisionEntryPoint:
    name = "review"


def test_execution_stage_public_api_is_explicit() -> None:
    assert set(execution_stages.__all__) == {
        "StageContract",
        "StageRegistration",
    }


def test_execution_stage_contract_rejects_invalid_ports() -> None:
    with pytest.raises(ValueError, match="invalid port 'bad-port'"):
        execution_stages.StageContract({"bad-port": str})


def test_installed_execution_stage_cannot_shadow_a_builtin() -> None:
    with pytest.raises(ValueError, match="conflicts with a built-in stage"):
        StageCatalog(("review",), (_BuiltinCollisionEntryPoint(),))

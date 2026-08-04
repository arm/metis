# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from collections.abc import Callable
from pathlib import Path
from unittest.mock import Mock

import pytest
from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field
from pydantic import ValidationError

from metis.capabilities import CapabilityContext
from metis.capabilities import CapabilityManifest
from metis.capabilities import CapabilityRegistration
from metis.engine.capabilities.catalog import CapabilityCatalog
from metis.engine.capabilities.engine import build_engine_capabilities
from metis.engine.execution.catalog import NodeCatalog
from metis.engine.execution.compiler import compile_stage
from metis.engine.execution.contracts import EmptyNodeConfiguration
from metis.engine.execution.contracts import NodeRegistration
from metis.engine.execution.contracts import NodeResult
from metis.engine.execution.graph import StageConfiguration


class _Configuration(BaseModel):
    budget: int = Field(gt=0)

    model_config = ConfigDict(extra="forbid", frozen=True)


class _EntryPoint:
    def __init__(self, name: str, loaded: object) -> None:
        self.name = name
        self._loaded = loaded
        self.load_count = 0

    def load(self) -> object:
        self.load_count += 1
        return self._loaded


def _context(tmp_path: Path) -> CapabilityContext:
    return CapabilityContext(tmp_path, Mock(), max_workers=2, max_token_length=2048)


def _registration(
    name: str,
    factory: Callable[[CapabilityContext, BaseModel], object],
    *,
    close: Callable[[object], None] | None = None,
) -> CapabilityRegistration:
    return CapabilityRegistration(
        CapabilityManifest(name),
        _Configuration,
        factory,
        close,
    )


def test_external_capability_is_loaded_only_when_selected(tmp_path: Path) -> None:
    factory = Mock(return_value=object())
    entry_point = _EntryPoint(
        "private_analysis", _registration("private_analysis", factory)
    )
    catalog = CapabilityCatalog((), (entry_point,))

    capabilities = build_engine_capabilities(set(), {}, catalog, _context(tmp_path))

    assert dict(capabilities) == {}
    assert entry_point.load_count == 0
    factory.assert_not_called()


def test_selected_capability_owns_configuration_and_lifecycle(tmp_path: Path) -> None:
    closed: list[object] = []
    instance = object()
    registration = _registration(
        "private_analysis",
        lambda _context, configuration: instance if configuration.budget == 3 else None,
        close=closed.append,
    )
    entry_point = _EntryPoint("private_analysis", registration)

    capabilities = build_engine_capabilities(
        {"private_analysis"},
        {"private_analysis": {"budget": 3}},
        CapabilityCatalog((), (entry_point,)),
        _context(tmp_path),
    )

    assert entry_point.load_count == 0
    assert capabilities["private_analysis"] is instance
    assert entry_point.load_count == 1
    capabilities.close()
    assert closed == [instance]


def test_invalid_selected_configuration_fails_before_factory(tmp_path: Path) -> None:
    factory = Mock()
    catalog = CapabilityCatalog(
        (_registration("private_analysis", factory),),
    )

    capabilities = build_engine_capabilities(
        {"private_analysis"},
        {"private_analysis": {"budget": 0}},
        catalog,
        _context(tmp_path),
    )

    with pytest.raises(ValidationError, match="budget"):
        capabilities["private_analysis"]

    factory.assert_not_called()


def test_external_capability_cannot_shadow_builtin() -> None:
    registration = _registration("shared", Mock())
    catalog = CapabilityCatalog(
        (registration,),
        (_EntryPoint("shared", registration),),
    )

    with pytest.raises(ValueError, match="conflicts with a built-in"):
        catalog.resolve("shared")


def test_unsupported_node_grant_does_not_load_capability(tmp_path: Path) -> None:
    factory = Mock()
    entry_point = _EntryPoint(
        "private_analysis", _registration("private_analysis", factory)
    )
    capabilities = build_engine_capabilities(
        {"private_analysis"},
        {"private_analysis": {"budget": 3}},
        CapabilityCatalog((), (entry_point,)),
        _context(tmp_path),
    )
    node = NodeRegistration(
        "plain_review",
        "review",
        EmptyNodeConfiguration,
        {},
        {},
        lambda _invocation: NodeResult({}),
    )
    stage = StageConfiguration.model_validate(
        {"nodes": {"plain_review": {"capabilities": ["private_analysis"]}}}
    )

    with pytest.raises(ValueError, match="does not declare capabilities"):
        compile_stage(NodeCatalog((node,)), "review", stage, {}, {}, capabilities)

    assert entry_point.load_count == 0
    factory.assert_not_called()

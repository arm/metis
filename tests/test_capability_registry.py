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
from pydantic import model_validator

from metis.configuration import load_runtime_config
from metis.configuration import load_yaml
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


@pytest.mark.parametrize("callback", ("registration", "validation"))
def test_capability_reentry_before_factory_is_rejected_and_retryable(
    tmp_path: Path, callback: str
) -> None:
    instance = object()
    factory = Mock(return_value=instance)
    closed: list[object] = []
    reentered = False

    class Configuration(EmptyNodeConfiguration):
        @model_validator(mode="before")
        @classmethod
        def validate_configuration(cls, values):
            nonlocal reentered
            if callback == "validation" and not reentered:
                reentered = True
                capabilities.require("shared")
            return values

    registration = CapabilityRegistration(
        CapabilityManifest("shared"), Configuration, factory, closed.append
    )

    def load_registration():
        nonlocal reentered
        if callback == "registration" and not reentered:
            reentered = True
            capabilities.require("shared")
        return registration

    capabilities = build_engine_capabilities(
        {"shared"},
        {},
        CapabilityCatalog((), (_EntryPoint("shared", load_registration),)),
        _context(tmp_path),
    )
    try:
        with pytest.raises(RuntimeError, match="shared.*already being constructed"):
            capabilities.require("shared")
        factory.assert_not_called()
        assert closed == []
        assert capabilities.require("shared") is instance
        assert capabilities["shared"] is instance
        factory.assert_called_once()
    finally:
        capabilities.close()
    assert closed == [instance]


def test_failed_capability_validation_does_not_block_retry(tmp_path: Path) -> None:
    attempts = 0
    instance = object()
    factory = Mock(return_value=instance)
    closed: list[object] = []

    class Configuration(EmptyNodeConfiguration):
        @model_validator(mode="before")
        @classmethod
        def validate_configuration(cls, values):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise ValueError("temporarily invalid configuration")
            return values

    registration = CapabilityRegistration(
        CapabilityManifest("shared"), Configuration, factory, closed.append
    )
    capabilities = build_engine_capabilities(
        {"shared"}, {}, CapabilityCatalog((registration,), ()), _context(tmp_path)
    )
    try:
        with pytest.raises(ValidationError, match="temporarily invalid"):
            capabilities["shared"]
        factory.assert_not_called()
        assert capabilities["shared"] is instance
        assert capabilities.require("shared") is instance
        assert attempts == 2
        factory.assert_called_once()
    finally:
        capabilities.close()
    assert closed == [instance]


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


def test_raw_capability_manifest_and_runtime_settings_keep_registered_identity(
    tmp_path: Path,
):
    manifest_path = tmp_path / "capability.yaml"
    manifest_path.write_text(
        """
name: CustomCapability
operations:
  - id: CustomCapability.Run
    name: Run
    surfaces: [model_tool]
""",
        encoding="utf-8",
    )
    config_path = tmp_path / "metis.yaml"
    config_path.write_text(
        """
llm_provider: {name: ollama, model: test-model}
metis_engine:
  capabilities:
    CustomCapability: {budget: 3}
""",
        encoding="utf-8",
    )
    manifest = CapabilityManifest.from_mapping(load_yaml(manifest_path))
    registration = CapabilityRegistration(
        manifest, _Configuration, lambda _context, config: config.budget
    )
    catalog = CapabilityCatalog((registration,), ())
    runtime = load_runtime_config(config_path)

    capabilities = build_engine_capabilities(
        {"CustomCapability"},
        runtime["capability_settings"].configurations,
        catalog,
        _context(tmp_path),
    )
    try:
        assert capabilities["CustomCapability"] == 3
        assert (
            catalog.resolve("CustomCapability").manifest.operations[0].id
            == "CustomCapability.Run"
        )
    finally:
        capabilities.close()


@pytest.mark.parametrize(
    "invalid_field",
    (
        "operations: model",
        "contracts: []",
        "operation: []",
        "operations: [{id: demo.run, name: Run, surfaces: model}]",
    ),
)
def test_capability_manifest_rejects_malformed_raw_fields(
    tmp_path: Path, invalid_field
):
    path = tmp_path / "manifest.yaml"
    path.write_text("name: demo\n" + invalid_field + "\n", encoding="utf-8")

    with pytest.raises(ValueError):
        CapabilityManifest.from_mapping(load_yaml(path))

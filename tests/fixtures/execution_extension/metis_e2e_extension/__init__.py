# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Inert installed extension: public contracts, no provider or target workloads."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
import json
import os
from pathlib import Path
from threading import Condition
from threading import Event
from threading import Lock
from threading import get_ident
from time import monotonic
from time import sleep
from typing import Annotated
from typing import Literal

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field
from pydantic import PrivateAttr

from metis.capabilities import CapabilityManifest
from metis.capabilities import CapabilityRegistration
from metis.execution_nodes import CapabilityRequirement
from metis.execution_nodes import EmptyNodeConfiguration
from metis.execution_nodes import ExecutionDiagnostic
from metis.execution_nodes import ExecutionStatus
from metis.execution_nodes import NodeRegistration
from metis.execution_nodes import NodeResult
from metis.execution_nodes import ReviewCommand
from metis.execution_nodes import SarifPayload
from metis.execution_nodes import StandardReviewResult
from metis.execution_stages import StageContract
from metis.execution_stages import StageRegistration
from metis.providers.base import ChatProvider
from metis.providers.config import ProviderConfigSpec
from metis.version import __version__

_event_lock = Lock()
execution_tag = ContextVar("e2e_execution_tag", default=None)


def event(name, **fields):
    if destination := os.environ.get("METIS_E2E_EVENTS"):
        with _event_lock:
            with Path(destination).open("a", encoding="utf-8") as handle:
                handle.write(json.dumps({"event": name, **fields}) + "\n")


class OfflineProvider(ChatProvider):
    CONFIG_SPEC = ProviderConfigSpec("Metis E2E", copy_keys=("model",))

    def get_chat_model(self, *args, **kwargs):
        raise AssertionError("The inert extension must never request a model")


class Settings(BaseModel):
    _lock: object = PrivateAttr(default_factory=Lock)
    value: int = 3
    factor: int = 1
    status: Literal["ok", "inconclusive"] = "ok"

    model_config = ConfigDict(extra="forbid", frozen=True)


def seed_stage():
    event("stage_contract", stage="e2e_seed")
    return StageRegistration("e2e_seed", StageContract({}))


collect_stage = StageRegistration(
    "e2e_collect",
    StageContract(
        {"seed": Annotated[int, Field(gt=0)]},
        {"total": Annotated[int, Field(gt=0)]},
    ),
)
faults_stage = StageRegistration("e2e_faults", StageContract({}))
wait_stage = StageRegistration("e2e_wait", StageContract({}))


def seed(invocation):
    with invocation.configuration._lock:
        event("seed")
        return NodeResult({"seed": invocation.configuration.value})


def multiply(invocation):
    value = invocation.inputs["seed"] * invocation.configuration.factor
    event("multiply", value=value)
    return NodeResult({"value": value})


def join(invocation):
    values = invocation.inputs["values"]
    event("join", values=values)
    return NodeResult({"total": sum(values)})


def findings(invocation):
    request = invocation.inputs["request"]
    event("review", mode=request.mode, target=request.target)
    return {
        "formats": ("json", "sarif"),
        "findings": StandardReviewResult.model_validate(
            {
                "reviews": [
                    {
                        "file": "fixture.txt",
                        "reviews": [
                            {"id": "e2e-1", "issue": "Inert extension fixture"}
                        ],
                    }
                ]
            }
        ),
    }


def review(invocation):
    payload = findings(invocation)
    payload["filename"] = invocation.filename
    payload["sarif"] = SarifPayload.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "Metis E2E"}},
                    "results": [{"message": {"text": "Inert extension fixture"}}],
                }
            ],
        }
    )
    status = ExecutionStatus(invocation.configuration.status)
    if invocation.context.callbacks.resume is not None:
        event("resume", records=invocation.context.callbacks.resume("e2e_result"))
    if invocation.context.callbacks.checkpoint is not None:
        invocation.context.callbacks.checkpoint(
            {
                "metis_version": __version__,
                "producer": "e2e_result",
                "key": "fixture",
                "record": {"completed": True},
            },
            1,
            1,
        )
    diagnostics = (
        (ExecutionDiagnostic("e2e.warning", "Inert extension warning", "warning"),)
        if status is ExecutionStatus.INCONCLUSIVE
        else ()
    )
    return NodeResult(payload, status, diagnostics)


def fail(invocation):
    event("failure")
    return NodeResult(
        {},
        ExecutionStatus.ERROR,
        (ExecutionDiagnostic("e2e.failure", "Deliberate fixture failure"),),
    )


seed_node = NodeRegistration("seed", "e2e_seed", Settings, {}, {"seed": int}, seed)
left_node = NodeRegistration(
    "left", "e2e_collect", Settings, {"seed": int}, {"value": int}, multiply
)
right_node = NodeRegistration(
    "right", "e2e_collect", Settings, {"seed": int}, {"value": int}, multiply
)
join_node = NodeRegistration(
    "join",
    "e2e_collect",
    EmptyNodeConfiguration,
    {"values": tuple[int, ...]},
    {"total": int},
    join,
)
review_node = NodeRegistration(
    "e2e_result",
    "review",
    Settings,
    {"request": ReviewCommand},
    {
        "formats": tuple[Literal["json", "sarif"], ...],
        "findings": StandardReviewResult,
        "sarif": SarifPayload,
        "filename": str | None,
    },
    review,
)
findings_node = NodeRegistration(
    "e2e_findings",
    "review",
    EmptyNodeConfiguration,
    {"request": ReviewCommand},
    {"formats": tuple[Literal["json", "sarif"], ...], "findings": StandardReviewResult},
    lambda invocation: NodeResult(findings(invocation)),
)
sarif_failure_node = NodeRegistration(
    "e2e_sarif_failure",
    "review",
    EmptyNodeConfiguration,
    {},
    {"sarif": SarifPayload},
    fail,
)
good_node = NodeRegistration(
    "good",
    "e2e_faults",
    EmptyNodeConfiguration,
    {},
    {"value": int},
    lambda invocation: event("good") or NodeResult({"value": 7}),
)
bad_node = NodeRegistration(
    "bad", "e2e_faults", EmptyNodeConfiguration, {}, {"value": int}, fail
)


class Resource:
    def __init__(self):
        self.closed = False
        self.condition = Condition()
        self.finish_work = Event()
        self.finish_work.set()
        self.active = {"node": 0, "job": 0}
        self.peak = {"node": 0, "job": 0}
        self.started = {"node": 0, "job": 0}
        self.threads = {"node": set(), "job": set()}
        self.tags = {"node": set(), "job": set()}
        self.on_work = None
        event("resource_created")

    def use(self):
        with self.condition:
            assert not self.closed, "handler used an already closed capability"

    @contextmanager
    def hold(self, kind):
        with self.condition:
            self.use()
            self.active[kind] += 1
            self.peak[kind] = max(self.peak[kind], self.active[kind])
            self.started[kind] += 1
            self.threads[kind].add(get_ident())
            self.tags[kind].add(execution_tag.get())
            self.condition.notify_all()
        try:
            yield
        finally:
            with self.condition:
                self.use()
                self.active[kind] -= 1
                self.condition.notify_all()

    def close(self):
        with self.condition:
            assert not self.closed, "capability closed more than once"
            assert not any(self.active.values()), (
                "capability closed before work drained"
            )
            self.closed = True
            event("resource_closed")


resource_capability = CapabilityRegistration(
    CapabilityManifest("e2e_resource"),
    EmptyNodeConfiguration,
    lambda context, configuration: Resource(),
    close=lambda resource: resource.close(),
)


def wait_for_cancellation(invocation):
    resource = invocation.context.capabilities["e2e_resource"]

    def worker(number):
        event("job_started", number=number)
        deadline = monotonic() + 10
        try:
            while not invocation.context.runtime.is_cancelled():
                resource.use()
                if monotonic() > deadline:
                    raise AssertionError("cooperative worker was never cancelled")
                sleep(0.01)
        finally:
            resource.use()
            event("job_finished", number=number)
        return number

    return NodeResult(
        {
            "values": tuple(
                invocation.context.jobs.run(
                    tuple(range(8)), worker, label="e2e", result_key=str
                )
            )
        }
    )


wait_node = NodeRegistration(
    "wait",
    "e2e_wait",
    EmptyNodeConfiguration,
    {},
    {"values": tuple[int, ...]},
    wait_for_cancellation,
    {"e2e_resource": CapabilityRequirement.REQUIRED},
)


class NativePayload(BaseModel):
    data: bytes


native_node = NodeRegistration(
    "native",
    "e2e_faults",
    EmptyNodeConfiguration,
    {},
    {"value": NativePayload},
    lambda invocation: NodeResult({"value": NativePayload(data=b"\xff")}),
)


pool_stage = StageRegistration("e2e_pool", StageContract({}))


def pool_work(invocation):
    resource = invocation.context.capabilities["e2e_resource"]

    def worker(number):
        with resource.hold("job"):
            if resource.on_work is not None:
                resource.on_work()
            deadline = monotonic() + 5
            while not resource.finish_work.wait(0.01):
                resource.use()
                if invocation.context.runtime.is_cancelled():
                    break
                assert monotonic() < deadline, "work was neither released nor cancelled"
            return number

    with resource.hold("node"):
        return NodeResult(
            {
                "values": tuple(
                    invocation.context.jobs.run(
                        (0, 1, 2), worker, label=None, result_key=str
                    )
                )
            }
        )


pool_left_node = NodeRegistration(
    "left",
    "e2e_pool",
    EmptyNodeConfiguration,
    {},
    {"values": tuple[int, ...]},
    pool_work,
    {"e2e_resource": CapabilityRequirement.REQUIRED},
)
pool_right_node = NodeRegistration(
    "right",
    "e2e_pool",
    EmptyNodeConfiguration,
    {},
    {"values": tuple[int, ...]},
    pool_work,
    {"e2e_resource": CapabilityRequirement.REQUIRED},
)

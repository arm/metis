# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from collections.abc import Callable
from collections.abc import Mapping
from collections.abc import Sequence
from concurrent.futures import CancelledError
from dataclasses import dataclass
from dataclasses import field
from dataclasses import is_dataclass
from dataclasses import replace
from enum import Enum
from operator import getitem
from threading import Event
from types import MappingProxyType
from types import UnionType
from typing import TYPE_CHECKING
from typing import Any
from typing import Annotated
from typing import Literal
from typing import NewType
from typing import ParamSpec
from typing import Protocol
from typing import TypeAlias
from typing import TypeAliasType
from typing import TypeVarTuple
from typing import Unpack
from typing import Union
from typing import get_args
from typing import get_origin

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import InstanceOf
from pydantic import PydanticUserError
from pydantic import TypeAdapter
from pydantic_core import SchemaValidator
from pydantic_core import core_schema

from metis.engine.codegraph import CodeGraph
from metis.engine.codegraph import CodeGraphDiagnostic
from metis.engine.codegraph import CodeGraphReference
from metis.engine.llm_runner import JsonPromptRequest
from metis.utils import count_tokens

if TYPE_CHECKING:
    from metis.engine.source import ProfiledSourceArtifact
    from metis.engine.stages.triage.contracts import TriageAdjudicator

StageName: TypeAlias = str
BUILTIN_STAGE_NAMES: tuple[StageName, ...] = ("initialize", "review", "triage")
ResultFormat = Literal["sarif", "json", "html", "csv"]
NodeHandler = Callable[["NodeInvocation"], "NodeResult"]


def annotation_members(
    annotation: Any, _aliases: tuple[Any, ...] = ()
) -> tuple[Any, ...]:
    if annotation is None:
        annotation = type(None)
    if isinstance(annotation, TypeAliasType):
        if annotation in _aliases:
            return ()
        return annotation_members(annotation.__value__, (*_aliases, annotation))
    origin = get_origin(annotation)
    if isinstance(origin, TypeAliasType):
        if annotation in _aliases:
            return ()
        return annotation_members(_alias_value(annotation), (*_aliases, annotation))
    if get_origin(annotation) is Annotated:
        return annotation_members(get_args(annotation)[0], _aliases)
    if get_origin(annotation) in {Union, UnionType}:
        return tuple(
            member
            for argument in get_args(annotation)
            for member in annotation_members(argument, _aliases)
        )
    return (annotation,)


def _alias_value(annotation: Any) -> Any:
    origin = get_origin(annotation)
    if origin is None:
        return annotation.__value__
    # Python substitutes declaration-order, unused and variadic parameters.
    parameters = tuple(
        Unpack[parameter] if isinstance(parameter, TypeVarTuple) else parameter
        for parameter in origin.__type_params__
    )
    bound = tuple.__class_getitem__((*parameters, origin.__value__))[
        get_args(annotation)
    ]
    return get_args(bound)[-1]


def _concrete_tuple_annotations(annotation: Any) -> Any:
    recursive: set[int] = set()

    def normalize(candidate: Any, aliases: tuple[Any, ...] = ()) -> Any:
        origin = get_origin(candidate)
        if isinstance(candidate, TypeAliasType) or isinstance(origin, TypeAliasType):
            if candidate in aliases:
                recursive.update(map(id, aliases[aliases.index(candidate) :]))
                return candidate
            value = _alias_value(candidate)
            normalized = normalize(value, (*aliases, candidate))
            alias = origin if origin is not None else candidate
            variadic = any(
                isinstance(parameter, TypeVarTuple)
                for parameter in alias.__type_params__
            )
            if normalized != value or variadic:
                if id(candidate) in recursive:
                    raise TypeError(
                        "Recursive tuple unpack annotations are unsupported"
                    )
                return normalized
            return candidate
        if isinstance(candidate, NewType):
            normalized = normalize(candidate.__supertype__, aliases)
            return candidate if normalized == candidate.__supertype__ else normalized
        if origin is None or origin is Literal:
            return candidate
        if origin is Unpack:
            raise TypeError("Tuple unpack must appear inside a tuple annotation")
        arguments = get_args(candidate)
        if origin is Annotated:
            normalized = (normalize(arguments[0], aliases), *arguments[1:])
        elif origin is Callable and len(arguments) == 2:
            parameters, result = arguments
            normalized = (
                [normalize(item, aliases) for item in parameters]
                if isinstance(parameters, list)
                else parameters,
                normalize(result, aliases),
            )
        else:
            expanded: list[Any] = []
            for argument in arguments:
                if origin is tuple and (
                    get_origin(argument) is Unpack
                    or getattr(argument, "__unpacked__", False)
                ):
                    unpacked = (
                        get_args(argument)[0]
                        if get_origin(argument) is Unpack
                        else argument
                    )
                    unpacked = normalize(unpacked, aliases)
                    if get_origin(unpacked) is not tuple:
                        raise TypeError("Tuple unpack must contain a concrete tuple")
                    items = get_args(unpacked)
                    if Ellipsis in items and len(arguments) != 1:
                        raise TypeError(
                            "Mixed variable-length tuple unpack is unsupported"
                        )
                    expanded.extend(items)
                else:
                    expanded.append(normalize(argument, aliases))
            normalized = tuple(expanded)
        if normalized == arguments:
            return candidate
        if origin in (Union, UnionType):
            return Union[normalized]
        if origin is Annotated:
            return getitem(Annotated, normalized)
        if hasattr(candidate, "copy_with"):
            return candidate.copy_with(normalized)
        return origin[normalized]

    return normalize(annotation)


def annotation_allows_none(annotation: Any) -> bool:
    return any(
        member is Any
        or member is type(None)
        or (get_origin(member) is Literal and None in get_args(member))
        for member in annotation_members(annotation)
    )


def collection_item_annotation(annotation: Any) -> Any | None:
    members = tuple(
        member
        for member in annotation_members(annotation)
        if member is not type(None) and member != Literal[None]
    )
    if len(members) == 1 and get_origin(members[0]) is tuple:
        arguments = get_args(members[0])
        if len(arguments) == 2 and arguments[1] is Ellipsis:
            return type(None) if arguments[0] is None else arguments[0]
    return None


def annotation_adapter(annotation: Any) -> SchemaValidator:
    # arbitrary_types_allowed also accepts arbitrary *values* as unchecked Any.
    # Reject those before Pydantic builds a permissive schema for a malformed port.
    pending: list[tuple[Any, frozenset[int]]] = [(annotation, frozenset())]
    seen: set[tuple[int, frozenset[int]]] = set()
    while pending:
        candidate, bound_parameters = pending.pop()
        key = (id(candidate), bound_parameters)
        if key in seen or id(candidate) in bound_parameters:
            continue
        seen.add(key)
        if candidate is None or isinstance(candidate, type):
            continue
        if isinstance(candidate, TypeAliasType):
            pending.append((candidate.__value__, bound_parameters))
            continue
        if isinstance(candidate, NewType):
            pending.append((candidate.__supertype__, bound_parameters))
            continue
        origin = get_origin(candidate)
        if origin is None or isinstance(origin, ParamSpec):
            raise TypeError(f"Expected a concrete port type, got {candidate!r}")
        if origin is Literal:
            continue
        arguments = get_args(candidate)
        if origin is Annotated:
            pending.append((arguments[0], bound_parameters))
            continue
        if isinstance(origin, TypeAliasType):
            parameters = origin.__type_params__
            pending.append(
                (origin.__value__, bound_parameters | frozenset(map(id, parameters)))
            )
            for index, argument in enumerate(arguments):
                if index < len(parameters) and isinstance(parameters[index], ParamSpec):
                    # A ParamSpec supplies a Callable's argument list through an alias.
                    if argument is Ellipsis:
                        continue
                    if isinstance(argument, (list, tuple)):
                        pending.extend((item, bound_parameters) for item in argument)
                        continue
                pending.append((argument, bound_parameters))
            continue
        if origin is Callable and len(arguments) == 2:
            parameters, result = arguments
            pending.append((result, bound_parameters))
            if parameters is not Ellipsis:
                pending.extend(
                    (item, bound_parameters)
                    for item in (
                        parameters if isinstance(parameters, list) else (parameters,)
                    )
                )
            continue
        if origin is tuple and len(arguments) == 2 and arguments[1] is Ellipsis:
            arguments = arguments[:1]
        pending.extend((argument, bound_parameters) for argument in arguments)
    annotation = _concrete_tuple_annotations(annotation)
    try:
        adapter = TypeAdapter(
            annotation, config=ConfigDict(arbitrary_types_allowed=True)
        )
    except PydanticUserError as exc:
        if exc.code != "type-adapter-config-unused":
            raise
        base = (
            get_args(annotation)[0]
            if get_origin(annotation) is Annotated
            else annotation
        )
        if is_dataclass(base):
            instance_annotation = InstanceOf.__class_getitem__(base)
            if base is not annotation:
                instance_annotation = getitem(
                    Annotated, (instance_annotation, *get_args(annotation)[1:])
                )
            adapter = TypeAdapter(instance_annotation)
        else:
            adapter = TypeAdapter(annotation)
    adapter.rebuild(raise_errors=True)
    return SchemaValidator(_strict_port_schema(adapter.core_schema))


def _strict_port_schema(schema: Any) -> Any:
    # Work on Pydantic's resolved schema, including generic/recursive definitions.
    # Copy schema structures only; defaults, metadata and cached model schemas stay intact.
    if isinstance(schema, list):
        return [_strict_port_schema(item) for item in schema]
    if isinstance(schema, tuple):
        return tuple(_strict_port_schema(item) for item in schema)
    if not isinstance(schema, dict):
        return schema
    inner = schema
    while inner.get("type") in ("function-before", "function-after", "function-wrap"):
        inner = inner["schema"]
    guard: core_schema.CoreSchema
    if inner.get("type") == "model":
        guard = core_schema.is_instance_schema(
            inner["cls"], cls_repr=inner["cls"].__name__
        )
    elif schema.get("type") == "float":
        guard = core_schema.is_instance_schema(float)
    elif schema.get("type") == "literal":

        def exact_literal(value: object) -> object:
            if not any(
                type(value) is type(expected) and value == expected
                for expected in schema["expected"]
            ):
                raise ValueError("literal type and value must match")
            return value

        guard = core_schema.no_info_plain_validator_function(exact_literal)
    else:
        return {
            key: value
            if isinstance(schema.get("type"), str)
            and key
            in {
                "metadata",
                "config",
                "serialization",
                "default",
                "expected",
                "function",
            }
            else _strict_port_schema(value)
            for key, value in schema.items()
        }
    original = dict(schema)
    # References must resolve to the guarded branch, including recursive model ports.
    reference = original.pop("ref", None)
    return core_schema.chain_schema([guard, original], ref=reference)


class NodeRepository(Protocol):
    @property
    def profiled_source_fingerprint(self) -> str | None: ...

    def get_code_files(
        self,
        *,
        include_suffixed_sources: bool = False,
        dir_path: str | None = None,
    ) -> list[str]: ...

    def get_language_name_for_path(self, path: str) -> str | None: ...

    def source_profile_applies_to_path(self, path: str) -> bool: ...

    def install_profiled_source(self, artifact: ProfiledSourceArtifact) -> None: ...


class NodePromptRunner(Protocol):
    def invoke(self, request: JsonPromptRequest) -> object: ...


class NodeCodeGraphs(Protocol):
    def materialize(
        self,
        *,
        progress_callback: Callable[[dict[str, object]], None] | None = None,
        diagnostic_callback: Callable[[CodeGraphDiagnostic], None] | None = None,
    ) -> CodeGraphReference: ...

    def load(self, reference: CodeGraphReference) -> CodeGraph: ...


class NodeJobs(Protocol):
    """Bounded jobs; child cancellation inherits parents without cancelling them.

    with_cancellation binds the supplied Event; cancel must set that Event and
    discard queued work. run drains active work before returning or raising.
    """

    def limit(self, max_concurrency: int) -> "NodeJobs": ...

    def with_cancellation(self, cancellation: Event) -> "NodeJobs": ...

    def cancel(self) -> None: ...

    def run[JobT, ResultT](
        self,
        jobs: Sequence[JobT],
        worker: Callable[[JobT], ResultT],
        *,
        label: str | None,
        result_key: Callable[[JobT], object],
        on_complete: Callable[[JobT, int, int], None] | None = None,
    ) -> list[ResultT]: ...


class EmptyNodeConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class ExecutionStatus(str, Enum):
    OK = "ok"
    INCONCLUSIVE = "inconclusive"
    ERROR = "error"


class CapabilityRequirement(str, Enum):
    REQUIRED = "required"
    OPTIONAL = "optional"


@dataclass(frozen=True, slots=True)
class ExecutionDiagnostic:
    code: str
    message: str
    severity: Literal["warning", "error"] = "error"


ProgressCallback = Callable[[Mapping[str, object]], None]
DebugCallback = Callable[[Mapping[str, object]], None]
CheckpointCallback = Callable[[dict[str, Any], int, int], None]
ResumeCallback = Callable[[str], Mapping[str, Mapping[str, Any]] | None]
DiagnosticCallback = Callable[[ExecutionDiagnostic], None]


@dataclass(frozen=True, slots=True)
class NodeCallbacks:
    """Inline callbacks; only progress is serialized within one execution.

    Callers synchronize other callbacks and callbacks shared across executions.
    """

    progress: ProgressCallback | None = None
    debug: DebugCallback | None = None
    checkpoint: CheckpointCallback | None = None
    resume: ResumeCallback | None = None
    diagnostic: DiagnosticCallback | None = None


def _not_cancelled() -> bool:
    return False


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    status: ExecutionStatus
    outputs: Mapping[str, Any]
    diagnostics: tuple[ExecutionDiagnostic, ...] = ()


@dataclass(frozen=True, slots=True)
class NodeRuntime:
    model: str
    max_workers: int
    max_token_length: int
    chat_model_kwargs: Mapping[str, object]
    model_tool_max_rounds: int = 0
    token_counter: Callable[[str], int] = count_tokens
    token_counter_for_model: Callable[[str], Callable[[str], int]] | None = None
    jobs: NodeJobs | None = None
    is_cancelled: Callable[[], bool] = _not_cancelled

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "chat_model_kwargs",
            MappingProxyType(dict(self.chat_model_kwargs)),
        )

    def _with_cancellation(self) -> NodeRuntime:
        """Own a child signal shared by the runtime and its job handle."""
        if self.jobs is None:
            raise RuntimeError("Node job scheduler is unavailable")
        cancellation = Event()

        def is_cancelled() -> bool:
            return cancellation.is_set() or self.is_cancelled()

        return replace(
            self,
            jobs=self.jobs.with_cancellation(cancellation),
            is_cancelled=is_cancelled,
        )


@dataclass(frozen=True, slots=True)
class NodeContext:
    stage: StageName
    codebase_path: str
    repository: NodeRepository
    capabilities: Mapping[str, object]
    prompts: NodePromptRunner
    codegraphs: NodeCodeGraphs
    runtime: NodeRuntime
    callbacks: NodeCallbacks
    triage: TriageAdjudicator | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "capabilities",
            MappingProxyType(dict(self.capabilities)),
        )

    @property
    def jobs(self) -> NodeJobs:
        if self.runtime.jobs is None:
            raise RuntimeError("Node job scheduler is unavailable")
        return self.runtime.jobs

    def report_progress(self, event: Mapping[str, object]) -> None:
        if self.runtime.is_cancelled():
            raise CancelledError("Execution stage was cancelled")
        if self.callbacks.progress is not None:
            self.callbacks.progress(event)


@dataclass(frozen=True, slots=True)
class NodeInvocation:
    configuration: BaseModel
    inputs: Mapping[str, object]
    context: NodeContext
    formats: tuple[ResultFormat, ...] | None = None
    filename: str | None = None


@dataclass(frozen=True, slots=True)
class NodeResult:
    outputs: Mapping[str, object]
    status: ExecutionStatus = ExecutionStatus.OK
    diagnostics: tuple[ExecutionDiagnostic, ...] = ()


@dataclass(frozen=True, slots=True)
class NodeRegistration:
    name: str
    stage: StageName
    configuration: type[BaseModel]
    inputs: Mapping[str, Any]
    outputs: Mapping[str, Any]
    execute: NodeHandler
    capabilities: Mapping[str, CapabilityRequirement] = field(default_factory=dict)
    # Nullable inputs can still require a configured producer to finish successfully.
    required_when_bound: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise ValueError("Execution node name must not be empty")
        if not self.name.isidentifier():
            raise ValueError(f"Execution node name {self.name!r} must be an identifier")
        if (
            not isinstance(self.stage, str)
            or not self.stage
            or not self.stage.isidentifier()
        ):
            raise ValueError(f"Invalid execution stage: {self.stage!r}")
        if not isinstance(self.configuration, type) or not issubclass(
            self.configuration, BaseModel
        ):
            raise TypeError("Execution node configuration must be a Pydantic model")
        if not callable(self.execute):
            raise TypeError(f"Execution node {self.name!r} handler is not callable")
        if not all(
            isinstance(ports, Mapping)
            for ports in (self.inputs, self.outputs, self.capabilities)
        ):
            raise TypeError(
                "Execution node inputs, outputs and capabilities must be mappings"
            )
        for port in (*self.inputs, *self.outputs):
            if not isinstance(port, str) or not port.isidentifier():
                raise ValueError(
                    f"Execution node {self.name!r} has invalid port {port!r}"
                )
        for port, annotation in (*self.inputs.items(), *self.outputs.items()):
            try:
                annotation_adapter(annotation)
            except Exception as exc:
                raise TypeError(
                    f"Execution node {self.name!r} port {port!r} has an unsupported "
                    f"annotation: {annotation!r}"
                ) from exc
        if isinstance(self.required_when_bound, (str, bytes)):
            raise TypeError("Required-when-bound ports must be a collection of names")
        required_when_bound = frozenset(self.required_when_bound)
        if not required_when_bound <= self.inputs.keys():
            raise ValueError("Required-when-bound ports must be declared node inputs")
        object.__setattr__(self, "required_when_bound", required_when_bound)
        for capability, requirement in self.capabilities.items():
            if not isinstance(capability, str) or not capability.isidentifier():
                raise ValueError(
                    f"Execution node {self.name!r} has invalid capability "
                    f"{capability!r}"
                )
            if not isinstance(requirement, CapabilityRequirement):
                raise TypeError(
                    f"Execution node {self.name!r} capability {capability!r} has "
                    f"invalid requirement {requirement!r}"
                )
        object.__setattr__(self, "inputs", MappingProxyType(dict(self.inputs)))
        object.__setattr__(self, "outputs", MappingProxyType(dict(self.outputs)))
        object.__setattr__(
            self,
            "capabilities",
            MappingProxyType(dict(self.capabilities)),
        )

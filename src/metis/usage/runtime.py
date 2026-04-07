from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
from threading import Lock
from typing import Any, Iterator

from llama_index.core.callbacks import CallbackManager

from .collector import UsageCollector
from .context import usage_operation, usage_scope
from .langchain import UsageCallbackHandler
from .llamaindex import UsageLlamaIndexHandler


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _safe_label(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "_" for ch in value)


@dataclass(frozen=True)
class UsageCommand:
    scope_id: str
    command_name: str
    display_name: str
    sequence: int
    target: str | None = None


@dataclass(frozen=True)
class UsageHooks:
    callback_manager: CallbackManager
    callbacks: list[Any]

    def embed_model_kwargs(self) -> dict[str, Any]:
        return {"callback_manager": self.callback_manager}

    def chat_model_kwargs(self) -> dict[str, Any]:
        return {"callbacks": self.callbacks}

    def query_engine_kwargs(self) -> dict[str, Any]:
        return {
            "callback_manager": self.callback_manager,
            "callbacks": self.callbacks,
        }


class UsageRuntime:
    def __init__(self, codebase_path: str | Path):
        self.codebase_path = str(codebase_path)
        self.started_at = _utc_now()
        self.collector = UsageCollector()
        self.langchain_handler = UsageCallbackHandler(self.collector)
        self.hooks = UsageHooks(
            callback_manager=CallbackManager([UsageLlamaIndexHandler(self.collector)]),
            callbacks=[self.langchain_handler],
        )
        self._lock = Lock()
        self._command_sequence = 0
        self._completed_commands: list[dict[str, Any]] = []

    @property
    def langchain_callbacks(self) -> list[Any]:
        return self.hooks.callbacks

    @property
    def llamaindex_callback_manager(self) -> CallbackManager:
        return self.hooks.callback_manager

    def snapshot_total(self) -> dict[str, Any]:
        return self.collector.snapshot()

    def snapshot_scope(self, scope_id: str) -> dict[str, Any]:
        return self.collector.snapshot_scope(scope_id)

    def has_usage(self) -> bool:
        return self.snapshot_total().get("total_tokens", 0) > 0 or bool(
            self._completed_commands
        )

    @contextmanager
    def command(
        self,
        command_name: str,
        target: str | None = None,
        display_name: str | None = None,
    ) -> Iterator[UsageCommand]:
        with self._lock:
            self._command_sequence += 1
            sequence = self._command_sequence

        display = display_name or command_name
        scope_parts = [_safe_label(command_name), str(sequence)]
        if target:
            scope_parts.append(_safe_label(Path(target).name))
        scope_id = ":".join(scope_parts)
        command = UsageCommand(
            scope_id=scope_id,
            command_name=command_name,
            display_name=display,
            sequence=sequence,
            target=target,
        )

        with usage_scope(scope_id), usage_operation(command_name):
            yield command

    def finalize_command(self, command: UsageCommand) -> dict[str, Any]:
        current = self.snapshot_scope(command.scope_id)
        totals = self.snapshot_total()
        record = {
            "scope_id": command.scope_id,
            "command_name": command.command_name,
            "display_name": command.display_name,
            "sequence": command.sequence,
            "target": command.target,
            "summary": current,
            "cumulative": totals,
            "completed_at": _utc_now(),
        }
        with self._lock:
            self._completed_commands.append(record)
        return record

    def completed_commands(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._completed_commands)

    def default_output_path(self) -> str:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        return str(Path("results") / f"metis_usage_{timestamp}.json")

    def build_persisted_payload(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "project_name": Path(self.codebase_path).resolve().name,
            "codebase_path": str(Path(self.codebase_path).resolve()),
            "started_at": self.started_at,
            "ended_at": _utc_now(),
            "totals": self.snapshot_total(),
            "commands": self.completed_commands(),
        }

    def save_run_summary(self, output_path: str | None = None) -> str:
        target = Path(output_path or self.default_output_path())
        payload = self.build_persisted_payload()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return str(target)

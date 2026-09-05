# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

"""Offline integration checks using a separately built, discovered extension wheel."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from textwrap import dedent
from zipfile import ZipFile

import pytest
import yaml


@pytest.fixture(scope="session")
def installed_execution_extension(tmp_path_factory):
    """Build once; Python imports this purelib wheel and its real entry-point metadata."""
    directory = tmp_path_factory.mktemp("execution-extension")
    project = directory / "project"
    shutil.copytree(Path(__file__).parent / "fixtures" / "execution_extension", project)
    wheels = directory / "wheels"
    wheels.mkdir()
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; from setuptools.build_meta import build_wheel; build_wheel(sys.argv[1])",
            str(wheels),
        ],
        cwd=project,
        env=extension_environment(project),
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    (wheel,) = wheels.glob("*.whl")
    with ZipFile(wheel) as archive:
        metadata = archive.read("metis_execution_e2e-0.0.1.dist-info/WHEEL").decode()
        assert "Root-Is-Purelib: true" in metadata
    return wheel


def extension_environment(installation, **extra_env):
    environment = {
        name: os.environ[name]
        for name in (
            "PATH",
            "SYSTEMROOT",
            "WINDIR",
            "TEMP",
            "TMP",
            "TMPDIR",
            "LANG",
            "LC_ALL",
        )
        if name in os.environ
    }
    source = Path(__file__).resolve().parents[1] / "src"
    environment["PYTHONPATH"] = os.pathsep.join((str(installation), str(source)))
    environment["PYTHONUNBUFFERED"] = "1"
    environment.update({name: str(value) for name, value in extra_env.items()})
    return environment


def test_extension_subprocesses_do_not_inherit_credentials(monkeypatch, tmp_path):
    names = (
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "AWS_SECRET_ACCESS_KEY",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "CUSTOM_PRIVATE_VALUE",
    )
    for name in names:
        monkeypatch.setenv(name, "not-a-real-credential")
    environment = extension_environment(
        tmp_path / "extension.whl", METIS_E2E_EVENTS=tmp_path / "events.jsonl"
    )
    assert not set(names).intersection(environment)
    assert environment["METIS_E2E_EVENTS"] == str(tmp_path / "events.jsonl")


def write_execution_config(path, execution, *, workers=2, **engine_settings):
    path.write_text(
        yaml.safe_dump(
            {
                "llm_provider": {"name": "metis_e2e", "model": "offline"},
                "query": {"model": "offline"},
                "metis_engine": {
                    "max_workers": workers,
                    **engine_settings,
                    "review_checkpoints": False,
                    "capabilities": {"e2e_resource": {}},
                    "execution": execution,
                },
            }
        ),
        encoding="utf-8",
    )
    return path


def extension_graph(*, fail=False):
    review = {
        "depends_on": ["e2e_collect"],
        "outputs": {
            name: f"e2e_result.{name}" for name in ("formats", "findings", "sarif")
        },
        "nodes": {"e2e_result": {}},
    }
    if fail:
        review["outputs"] = {
            "formats": "e2e_findings.formats",
            "findings": "e2e_findings.findings",
            "sarif": "e2e_sarif_failure.sarif",
        }
        review["nodes"] = {"e2e_findings": {}, "e2e_sarif_failure": {}}
    node_configuration = {
        "e2e_seed": {"seed": {"value": 3}},
        "e2e_collect": {"left": {"factor": 1}, "right": {"factor": 2}},
    }
    return {
        "inputs": {"review_request": {"mode": "code"}},
        "stages": {
            "review": review,
            "e2e_collect": {
                "inputs": {"seed": "e2e_seed.seed"},
                "outputs": {"total": "join.total"},
                "nodes": {
                    "left": {},
                    "right": {},
                    "join": {"inputs": {"values": ["right.value", "left.value"]}},
                },
            },
            "e2e_seed": {"outputs": {"seed": "seed.seed"}, "nodes": {"seed": {}}},
        },
        "node_configuration": node_configuration,
    }


_ENGINE_SETUP = """
from importlib import metadata
import json
from pathlib import Path
import sys
from metis.configuration import load_runtime_config
from metis.engine import MetisEngine, ExecutionGraphError
from metis.providers.registry import get_chat_provider
assert metadata.version("metis-execution-e2e") == "0.0.1"
assert str(metadata.distribution("metis-execution-e2e").locate_file("")).endswith(".whl/")
runtime = load_runtime_config(sys.argv[1])
provider = get_chat_provider(runtime.pop("llm_provider_name"))(runtime.pop("llm_provider"))
engine = MetisEngine(codebase_path=sys.argv[2], llm_provider=provider, **runtime)
"""


def _run_engine(installation, directory, config, script, *, timeout=20):
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            dedent(_ENGINE_SETUP) + dedent(script),
            str(config),
            str(directory),
        ],
        cwd=directory,
        env=extension_environment(
            installation, METIS_E2E_EVENTS=directory / "events.jsonl"
        ),
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    return [
        json.loads(line)
        for line in (directory / "events.jsonl").read_text().splitlines()
    ]


@pytest.mark.parametrize(
    "direct_review", [False, True], ids=["whole-graph", "direct-review"]
)
def test_installed_extension_yaml_runs_transitive_stages_and_typed_fanin(
    installed_execution_extension,
    tmp_path,
    direct_review,
):
    execution = extension_graph()
    if direct_review:
        execution["stages"]["e2e_faults"] = {
            "outputs": {"value": "good.value"},
            "nodes": {"good": {}},
        }
    config = write_execution_config(tmp_path / "metis.yaml", execution)
    invocation = (
        'engine.execute_review("file", target="supplied.txt")'
        if direct_review
        else "engine.execute_graph().outputs"
    )
    events = _run_engine(
        installed_execution_extension,
        tmp_path,
        config,
        f"""
try:
    output = {invocation}
    Path(sys.argv[2], "artifact.json").write_text(json.dumps(output), encoding="utf-8")
finally:
    engine.close()
""",
    )
    output = json.loads((tmp_path / "artifact.json").read_text())
    review = output if direct_review else output["review"]
    assert (
        review["sarif"]["runs"][0]["results"][0]["message"]["text"]
        == "Inert extension fixture"
    )
    names = [item["event"] for item in events]
    assert names.count("stage_contract") == 1
    assert names.index("seed") < names.index("join") < names.index("review")
    assert next(item["values"] for item in events if item["event"] == "join") == [6, 3]
    assert "good" not in names
    assert next(item["target"] for item in events if item["event"] == "review") == (
        "supplied.txt" if direct_review else None
    )
    if not direct_review:
        assert output["e2e_collect"] == {"total": 9}


def test_installed_extension_keeps_partial_outputs_in_public_error(
    installed_execution_extension,
    tmp_path,
):
    config = write_execution_config(tmp_path / "metis.yaml", extension_graph(fail=True))
    events = _run_engine(
        installed_execution_extension,
        tmp_path,
        config,
        """
try:
    try:
        engine.execute_graph()
    except ExecutionGraphError as failure:
        assert failure.result.status.value == "error"
        assert any(item.code == "e2e.failure" for item in failure.result.diagnostics)
        Path(sys.argv[2], "partial.json").write_text(json.dumps(failure.result.outputs), encoding="utf-8")
    else:
        raise AssertionError("The failing extension was reported as successful")
finally:
    engine.close()
""",
    )
    output = json.loads((tmp_path / "partial.json").read_text())
    assert output["e2e_collect"] == {"total": 9}
    assert output["review"]["findings"]["reviews"][0]["reviews"][0]["id"] == "e2e-1"
    assert "sarif" not in output["review"]
    assert any(event["event"] == "failure" for event in events)


@pytest.mark.parametrize("boundary", ("input", "output"))
def test_installed_stage_constraints_reject_invalid_values_and_keep_valid_outputs(
    installed_execution_extension, tmp_path, boundary
):
    execution = extension_graph()
    execution["stages"]["e2e_collect"]["outputs"]["independent"] = "left.value"
    if boundary == "input":
        execution["node_configuration"]["e2e_seed"]["seed"]["value"] = -1
    else:
        execution["node_configuration"]["e2e_collect"]["right"]["factor"] = -2
    config = write_execution_config(tmp_path / "metis.yaml", execution)
    events = _run_engine(
        installed_execution_extension,
        tmp_path,
        config,
        f"""
try:
    try:
        engine.execute_graph()
    except ExecutionGraphError as failure:
        assert failure.result.status.value == "error"
        assert any(item.code == "execution.stage_{boundary}_invalid" for item in failure.result.diagnostics)
        Path(sys.argv[2], "partial.json").write_text(json.dumps(failure.result.outputs), encoding="utf-8")
    else:
        raise AssertionError("The invalid stage value was accepted")
finally:
    engine.close()
""",
    )
    output = json.loads((tmp_path / "partial.json").read_text())
    names = [item["event"] for item in events]
    assert "review" not in names
    if boundary == "input":
        assert output == {"e2e_seed": {"seed": -1}}
        assert "multiply" not in names
    else:
        assert output == {
            "e2e_seed": {"seed": 3},
            "e2e_collect": {"independent": 3},
        }
        assert "join" in names


def test_installed_extension_close_cancels_queued_work_before_capability_cleanup(
    installed_execution_extension,
    tmp_path,
):
    config = write_execution_config(
        tmp_path / "metis.yaml",
        {
            "stages": {
                "e2e_wait": {
                    "outputs": {"values": "wait.values"},
                    "nodes": {"wait": {"capabilities": ["e2e_resource"]}},
                }
            }
        },
        workers=1,
    )
    events = _run_engine(
        installed_execution_extension,
        tmp_path,
        config,
        """
from concurrent.futures import CancelledError
from threading import Thread
from time import monotonic, sleep
outcomes = []
def execute():
    try:
        outcomes.append(engine.execute_graph())
    except BaseException as error:
        outcomes.append(error)
thread = Thread(target=execute)
thread.start()
events = Path(sys.argv[2], "events.jsonl")
try:
    deadline = monotonic() + 5
    while not events.exists() or '"event": "job_started"' not in events.read_text():
        assert not outcomes, outcomes
        assert monotonic() < deadline, "Worker did not start"
        sleep(0.01)
    engine.close()
    thread.join(timeout=5)
    assert not thread.is_alive(), "Close left an execution thread alive"
    assert len(outcomes) == 1 and isinstance(outcomes[0], CancelledError), outcomes
    try:
        engine.execute_graph()
    except RuntimeError as error:
        assert "closed" in str(error).lower()
    else:
        raise AssertionError("Execution after close was accepted")
finally:
    engine.close()
    thread.join(timeout=5)
""",
        timeout=20,
    )
    names = [item["event"] for item in events]
    assert names.count("job_started") == 1
    assert names.count("job_finished") == 1
    assert names.count("resource_closed") == 1
    assert names.index("job_finished") < names.index("resource_closed")


def test_completed_execution_context_can_close_public_engine(
    installed_execution_extension,
    tmp_path,
):
    config = write_execution_config(tmp_path / "metis.yaml", extension_graph())
    _run_engine(
        installed_execution_extension,
        tmp_path,
        config,
        """
from contextvars import copy_context
saved = []
def capture(event):
    if event.get("event") == "execution_node_start":
        saved.append(copy_context())
try:
    engine.execute_graph(callbacks={"progress_callback": capture})
    assert saved, "No node callback was observed"
    saved[-1].run(engine.close)
finally:
    engine.close()
""",
    )


def test_nested_public_engine_rejects_closing_active_ancestor(
    installed_execution_extension,
    tmp_path,
):
    config = write_execution_config(tmp_path / "metis.yaml", extension_graph())
    _run_engine(
        installed_execution_extension,
        tmp_path,
        config,
        """
inner = MetisEngine(codebase_path=sys.argv[2], llm_provider=provider, **runtime)
seen = []
def close_ancestor(event):
    if event.get("event") == "execution_stage_start" and not seen:
        try:
            engine.close()
        except RuntimeError as error:
            assert "active execution" in str(error)
            seen.append("rejected")
        else:
            raise AssertionError("Nested callback closed its active ancestor")
def execute_inner(event):
    if event.get("event") == "execution_node_start" and event.get("node") == "seed":
        assert inner.execute_graph(callbacks={"progress_callback": close_ancestor}).status.value == "ok"
try:
    assert engine.execute_graph(callbacks={"progress_callback": execute_inner}).status.value == "ok"
    assert seen == ["rejected"]
finally:
    inner.close()
    engine.close()
""",
    )


def test_installed_extension_keeps_native_partial_values_in_public_error(
    installed_execution_extension, tmp_path
):
    config = write_execution_config(
        tmp_path / "metis.yaml",
        {
            "stages": {
                "e2e_faults": {
                    "outputs": {"native": "native.value", "failed": "bad.value"},
                    "nodes": {"native": {}, "bad": {}},
                }
            }
        },
    )
    _run_engine(
        installed_execution_extension,
        tmp_path,
        config,
        """
from metis_e2e_extension import NativePayload
try:
    try:
        engine.execute_graph()
    except ExecutionGraphError as failure:
        assert failure.result.status.value == "error"
        assert any(item.code == "e2e.failure" for item in failure.result.diagnostics)
        partial = failure.result.outputs["e2e_faults"]
        assert isinstance(partial["native"], NativePayload)
        assert partial["native"].data == bytes([255])
        assert "failed" not in partial
    else:
        raise AssertionError("Native partial output hid the execution failure")
finally:
    engine.close()
""",
    )


def test_public_engine_close_during_final_stage_callback_propagates_cancellation(
    installed_execution_extension, tmp_path
):
    config = write_execution_config(tmp_path / "metis.yaml", extension_graph())
    _run_engine(
        installed_execution_extension,
        tmp_path,
        config,
        """
from concurrent.futures import CancelledError
from threading import Thread
closers = []
errors = []
def close():
    try:
        engine.close()
    except BaseException as error:
        errors.append(error)
def progress(event):
    if event.get("event") == "execution_stage_end" and event.get("stage") == "review":
        # Observe the real cancellation event to force shutdown before the callback returns.
        cancellation, = engine.execution._active_executions
        closer = Thread(target=close)
        closers.append(closer)
        closer.start()
        assert cancellation.wait(5), "Shutdown never cancelled the active execution"
try:
    try:
        engine.execute_graph(callbacks={"progress_callback": progress})
    except CancelledError:
        pass
    else:
        raise AssertionError("Cancellation during the final stage callback was lost")
finally:
    for closer in closers:
        closer.join(timeout=5)
        assert not closer.is_alive(), "Shutdown left a thread alive"
    engine.close()
assert len(closers) == 1 and not errors, errors
""",
    )


_POOL_GRAPH = {
    "stages": {
        "e2e_pool": {
            "outputs": {"left": "left.values", "right": "right.values"},
            "nodes": {
                "left": {"capabilities": ["e2e_resource"]},
                "right": {"capabilities": ["e2e_resource"]},
            },
        }
    }
}


@pytest.mark.parametrize("workers,nodes,executions", [(1, 3, 2), (4, 1, 3), (2, 2, 1)])
def test_engine_bounds_jobs_nodes_and_graphs_with_shared_extension_capability(
    installed_execution_extension, tmp_path, workers, nodes, executions
):
    config = write_execution_config(
        tmp_path / "metis.yaml",
        _POOL_GRAPH,
        workers=workers,
        max_active_nodes=nodes,
        max_concurrent_executions=executions,
    )
    events = _run_engine(
        installed_execution_extension,
        tmp_path,
        config,
        """
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from metis_e2e_extension import execution_tag
resource = engine.capabilities["e2e_resource"]
resource.finish_work.clear()
graphs = {"active": 0, "peak": 0, "started": 0}
start = Barrier(9, timeout=5)
def progress(event):
    with resource.condition:
        if event["event"] == "execution_stage_start":
            graphs["active"] += 1
            graphs["started"] += 1
            graphs["peak"] = max(graphs["peak"], graphs["active"])
        elif event["event"] == "execution_stage_end":
            graphs["active"] -= 1
        resource.condition.notify_all()
def execute(tag):
    token = execution_tag.set(tag)
    try:
        start.wait()
        return engine.execute_graph(callbacks={"progress_callback": progress})
    finally:
        execution_tag.reset(token)
try:
    with ThreadPoolExecutor(max_workers=8) as callers:
        futures = [callers.submit(execute, tag) for tag in range(8)]
        try:
            start.wait()
            expected_nodes = min(runtime["max_active_nodes"], runtime["max_concurrent_executions"] * 2)
            expected_jobs = min(runtime["max_workers"], expected_nodes * 3)
            with resource.condition:
                assert resource.condition.wait_for(
                    lambda: resource.peak["node"] >= expected_nodes
                    and resource.peak["job"] >= expected_jobs
                    and graphs["started"] >= runtime["max_concurrent_executions"], timeout=5
                ), (resource.peak, graphs)
        finally:
            resource.finish_work.set()
        for future in futures:
            result = future.result(timeout=5)
            assert result.status.value == "ok"
            assert set(result.outputs) == {"e2e_pool"}
            assert {name: sorted(values) for name, values in result.outputs["e2e_pool"].items()} == {"left": [0, 1, 2], "right": [0, 1, 2]}
    assert graphs == {"active": 0, "peak": runtime["max_concurrent_executions"], "started": 8}, graphs
    assert resource.peak == {"node": expected_nodes, "job": expected_jobs}, resource.peak
    assert resource.started == {"node": 16, "job": 48}, resource.started
    assert resource.active == {"node": 0, "job": 0}
    assert resource.tags == {"node": set(range(8)), "job": set(range(8))}, resource.tags
    assert len(resource.threads["node"]) <= runtime["max_active_nodes"]
    assert len(resource.threads["job"]) <= runtime["max_workers"]
    assert resource.threads["node"].isdisjoint(resource.threads["job"])
finally:
    resource.finish_work.set()
    engine.close()
assert resource.closed
""",
    )
    names = [event["event"] for event in events]
    assert names.count("resource_created") == names.count("resource_closed") == 1


def test_engine_close_drains_active_work_and_rejects_waiting_graphs(
    installed_execution_extension, tmp_path
):
    config = write_execution_config(
        tmp_path / "metis.yaml",
        _POOL_GRAPH,
        workers=1,
        max_active_nodes=1,
        max_concurrent_executions=1,
    )
    _run_engine(
        installed_execution_extension,
        tmp_path,
        config,
        """
from concurrent.futures import CancelledError, ThreadPoolExecutor
from threading import Event, Thread, current_thread, enumerate as threads, get_ident
resource = engine.capabilities["e2e_resource"]
job_started = Event()
release_job = Event()
waiters_ready = Event()
waiting = set()
close_errors = []
condition = engine.execution._condition
original_wait = condition.wait

def observed_wait(timeout=None):
    # wait_for holds the real Condition lock here. Close cannot acquire it
    # until this caller enters the original wait and releases the lock.
    if current_thread().name.startswith("graph-caller"):
        waiting.add(get_ident())
        if len(waiting) == 3:
            waiters_ready.set()
    return original_wait(timeout)

condition.wait = observed_wait

def hold_job():
    job_started.set()
    assert release_job.wait(5), "Active job was never released"

resource.on_work = hold_job

def execute():
    try:
        return engine.execute_graph()
    except (CancelledError, RuntimeError) as error:
        return error

def close():
    try:
        engine.close()
    except BaseException as error:
        close_errors.append(error)

closer = Thread(target=close)
try:
    with ThreadPoolExecutor(max_workers=4, thread_name_prefix="graph-caller") as callers:
        active = callers.submit(execute)
        try:
            assert job_started.wait(5), "Active graph never reached its job"
            queued = [callers.submit(execute) for _ in range(3)]
            assert waiters_ready.wait(5), "Three callers never waited for admission"
            closer.start()
            outcomes = [future.result(timeout=5) for future in queued]
            assert all(isinstance(error, RuntimeError) and "closed" in str(error) for error in outcomes), outcomes
            assert not active.done(), "Active graph returned before its job drained"
            assert closer.is_alive(), "Close returned before the active job drained"
            assert not resource.closed, "Capability closed while its job remained active"
        finally:
            release_job.set()
        assert isinstance(active.result(timeout=5), CancelledError)
    closer.join(timeout=5)
    assert not closer.is_alive(), "Close did not finish after its job drained"
    assert not close_errors, close_errors
    assert resource.started == {"node": 1, "job": 1}, resource.started
    assert resource.active == {"node": 0, "job": 0}
    assert resource.closed
    assert not [thread.name for thread in threads() if thread.name.startswith(("metis-node", "metis_"))]
finally:
    release_job.set()
    if closer.ident is not None:
        closer.join(timeout=5)
        assert not closer.is_alive(), "Shutdown left its closer thread alive"
    condition.wait = original_wait
    engine.close()
""",
    )


def test_engine_serializes_progress_under_observed_node_contention(
    installed_execution_extension, tmp_path
):
    config = write_execution_config(
        tmp_path / "metis.yaml",
        _POOL_GRAPH,
        workers=1,
        max_active_nodes=2,
        max_concurrent_executions=1,
    )
    _run_engine(
        installed_execution_extension,
        tmp_path,
        config,
        """
from concurrent.futures import ThreadPoolExecutor
from threading import Event, Lock
import metis.engine.stages.service as service
entered = Event()
attempted = Event()
overlap = Event()
release_callback = Event()
in_callback = Lock()
seen = []
serialized = service.serialized_progress_callback

class ObservedLock:
    def __init__(self, lock):
        self.lock = lock

    def __enter__(self):
        if not self.lock.acquire(blocking=False):
            attempted.set()
            self.lock.acquire()
        return self

    def __exit__(self, *_args):
        self.lock.release()

def observe_serialization(callback):
    wrapped = serialized(callback)
    if wrapped is not None:
        # Observe the actual engine wrapper's lock without adding serialization.
        for name, cell in zip(wrapped.__code__.co_freevars, wrapped.__closure__ or ()):
            if name == "lock":
                cell.cell_contents = ObservedLock(cell.cell_contents)
    return wrapped

service.serialized_progress_callback = observe_serialization

def progress(event):
    if event["event"] != "execution_node_start":
        return
    # A failed probe reports overlap immediately; this callback never waits
    # for its own lock and therefore cannot supply missing engine serialization.
    if not in_callback.acquire(blocking=False):
        overlap.set()
        attempted.set()
        raise AssertionError("Engine delivered overlapping progress callbacks")
    try:
        seen.append(event["node"])
        if len(seen) == 1:
            entered.set()
            assert release_callback.wait(5), "First callback was never released"
    finally:
        in_callback.release()

try:
    with ThreadPoolExecutor(max_workers=1) as callers:
        result = callers.submit(engine.execute_graph, callbacks={"progress_callback": progress})
        try:
            assert entered.wait(5), "First node never delivered progress"
            assert attempted.wait(5), "Second node never contended for progress delivery"
            assert not overlap.is_set(), "Progress callbacks overlapped"
            assert not result.done(), "Graph returned while its callback was active"
        finally:
            release_callback.set()
        assert result.result(timeout=5).status.value == "ok"
    assert sorted(seen) == ["left", "right"], seen
finally:
    release_callback.set()
    service.serialized_progress_callback = serialized
    engine.close()
""",
    )


@pytest.mark.parametrize("location", ["stage", "node", "job"])
def test_engine_rejects_nested_execution_before_waiting_for_capacity(
    installed_execution_extension, tmp_path, location
):
    config = write_execution_config(
        tmp_path / "metis.yaml",
        _POOL_GRAPH,
        workers=1,
        max_active_nodes=1,
        max_concurrent_executions=1,
    )
    _run_engine(
        installed_execution_extension,
        tmp_path,
        config,
        f"""
from threading import Lock
resource = engine.capabilities["e2e_resource"]
seen = []
lock = Lock()
def nested():
    try:
        engine.execute_graph()
    except RuntimeError as error:
        assert "active execution" in str(error), error
        with lock:
            seen.append(str(error))
    else:
        raise AssertionError("Nested execution was admitted")
def progress(event):
    if event["event"] == "execution_{location}_start":
        nested()
if {location!r} == "job":
    resource.on_work = nested
try:
    for _ in range(2):
        assert engine.execute_graph(callbacks={{"progress_callback": progress}}).status.value == "ok"
    assert len(seen) == {{"stage": 2, "node": 4, "job": 12}}[{location!r}], seen
finally:
    engine.close()
""",
    )


def test_cancelling_one_graph_keeps_peer_work_and_shared_pools_alive(
    installed_execution_extension, tmp_path
):
    config = write_execution_config(
        tmp_path / "metis.yaml",
        _POOL_GRAPH,
        workers=2,
        max_active_nodes=4,
        max_concurrent_executions=2,
    )
    _run_engine(
        installed_execution_extension,
        tmp_path,
        config,
        """
from concurrent.futures import CancelledError, ThreadPoolExecutor
from metis_e2e_extension import execution_tag
resource = engine.capabilities["e2e_resource"]
resource.finish_work.clear()
def abort(event):
    if event["event"] == "execution_node_start":
        raise CancelledError("caller cancelled this graph")
def execute(tag, callbacks=None):
    token = execution_tag.set(tag)
    try:
        return engine.execute_graph(callbacks=callbacks)
    finally:
        execution_tag.reset(token)
try:
    with ThreadPoolExecutor(max_workers=2) as callers:
        peer = callers.submit(execute, 1)
        try:
            with resource.condition:
                assert resource.condition.wait_for(lambda: resource.active["job"] == 2, timeout=5)
            cancelled = callers.submit(execute, 0, {"progress_callback": abort})
            try:
                cancelled.result(timeout=5)
            except CancelledError:
                pass
            else:
                raise AssertionError("Cancellation was swallowed")
            assert not peer.done()
            assert not resource.closed
        finally:
            resource.finish_work.set()
        assert peer.result(timeout=5).status.value == "ok"
    assert execute(2).status.value == "ok"
    assert resource.tags == {"node": {1, 2}, "job": {1, 2}}, resource.tags
finally:
    resource.finish_work.set()
    engine.close()
""",
    )


@pytest.mark.parametrize("scheduler_fails_first", [False, True])
def test_engine_close_retries_interruptions_before_closing_capabilities(
    installed_execution_extension, tmp_path, scheduler_fails_first
):
    config = write_execution_config(
        tmp_path / "metis.yaml",
        _POOL_GRAPH,
        workers=1,
        max_active_nodes=1,
        max_concurrent_executions=1,
    )
    _run_engine(
        installed_execution_extension,
        tmp_path,
        config,
        f"scheduler_fails_first = {scheduler_fails_first!r}\n"
        + """
from concurrent.futures import CancelledError, ThreadPoolExecutor
from threading import Event, get_ident, enumerate as threads
resource = engine.capabilities["e2e_resource"]
callback_entered, release_callback = Event(), Event()
close_state_changed, close_finished = Event(), Event()
condition = engine.execution._condition
scheduler = engine.execution._scheduler
nodes = engine.execution._node_executor
original_wait = condition.wait
original_scheduler_close = scheduler.close
original_node_shutdown = nodes.shutdown
closer_id = None
attempts = {"scheduler": 0, "wait": 0, "nodes": 0}
first_error = KeyboardInterrupt("first shutdown interruption")
close_errors = []

def interrupt_scheduler_close():
    attempts["scheduler"] += 1
    if scheduler_fails_first and attempts["scheduler"] == 1:
        raise first_error
    return original_scheduler_close()

def interrupt_wait(timeout=None):
    if get_ident() == closer_id:
        attempts["wait"] += 1
        if attempts["wait"] == 1 and not scheduler_fails_first:
            raise first_error
        if attempts["wait"] <= 2:
            raise SystemExit("later graph-drain interruption")
        close_state_changed.set()
    return original_wait(timeout)

def interrupt_node_shutdown(**kwargs):
    attempts["nodes"] += 1
    if attempts["nodes"] <= 2:
        raise RuntimeError("later worker-drain interruption")
    return original_node_shutdown(**kwargs)

def close():
    global closer_id
    closer_id = get_ident()
    try:
        engine.close()
    except BaseException as error:
        close_errors.append(error)
    finally:
        close_finished.set()
        close_state_changed.set()

def progress(event):
    if event["event"] == "execution_stage_end":
        callback_entered.set()
        assert release_callback.wait(5), "Callback was never released"
        resource.use()

try:
    with ThreadPoolExecutor(max_workers=2) as callers:
        active = callers.submit(engine.execute_graph, callbacks={"progress_callback": progress})
        closing = None
        try:
            assert callback_entered.wait(5)
            scheduler.close = interrupt_scheduler_close
            condition.wait = interrupt_wait
            nodes.shutdown = interrupt_node_shutdown
            closing = callers.submit(close)
            assert close_state_changed.wait(5), "Close neither retried nor returned"
            resource.use()
            assert not close_finished.is_set(), "Close returned before its graph drained"
            assert not active.done()
            assert len(engine.execution._active_executions) == 1
            assert attempts["wait"] >= 3
            assert attempts["nodes"] == 0
        finally:
            release_callback.set()
            try:
                active.result(timeout=5)
            except CancelledError:
                pass
            if closing is not None:
                closing.result(timeout=5)
    assert close_errors == [first_error], close_errors
    assert attempts["nodes"] == 3
    assert not engine.execution._active_executions
    assert resource.closed
    assert not [thread.name for thread in threads() if thread.name.startswith(("metis-node", "metis_"))]
finally:
    release_callback.set()
    scheduler.close = original_scheduler_close
    condition.wait = original_wait
    nodes.shutdown = original_node_shutdown
    engine.close()
""",
        timeout=20,
    )

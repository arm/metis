# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from concurrent.futures import CancelledError
import json
import logging
from unittest.mock import Mock

import pytest

from metis.engine.stages.triage.models import TriageRun
from metis.engine.stages.triage.service import TriageService
from metis.engine.stages.triage.storage import TriageStore
from metis.sarif.models import SarifPayload


@pytest.fixture(params=["run", "file"])
def triage(request, tmp_path, node_jobs):
    service = TriageService()
    payload = {
        "version": "2.1.0",
        "runs": [{"results": [{"message": {"text": name}} for name in ("A", "B")]}],
    }

    def invoke(classifier, **callbacks):
        options = {"classifier": classifier, "jobs": node_jobs.limit(1), **callbacks}
        if request.param == "run":
            return service.triage_run(
                TriageRun.from_payload(SarifPayload.model_validate(payload)), **options
            )
        source = tmp_path / "input.sarif"
        source.write_text(json.dumps(payload), encoding="utf-8")
        with TriageStore(source) as store:
            return service.triage_file(store, workers=1, **options)

    return invoke


@pytest.mark.parametrize("error_type", [OSError, CancelledError])
def test_checkpoint_failure_stops_triage(triage, error_type):
    failure = error_type("checkpoint unavailable")
    checkpoint = Mock(side_effect=failure)
    classifier = Mock(return_value={"status": "invalid", "reason": "Guarded"})

    with pytest.raises(error_type) as raised:
        triage(classifier, checkpoint_callback=checkpoint)

    assert raised.value is failure
    assert classifier.call_count == 1
    assert checkpoint.call_count >= 1


def test_partial_result_flush_failure_propagates(triage):
    classifier = Mock(side_effect=[{"status": "invalid", "reason": "Guarded"}, None])
    failure = OSError("partial checkpoint unavailable")
    checkpoint = Mock(side_effect=[None, failure])

    with pytest.raises(OSError) as raised:
        triage(classifier, checkpoint_callback=checkpoint)

    assert raised.value is failure
    assert [call.args[1:] for call in checkpoint.call_args_list] == [(1, 2), (1, 1)]


def test_cleanup_checkpoint_failure_preserves_original_cancellation(triage, caplog):
    caplog.set_level(logging.WARNING, logger="metis")
    failure = CancelledError("progress cancellation")
    checkpoint = Mock(side_effect=OSError("cleanup checkpoint unavailable"))

    def progress(event):
        if event["event"] == "done":
            raise failure

    with pytest.raises(CancelledError) as raised:
        triage(
            Mock(return_value={"status": "invalid", "reason": "Guarded"}),
            progress_callback=progress,
            checkpoint_callback=checkpoint,
        )

    assert raised.value is failure
    assert checkpoint.call_count == 1
    assert checkpoint.call_args.args[1:] == (1, 1)
    assert "cleanup checkpoint unavailable" in caplog.text


def test_progress_callback_failure_remains_best_effort(triage):
    checkpoint = Mock()
    classifier = Mock(return_value={"status": "invalid", "reason": "Guarded"})

    triage(
        classifier,
        progress_callback=Mock(side_effect=RuntimeError("display unavailable")),
        checkpoint_callback=checkpoint,
    )

    assert classifier.call_count == 2
    assert checkpoint.call_count == 2
    assert checkpoint.call_args.args[1:] == (2, 2)

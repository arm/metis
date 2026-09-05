# Offline execution extension

`tests/test_execution_e2e.py` builds this pure-Python wheel once per test session
with the installed setuptools backend. Subprocesses import the wheel directly;
Python discovers its genuine distribution and entry-point metadata. No package
index, external service, provider credentials, or security workload is used.
Build and execution subprocesses inherit only basic process settings; provider
credentials and other unrelated environment values are excluded.

The fixture exercises custom stages, scalar and tuple ports, a replacement review
publisher, partial failure, and a capability owned by the public engine.
The pool stage also measures shared node/job capacity, graph admission, context
propagation and cancellation with condition-protected counters and bounded waits. Its chat
provider raises if a test accidentally requests a model. Optional JSON-line
events are written to `METIS_E2E_EVENTS` for ordering and cleanup assertions.

The shared pytest fixture and configuration helpers in `test_execution_e2e` are
also used by `test_cli_e2e.py` to run the actual `python -m metis` entry point and
verify JSON, SARIF, HTML, CSV, error status, and checkpoint persistence.

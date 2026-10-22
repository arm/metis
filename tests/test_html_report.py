# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

from importlib.resources import files
import json
import shutil
import subprocess

import pytest

from metis.cli.exporters import export_html
from metis.engine.nodes.reachability.finding_adapter import review_sort_key


def test_chart_tooltips_encode_labels_and_paths(tmp_path):
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is required to execute the report formatters")

    template = files("metis.cli").joinpath("report_template.html").read_text()
    report = {
        "reviews": [
            {
                "file": "audit.c",
                "reviews": [
                    {"severity": severity}
                    for severity in ("Low", "Unknown", "High", "Medium", "Critical")
                ],
            }
        ]
    }
    rendered = export_html(
        report, tmp_path / "report.html", template, "test"
    ).read_text()
    payload = json.loads(
        rendered.split('type="application/json">', 1)[1].split("</script>", 1)[0]
    )
    ordered = sorted(payload["issues"], key=review_sort_key)
    assert [issue["severity"] for issue in ordered] == payload["severityOrder"]
    assert payload["fileStats"]["audit.c"]["maxSeverity"] == "Critical"
    severity_ranking = template.split("        const severityOrder =", 1)[1].split(
        "\n\n", 1
    )[0]
    severity_formatter = template.split("formatter: params => ", 1)[1].split("\n", 1)[0]
    treemap_formatter = template.split("formatter: info => ", 1)[1].split(
        "\n                },", 1
    )[0]
    script = r"""
const assert = require('node:assert/strict');
// Stand in for the existing ECharts encoder; exercise the actual formatters.
const echarts = {format: {encodeHTML: value => String(value).replace(/[<>&]/g,
    char => ({'<': '&lt;', '>': '&gt;', '&': '&amp;'}[char]))}};
const payload = __PAYLOAD__;
const severityOrder = __SEVERITY_RANKING__
assert.deepEqual(severityRank, {Critical: 5, High: 4, Medium: 3, Low: 2, Unknown: 1});
const severityFormatter = (__SEVERITY_FORMATTER__);
const treemapFormatter = (__TREEMAP_FORMATTER__);
assert.equal(severityFormatter({name: 'High <>&', value: 2}),
    'High &lt;&gt;&amp;: 2');
assert.equal(treemapFormatter({data: {
    isFile: true, fullPath: 'folder/<>&.c', severity: 'High <>&',
    severityCounts: {'High <>&': 2}, filterType: 'file'
}}), '<strong>folder/&lt;&gt;&amp;.c</strong><br/>Severity: High &lt;&gt;&amp;'
    + '<br/>Total issues: 2<br/>High &lt;&gt;&amp;: 2<br/>Click to filter by file');
"""
    script = script.replace(
        "__SEVERITY_FORMATTER__", "params => " + severity_formatter
    ).replace("__TREEMAP_FORMATTER__", "info => " + treemap_formatter)
    script = script.replace("__PAYLOAD__", json.dumps(payload)).replace(
        "__SEVERITY_RANKING__", severity_ranking
    )
    subprocess.run(
        [node, "-e", script], check=True, capture_output=True, text=True, timeout=10
    )

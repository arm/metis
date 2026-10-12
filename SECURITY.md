<!--
    SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>

    SPDX-License-Identifier: Apache-2.0
-->

# Security Policy

Metis is an open-source command-line tool intended for use by the developer and security community. We make no guarantees about the security of intermediate commits or pre-release code. Security-related validation is primarily performed at the time of tagged releases.


## Reporting a Vulnerability

Security vulnerabilities may be reported to the Arm Product Security Incident Response Team (PSIRT) by sending an email
to [psirt@arm.com](mailto:psirt@arm.com).

For more information visit https://developer.arm.com/support/arm-security-updates/report-security-vulnerabilities

## Security Guidelines

> [!WARNING]
> Running Metis on untrusted repositories carries security risks.

Source code, comments, documentation, and other repository content may contain
malicious inputs, including prompt injection intended to influence model
responses or tool use. Metis does not guarantee protection against these
attacks and must not be treated as a sandbox or security boundary.

Users are responsible for assessing these risks and securing their execution
environment and any surrounding automation or CI/CD pipeline. Apply controls
appropriate to your threat model, data sensitivity, enabled features, and
operational requirements:

- Run scans in isolated, disposable environments with least-privilege
  filesystem, process, and network access.
- Use narrowly scoped credentials and avoid exposing production secrets,
  unrelated sensitive data, or privileged services to scans.
- Use trusted configuration and extensions, and restrict outbound connections
  to approved destinations. Repository content may be sent to configured
  model providers.
- Validate inputs and treat model responses, findings, and generated artifacts
  as untrusted advisory output. Review them before they trigger code changes,
  deployments, or other privileged actions.
- Protect logs and intermediate results that may contain sensitive project
  data.
- Keep the runtime, system packages, and third-party dependencies up to date,
  and review them regularly for vulnerabilities.

# SPDX-FileCopyrightText: Copyright 2026 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

FROM ghcr.io/astral-sh/uv:python3.13-trixie-slim@sha256:69ef6514bf9b7de044514258356fa68a2d94df2e5dc807b5bfbf88fbb35f3a58 AS builder

ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
WORKDIR /app

COPY src/ pyproject.toml MANIFEST.in ./
RUN uv sync --no-dev --no-editable


FROM python:3.13-slim-trixie@sha256:47b6eb1efcabc908e264051140b99d08ebb37fd2b0bf62273e2c9388911490c1 AS runtime

RUN groupadd -r metisuser && useradd -r -m -d /home/metisuser -g metisuser metisuser

WORKDIR /app

COPY --from=builder --chown=metisuser:metisuser /app/.venv /app/.venv

ENV PATH="/app/.venv/bin:$PATH"

WORKDIR /cache

ADD --chown=metisuser:metisuser https://openaipublic.blob.core.windows.net/encodings/cl100k_base.tiktoken 9b5ad71b2ce5302211f9c61530b329a4922fc6a4

ENV TIKTOKEN_CACHE_DIR="/cache"

WORKDIR /metis

USER metisuser
ENTRYPOINT ["metis"]

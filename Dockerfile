FROM ghcr.io/astral-sh/uv:python3.13-trixie-slim@sha256:69ef6514bf9b7de044514258356fa68a2d94df2e5dc807b5bfbf88fbb35f3a58 AS builder

ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
WORKDIR /app

COPY src/ pyproject.toml MANIFEST.in ./
RUN uv sync --no-dev --no-editable


FROM python:3.13-slim-trixie@sha256:47b6eb1efcabc908e264051140b99d08ebb37fd2b0bf62273e2c9388911490c1 AS runtime

RUN groupadd -r metisuser && useradd -r -g metisuser metisuser

WORKDIR /app

COPY --from=builder --chown=metisuser:metisuser /app/.venv /app/.venv

ENV PATH="/app/.venv/bin:$PATH"

WORKDIR /metis

USER metisuser
ENTRYPOINT ["metis"]

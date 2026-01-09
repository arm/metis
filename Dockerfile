FROM ghcr.io/astral-sh/uv:python3.13-trixie-slim AS builder

ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
WORKDIR /app

COPY src/ pyproject.toml MANIFEST.in ./
RUN uv sync --no-dev --no-editable


FROM python:3.13-slim-trixie AS runtime

RUN groupadd -r metisuser && useradd -r -g metisuser metisuser

WORKDIR /app

COPY --from=builder --chown=metisuser:metisuser /app/.venv /app/.venv

ENV PATH="/app/.venv/bin:$PATH"

WORKDIR /metis

USER metisuser
ENTRYPOINT ["metis"]

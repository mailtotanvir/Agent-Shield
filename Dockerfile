# syntax=docker/dockerfile:1.7
FROM python:3.12.11-slim@sha256:47ae396f09c1303b8653019811a8498470603d7ffefc29cb07c88f1f8cb3d19f AS build
WORKDIR /build
RUN pip install --no-cache-dir uv==0.11.17
COPY pyproject.toml uv.lock README.md ./
COPY agentshield ./agentshield
RUN UV_PROJECT_ENVIRONMENT=/opt/venv uv sync --frozen --no-dev --no-editable

FROM python:3.12.11-slim@sha256:47ae396f09c1303b8653019811a8498470603d7ffefc29cb07c88f1f8cb3d19f
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
COPY --from=build /opt/venv /opt/venv
RUN groupadd --system --gid 65532 agentshield \
    && useradd --system --uid 65532 --gid agentshield --no-create-home agentshield
USER 65532:65532
ENTRYPOINT ["agentshield-broker"]

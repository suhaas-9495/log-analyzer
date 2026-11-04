# syntax=docker/dockerfile:1
# Multi-stage build:
#   build    - builds the wheel
#   test     - `docker build --target test .` runs lint, type check and the test suite
#   runtime  - small, non-root image containing only the installed wheel and configs
ARG PYTHON_VERSION=3.12

FROM python:${PYTHON_VERSION}-slim AS build
WORKDIR /src
RUN pip install --no-cache-dir "build>=1.2,<2"
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m build --wheel --outdir /dist

FROM python:${PYTHON_VERSION}-slim AS test
WORKDIR /src
ENV PYTHONDONTWRITEBYTECODE=1
COPY . .
RUN pip install --no-cache-dir -e ".[dev]" \
 && ruff check src tests scripts \
 && ruff format --check src tests scripts \
 && mypy \
 && pytest --cov -q

FROM python:${PYTHON_VERSION}-slim AS runtime
LABEL org.opencontainers.image.title="log-analyzer" \
      org.opencontainers.image.description="Intelligent log analyzer and alert generator"
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    LOG_ANALYZER_CONFIG=/app/configs/config.yaml
RUN useradd --create-home --uid 10001 analyzer
WORKDIR /app
COPY --from=build /dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -f /tmp/*.whl
COPY configs ./configs
COPY data/sample/test_logs.txt ./data/sample/test_logs.txt
USER analyzer
EXPOSE 8080
ENTRYPOINT ["log-analyzer"]
# Default: analyze the bundled sample. Override, e.g.:
#   docker run --rm -v "$PWD/logs:/logs:ro" log-analyzer --file /logs/app.log
#   tail -f app.log | docker run --rm -i log-analyzer
#   docker run --rm -p 8080:8080 log-analyzer serve
CMD ["--file", "/app/data/sample/test_logs.txt"]

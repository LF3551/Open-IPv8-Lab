FROM python:3.12-slim AS builder

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src/ src/

RUN pip install --no-cache-dir build && python -m build --wheel

FROM python:3.12-slim

LABEL org.opencontainers.image.title="Open-IPv8-Lab"
LABEL org.opencontainers.image.description="Experimental userspace IPv8 toolkit"
LABEL org.opencontainers.image.source="https://github.com/LF3551/Open-IPv8-Lab"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.authors="Aleksei Aleinikov"

WORKDIR /app
COPY --from=builder /app/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl

ENTRYPOINT ["ipv8lab"]
CMD ["--help"]

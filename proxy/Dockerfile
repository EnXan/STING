FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

COPY pyproject.toml uv.lock ./
RUN uv sync --locked

COPY proxy/addon.py .

EXPOSE 8080
CMD ["uv", "run", "mitmdump", "--listen-host", "0.0.0.0", "--listen-port", "8080", "-s", "addon.py"]
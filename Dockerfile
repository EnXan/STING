# Install uv
FROM python:3.12-slim
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Build-time working directory; the agent runs from /repo at runtime
WORKDIR /app

# Install auditd for monitoring system calls (file changes and shell commands)
RUN apt-get update && apt-get install -y --no-install-recommends \
    inotify-tools \
    strace \
    curl \
    ca-certificates \
    git \
    ripgrep \
    chromium \
    chromium-driver \
    fonts-liberation \
    libasound2 \
    libatk-bridge2.0-0 \
    libgbm1 \
    libgtk-3-0 \
    libnss3 \
    && rm -rf /var/lib/apt/lists/*

ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright \
    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 \
    CHROME_BIN=/usr/bin/chromium \
    CHROMIUM_PATH=/usr/bin/chromium

# Install Claude Code, move binary to system-wide path
RUN curl -fsSL https://claude.ai/install.sh | bash && \
    install -m 0755 "$(readlink -f /root/.local/bin/claude)" /usr/local/bin/claude

# Install Codex binary
RUN curl -fsSL https://github.com/openai/codex/releases/latest/download/codex-x86_64-unknown-linux-musl.tar.gz \
    | tar -xz -C /usr/local/bin/ \
    && mv /usr/local/bin/codex-x86_64-unknown-linux-musl /usr/local/bin/codex \
    && chmod +x /usr/local/bin/codex

# Install kimi-code CLI
RUN curl -fsSL https://code.kimi.com/kimi-code/install.sh -o /tmp/install-kimi.sh \
    && KIMI_NO_MODIFY_PATH=1 bash /tmp/install-kimi.sh \
    && install -m 0755 /root/.kimi-code/bin/kimi /usr/local/bin/kimi \
    && rm /tmp/install-kimi.sh

# claude refuses --dangerously-skip-permissions as root; a non-root user is required.
RUN useradd -m -s /bin/bash agent

# Pre-build the target repo's venv at /opt/repo-venv (inside the container,
# not the bind-mounted /repo) so uv sync at runtime is a ~1s audit, not an
# 86s cross-filesystem copy. Also pre-installs Playwright/Patchright Chromium.
RUN git clone --depth=1 https://github.com/EnXan/immo_alert_berlin /tmp/target-repo \
    && cd /tmp/target-repo \
    && UV_PROJECT_ENVIRONMENT=/opt/repo-venv uv sync --frozen \
    && UV_PROJECT_ENVIRONMENT=/opt/repo-venv uv run playwright install chromium \
    && UV_PROJECT_ENVIRONMENT=/opt/repo-venv uv run patchright install chromium \
    && rm -rf /tmp/target-repo \
    && chmod a+w /ms-playwright \
    && chmod -R a+w /ms-playwright/.links \
    && mkdir -p /root/.cache /home/agent/.cache \
    && ln -sf /ms-playwright /root/.cache/ms-playwright \
    && ln -sf /ms-playwright /home/agent/.cache/ms-playwright \
    && chown -h agent:agent /home/agent/.cache/ms-playwright

RUN mkdir -p /var/log/sting /repo

# Install dependencies
RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-install-project

# Copy the project into the image
COPY . /app

# Sync the project
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --locked

# Entrypoint starts observers, then hands off to agent
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
CMD ["claude", "--dangerously-skip-permissions"]

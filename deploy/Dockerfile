FROM oven/bun:1.3.14-debian

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates git nodejs npm bubblewrap \
  && rm -rf /var/lib/apt/lists/*

# Install the real harness runtimes used by Argus. Credentials are not baked
# into the image; mount the harness config directories or use platform-stored
# credentials at runtime.
ARG PI_VERSION=1.3.0
ARG CLAUDE_CODE_VERSION=2.1.310
RUN npm install -g "@earendil-works/pi-coding-agent@${PI_VERSION}" "@anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}" \
  && npm cache clean --force

WORKDIR /app
COPY package.json bun.lock tsconfig.json ./
RUN bun install --frozen-lockfile

COPY . .
RUN bun run build:web

ENV ARGUS_PORT=8787 \
    ARGUS_HOST=0.0.0.0 \
    ARGUS_DATA_DIR=/data \
    ARGUS_SANDBOX=none \
    ARGUS_PI_BIN=pi \
    ARGUS_CLAUDE_BIN=claude

VOLUME ["/data"]
EXPOSE 8787

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD bun -e 'fetch("http://127.0.0.1:8787/api/health").then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))'

CMD ["bun", "run", "src/server.ts"]

# syntax=docker/dockerfile:1
# SECURE model-serving image: multi-stage, pinned, non-root, distroless, no secrets in layers.
#
# The sha256 digests below are PLACEHOLDERS (obviously fake). Before a real build, replace each
# one with the current digest, for example:
#   docker buildx imagetools inspect debian:12-slim
# and let a bot (Renovate / Dependabot) keep the digests up to date.

# ---------------------------------------------------------------- stage 1: build
# The builder uses the same Debian release and Python version as the distroless runtime,
# so the virtual environment copied below works there unchanged.
FROM debian:12-slim@sha256:1111111111111111111111111111111111111111111111111111111111111111 AS build
RUN apt-get update \
 && apt-get install --no-install-recommends --yes python3-venv gcc libpython3-dev \
 && python3 -m venv /venv

WORKDIR /build
# requirements.lock is generated with hashes, e.g. `pip-compile --generate-hashes` or `uv pip compile --generate-hashes`.
COPY requirements.lock .

# FIX (DF-004, DF-010): the private index credential is a BuildKit secret: mounted for this one
# RUN step only, never written to a layer. Only ONE index is used, so no dependency confusion.
RUN --mount=type=secret,id=netrc,target=/root/.netrc \
    /venv/bin/pip install --no-cache-dir --index-url https://pypi.internal.example/simple \
        --require-hashes -r requirements.lock

# ---------------------------------------------------------------- stage 2: runtime
# FIX (DF-001, DF-002, DF-008): pinned by digest; no shell, no package manager, no compiler.
FROM gcr.io/distroless/python3-debian12:nonroot@sha256:2222222222222222222222222222222222222222222222222222222222222222

WORKDIR /app
COPY --from=build /venv /venv
COPY src/ /app/src/
# FIX (DF-011): weights in safetensors format (data only, no code). CI checks the file's sha256
# against the AI-BOM before this image is built.
COPY model/support-llm-v3.safetensors /app/model/

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1

# FIX (DF-003): an explicit non-root numeric user (65532 = "nonroot" in distroless images).
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/venv/bin/python", "-m", "uvicorn", "src.serve:app", "--host", "0.0.0.0", "--port", "8080"]
# The read-only root filesystem, dropped capabilities and seccomp profile are set at RUN time
# (docker run --read-only --cap-drop ALL, or the Kubernetes securityContext). See ../kubernetes.

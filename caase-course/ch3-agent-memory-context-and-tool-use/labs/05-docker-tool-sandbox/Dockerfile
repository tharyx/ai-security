# Hedged example: a minimal image for ONE agent tool. Not built or tested by the repo author.
# Verify the base image tag and pin it by digest for real use (docker pull, then use name@sha256:...).
FROM python:3.12-slim

# Non-root user with a fixed numeric id, so the same id can be used in `docker run --user`.
RUN groupadd --gid 10001 tool && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin tool

WORKDIR /app
# Copy only the tool code. No credentials, no .env, no source tree, no package manager cache.
COPY tool.py /app/tool.py

USER 10001:10001
ENTRYPOINT ["python", "-I", "/app/tool.py"]

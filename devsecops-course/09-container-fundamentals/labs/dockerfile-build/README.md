# Lab: Create Docker image using Dockerfile

**Course exercise:** "Create Docker Image using Dockerfile". Lessons: [03 Dockerfile builds](../../03-images-dockerfile-and-registries.md#3-building-images-with-a-dockerfile).

**Time:** 60 minutes. **Safety:** A Dockerfile parser and layer model. Nothing is built or run.

## What it models

A real **Dockerfile parser** (comments, line continuations, stages), a **layer model** (only `RUN`, `COPY`, `ADD` make layers), a **build cache** (a layer is reused only if its parent and its instruction and copied files are unchanged), an `explain_cache()` that says why layers were rebuilt, and **multi-stage builds** (only the last stage ships). Fixtures: [single-stage](fixtures/single-stage.Dockerfile), [multi-stage](fixtures/multi-stage.Dockerfile).

## Steps

```text
.venv/Scripts/python devsecops-course/09-container-fundamentals/labs/dockerfile-build/demo.py
.venv/Scripts/python -m pytest devsecops-course/09-container-fundamentals/labs/dockerfile-build -v
```

1. Run the demo and read the cold-cache build.
2. Edit one source file and see which layers are rebuilt. Then move `COPY . /app` below the `pip install` line and compare.
3. Compare the sizes of the single-stage and multi-stage images.
4. Add `ARG` handling or a `.dockerignore` effect as an extension.

## Expected output (real run)

```text
Build 1 (cold cache):
  0527faa40779    1000000 KB  CACHED  FROM python:3.12
  2b3523914c29        322 KB  built   COPY . /app
  19dbe579006a      80000 KB  built   RUN apt-get update && apt-get install -y gcc libpq-d
  3b718df25bd6      40000 KB  built   RUN pip install -r requirements.txt
  metadata: {'WORKDIR': '/app', 'USER': 'root', 'CMD': '["python", "app.py"]'}

Build 2 (app.py edited): COPY comes BEFORE pip install, so everything after it is rebuilt
  cached : FROM python:3.12
  REBUILT: COPY . /app
  REBUILT (parent changed): RUN apt-get update && apt-get install -y gcc
  REBUILT (parent changed): RUN pip install -r requirements.txt

Multi-stage: final image 17500 KB, discarded stages: ['build']
Single-stage image: 1120322 KB
```

## Think about it

Layers never forget: if you `COPY secret` and later `RUN rm secret`, the first layer still contains it. Where would a scanner find it? (In the layer, see [recon-third-party-image-inspection](../../../10-container-reconnaissance-and-attacks/labs/recon-third-party-image-inspection/README.md).)

## Run the real tool

`docker build -t app:1 .`, `docker history app:1`, `docker buildx build`, BuildKit cache mounts. With BuildKit the cache and layer rules are richer than this model.

> Hedged: real tools and flags change between versions. Verify at the source. Tests in this repo never need Docker.

## Tests

`8` tests in `test_dso_ch09_*.py`: `.venv/Scripts/python -m pytest devsecops-course/09-container-fundamentals/labs/dockerfile-build`.

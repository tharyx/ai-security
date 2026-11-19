# Lab: Working with docker command

**Course exercise:** "Working With Docker Command". Lessons: [02 Docker architecture](../../02-docker-architecture-and-runtime.md), [03 running a container](../../03-images-dockerfile-and-registries.md#7-running-a-container).

**Time:** 30 minutes. **Safety:** No Docker needed. The lab only models rules in Python.

## What it models

The full hands-on lab already exists in the sibling CSSE course: [csse ch3 docker-commands](../../../../csse-course/ch3-attacking-container-supply-chain/labs/docker-commands/README.md) (a `docker run` flag parser with 18 findings) and its [COMMANDS.md](../../../../csse-course/ch3-attacking-container-supply-chain/labs/docker-commands/COMMANDS.md). **Do that lab first. Do not duplicate it.** This folder adds one short exercise on top: the **container lifecycle state machine** ([lifecycle.py](lifecycle.py)) that tells you which command moves a container to which state, and a task-to-command table.

## Steps

```text
.venv/Scripts/python devsecops-course/09-container-fundamentals/labs/docker-command/demo.py
.venv/Scripts/python -m pytest devsecops-course/09-container-fundamentals/labs/docker-command -v
```

1. Do the csse docker-commands lab and read COMMANDS.md.
2. Run the demo below and draw the state diagram on paper: created, running, paused, exited, removed.
3. Predict, then check: what happens if you `rm` a running container without `-f`? (An error: you must stop it or force it.)
4. Add one rule of your own to `TRANSITIONS` (for example `restart` from `exited`) and add a test.

## Expected output (real run)

```text
docker run   -> web        nginx:1.27     running
docker pause -> web        nginx:1.27     paused
docker stop  -> web        nginx:1.27     exited
error        -> cannot 'pause' a container that is exited
docker rm    -> removed | history: created > running > paused > running > exited > removed

run a new container in the background         docker run -d IMAGE
list running containers                       docker ps
list all containers including stopped         docker ps -a
see the container configuration as JSON       docker inspect NAME
```

## Think about it

Why does `docker run` equal `create` plus `start`? (Because the image layers and the writable layer are made at create time; start launches the process.) Why does a stopped container still matter for security? (Its writable layer, logs and env remain readable with `docker inspect` and `docker diff` until you `rm` it.)

## Run the real tool

`docker run -d --name web nginx:1.27`, `docker ps -a`, `docker pause web`, `docker stop web`, `docker rm web`. See [real-tools/docker.md](../../real-tools/docker.md).

> Hedged: real tools and flags change between versions. Verify at the source. Tests in this repo never need Docker.

## Tests

`5` tests in `test_dso_ch09_*.py`: `.venv/Scripts/python -m pytest devsecops-course/09-container-fundamentals/labs/docker-command`.

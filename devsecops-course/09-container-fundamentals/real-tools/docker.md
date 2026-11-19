# Real tool guide: Docker, Compose, registry and the Docker SDK (chapter 9 labs)

> **Hedged guide.** Written from documentation, not run by the repo author for this guide. Commands, flags and defaults change between versions: check `docker --help` and docs.docker.com. The tests in this repo never need Docker.

## Safe setup

- Use a **disposable VM** or a Linux machine you do not care about. Docker Desktop (Windows, macOS) runs Linux containers in a small VM.
- Prefer **rootless Docker** or Podman for experiments. Keep the API on the Unix socket. Never bind it to a network without TLS.
- Never `--privileged`, never mount `docker.sock` or `/` into practice containers unless the exercise says so, on a throwaway VM.

## Commands that map to the labs

| Lab | Real commands |
|---|---|
| docker-command | `docker run -d --name web nginx:1.27`, `docker ps -a`, `docker pause/unpause/stop/start/rm`, `docker logs`, `docker exec -it web sh`, `docker inspect web` |
| docker-networking | `docker network create backend`, `docker network ls`, `docker network inspect backend`, `docker run --network backend`, `docker run -p 127.0.0.1:8080:80`, `ss -ltnp` |
| manage-data | `docker volume create pgdata`, `docker volume inspect pgdata`, `docker run -v pgdata:/var/lib/postgresql/data`, `docker run --mount type=bind,src=/srv/x,dst=/x,readonly`, `docker run --tmpfs /run/secrets` |
| dockerfile-build | `docker build -t app:1 .`, `docker history app:1`, `docker build --no-cache`, `DOCKER_BUILDKIT=1`, `docker buildx build` |
| writing-dockerfile | `hadolint Dockerfile`, `dockle app:1` (image linter, CIS-based), `docker run --rm -i hadolint/hadolint < Dockerfile` (hedged image name) |
| container-registry | `docker run -d -p 127.0.0.1:5000:5000 --name reg registry:2`, `docker tag app:1 localhost:5000/app:1`, `docker push localhost:5000/app:1`, `curl http://127.0.0.1:5000/v2/_catalog`, `crane digest localhost:5000/app:1`, `skopeo inspect --tls-verify=false docker://localhost:5000/app:1` |
| docker-compose | `docker compose config`, `docker compose up -d`, `docker compose ps`, `docker compose down -v` |
| docker-sdk | `pip install docker` then the snippet below |

## Docker SDK for Python (hedged)

```python
import docker
client = docker.from_env()                     # honours DOCKER_HOST
client.ping()
for c in client.containers.list(all=True):
    print(c.name, c.status, c.attrs["HostConfig"].get("Privileged"))
client.images.pull("alpine", tag="3.20")
out = client.containers.run("alpine:3.20", "echo hello", remove=True)   # returns bytes when not detached
print(out.decode())
```

Differences from the offline twin in [docker-sdk](../labs/docker-sdk/README.md): the real SDK pulls images automatically in `containers.run`, `container.image` is an Image object, and errors come from `docker.errors` (`NotFound`, `ImageNotFound`, `APIError`). Check the SDK documentation for your version.

## Safe checks of your own environment

- `docker info` (look at Security Options, Cgroup Version, Rootless), `docker version`.
- `docker ps --format '{{json .}}'`, then feed the JSON into the [CH10 recon lab](../../10-container-reconnaissance-and-attacks/labs/recon-builtin-tools/README.md) fixtures format.
- CIS checks: `docker-bench-security` (verify maintenance status).

## Related

The sibling course has a longer guide for the same tools: [csse real-tools/docker.md](../../../csse-course/ch3-attacking-container-supply-chain/real-tools/docker.md).

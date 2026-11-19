# Docker command reference (security view)

Use this next to the simulator. Commands that start containers are shown for learning; the lab itself never runs them.

| Task | Command | Security note |
|---|---|---|
| Version and daemon info | `docker version`, `docker info` | `docker info` shows the storage driver, cgroup version, rootless mode and security options (seccomp, apparmor). |
| Pull an image | `docker pull nginx:1.27` / `docker pull nginx@sha256:<digest>` | A tag can move; a digest cannot. |
| List images | `docker images --digests` | Shows digests next to tags. |
| Run a container | `docker run -d --name web -p 127.0.0.1:8080:80 nginx:1.27` | Every flag changes the attack surface (see the simulator). |
| List containers | `docker ps -a` | Look for containers you did not start. |
| Shell into a container | `docker exec -it web sh` | `docker exec` needs daemon access, which is root-equivalent. |
| Logs | `docker logs web` | Logs may leak secrets. |
| Inspect | `docker inspect web` | Shows `HostConfig` (privileged, binds, caps) and `Config.Env` (secrets). |
| Image history | `docker history --no-trunc nginx:1.27` | Shows each layer's build command, including secrets passed as `ARG`/`ENV`. |
| Image inspect | `docker image inspect nginx:1.27` | Shows config, entrypoint, user and layer digests. |
| Snapshot a container | `docker commit web web-snapshot:1` | Captures the writable layer. Also captures anything an attacker wrote. |
| Export an image | `docker save -o web.tar web-snapshot:1` | A tar with `manifest.json`, a config JSON and layer tars. |
| Export a container filesystem | `docker export web > web-fs.tar` | Flat file system, no layers or metadata. |
| Load an image | `docker load -i web.tar` | Treat tar files from strangers as untrusted. |
| Build | `docker build -t app:1 .` | Use a `.dockerignore`; never `COPY .env`. |
| Stop and remove | `docker stop web && docker rm web` | |
| Cleanup | `docker system prune` | Removes unused data. Be careful on shared hosts. |
| Copy files | `docker cp web:/etc/passwd .` | Handy for forensics. |
| Diff a container | `docker diff web` | `A` added, `C` changed, `D` deleted paths in the writable layer. Great for spotting an intrusion. |
| Networks and volumes | `docker network ls`, `docker volume ls` | `--network host` removes network isolation. |

## Safe defaults to remember

`--read-only --tmpfs /tmp --user 10001:10001 --cap-drop ALL --security-opt no-new-privileges --memory 256m --pids-limit 100 -p 127.0.0.1:8080:8080 image@sha256:<digest>`

"""An offline twin of the Docker SDK for Python (the `docker` package).

The method names mirror the real SDK so the SAME audit code runs against either client:

    real:     import docker; client = docker.from_env()
    offline:  client = FakeDockerClient.from_fixture("fixtures/daemon-state.json")

Mirrored (simplified): client.ping(), client.version(), client.info(), client.containers.list/run/get,
Container.status/name/image/attrs/stop/remove/logs, client.images.pull/list/get.
Return types are simplified: images.pull returns one image; the real SDK returns Image or a list if no tag is given.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field


class NotFound(Exception):
    """Mirrors docker.errors.NotFound."""


class ImageNotFound(NotFound):
    """Mirrors docker.errors.ImageNotFound."""


@dataclass
class Image:
    tags: list[str]
    id: str
    attrs: dict = field(default_factory=dict)

    @property
    def short_id(self) -> str:
        return self.id[:19]


class Container:
    def __init__(self, client: "FakeDockerClient", doc: dict):
        self._client, self.attrs = client, doc
        self.name = doc["Name"].lstrip("/")
        self.id = doc["Id"]
        self.status = doc["State"]["Status"]
        self.image = doc["Config"]["Image"]

    def stop(self, timeout: int = 10) -> None:
        self.status = self.attrs["State"]["Status"] = "exited"

    def remove(self, force: bool = False) -> None:
        if self.status == "running" and not force:
            raise RuntimeError("cannot remove a running container (use force=True)")
        self._client._containers.pop(self.name, None)

    def logs(self) -> bytes:
        return ("\n".join(self.attrs.get("Logs", [])) + "\n").encode()


class _Containers:
    def __init__(self, client: "FakeDockerClient"):
        self._c = client

    def list(self, all: bool = False, filters: dict | None = None) -> list[Container]:
        out = list(self._c._containers.values())
        if not all:
            out = [c for c in out if c.status == "running"]
        for k, v in (filters or {}).items():
            if k == "name":
                out = [c for c in out if v in c.name]
            elif k == "status":
                out = [c for c in out if c.status == v]
        return out

    def get(self, name: str) -> Container:
        try:
            return self._c._containers[name]
        except KeyError:
            raise NotFound(f"No such container: {name}") from None

    def run(self, image: str, command: str | None = None, detach: bool = False, name: str | None = None,
            ports: dict | None = None, environment: dict | None = None, privileged: bool = False,
            volumes: dict | None = None, **kwargs) -> Container | bytes:
        self._c.images.get(image)          # raises ImageNotFound if it was never pulled (the real SDK pulls automatically)
        name = name or f"fake_{len(self._c._containers) + 1}"
        doc = {
            "Id": f"{len(self._c._containers) + 1:064x}", "Name": "/" + name,
            "State": {"Status": "running"},
            "Config": {"Image": image, "Cmd": [command] if command else [],
                       "Env": [f"{k}={v}" for k, v in (environment or {}).items()], "User": kwargs.get("user", "")},
            "HostConfig": {"Privileged": privileged, "PortBindings": ports or {},
                           "Binds": [f"{h}:{c['bind']}:{c.get('mode', 'rw')}" for h, c in (volumes or {}).items()]},
            "Logs": [f"started {command or 'default command'}"],
        }
        c = Container(self._c, doc)
        self._c._containers[name] = c
        if not detach:
            return c.logs()
        return c


class _Images:
    def __init__(self, client: "FakeDockerClient"):
        self._c = client

    def pull(self, repository: str, tag: str | None = None) -> Image:
        ref = f"{repository}:{tag or 'latest'}"
        if ref not in self._c._registry:
            raise ImageNotFound(f"pull access denied / not found: {ref}")
        img = Image([ref], self._c._registry[ref])
        self._c._images[ref] = img
        return img

    def list(self) -> list[Image]:
        return list(self._c._images.values())

    def get(self, name: str) -> Image:
        ref = name if ":" in name.rsplit("/", 1)[-1] else name + ":latest"
        if ref not in self._c._images:
            raise ImageNotFound(f"No such image: {name}")
        return self._c._images[ref]


class FakeDockerClient:
    def __init__(self, state: dict):
        self._info, self._version = state["info"], state["version"]
        self._registry: dict[str, str] = dict(state["registry"])      # what `images.pull` can fetch
        self._images = {r: Image([r], i) for r, i in state["local_images"].items()}
        self._containers: dict[str, Container] = {}
        self.containers, self.images = _Containers(self), _Images(self)
        for doc in state["containers"]:
            self._containers[doc["Name"].lstrip("/")] = Container(self, doc)

    @classmethod
    def from_fixture(cls, path: str) -> "FakeDockerClient":
        with open(path, encoding="utf-8") as f:
            return cls(json.load(f))

    def ping(self) -> bool:
        return True

    def version(self) -> dict:
        return self._version

    def info(self) -> dict:
        return self._info


def audit(client) -> list[str]:
    """Works with docker.from_env() AND FakeDockerClient: that is the point of the twin."""
    findings = []
    for c in client.containers.list(all=True):
        hc = c.attrs.get("HostConfig", {})
        if hc.get("Privileged"):
            findings.append(f"{c.name}: privileged container")
        for b in hc.get("Binds") or []:
            if "docker.sock" in b:
                findings.append(f"{c.name}: mounts docker.sock ({b})")
        if not c.attrs.get("Config", {}).get("User"):
            findings.append(f"{c.name}: runs as image default user (probably root)")
        if c.image.endswith(":latest") or ":" not in c.image:
            findings.append(f"{c.name}: unpinned image {c.image}")
    return findings

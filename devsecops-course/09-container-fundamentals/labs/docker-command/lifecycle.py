"""Container lifecycle state machine: the short exercise for 'Working With Docker Command'.

Teaches which docker command moves a container to which state, and what `docker ps` would show.
Nothing is executed; this only models the rules.
"""
from __future__ import annotations

# (current state, command) -> new state. `None` means the container no longer exists.
TRANSITIONS: dict[tuple[str, str], str | None] = {
    ("created", "start"): "running",
    ("created", "rm"): None,
    ("running", "pause"): "paused",
    ("paused", "unpause"): "running",
    ("running", "stop"): "exited",
    ("running", "kill"): "exited",
    ("running", "restart"): "running",
    ("exited", "start"): "running",
    ("exited", "rm"): None,
    ("running", "rm -f"): None,
    ("paused", "rm -f"): None,
}

COMMAND_FOR_TASK = {
    "run a new container in the background": "docker run -d IMAGE",
    "list running containers": "docker ps",
    "list all containers including stopped": "docker ps -a",
    "see the container configuration as JSON": "docker inspect NAME",
    "read the container output": "docker logs NAME",
    "open a shell in a running container": "docker exec -it NAME sh",
    "see files changed in the writable layer": "docker diff NAME",
    "see how an image was built": "docker history IMAGE",
    "stop gracefully (SIGTERM then SIGKILL)": "docker stop NAME",
    "remove a stopped container": "docker rm NAME",
}


class LifecycleError(Exception):
    pass


class Container:
    def __init__(self, name: str, image: str):
        self.name, self.image, self.state = name, image, "created"
        self.history = ["created"]

    def do(self, command: str) -> str | None:
        key = (self.state, command)
        if key not in TRANSITIONS:
            raise LifecycleError(f"cannot '{command}' a container that is {self.state}")
        new = TRANSITIONS[key]
        self.state = new or "removed"
        self.history.append(self.state)
        return new

    def ps_line(self) -> str:
        return f"{self.name:<10} {self.image:<14} {self.state}"


def run(name: str, image: str) -> Container:
    """`docker run` = create + start."""
    c = Container(name, image)
    c.do("start")
    return c

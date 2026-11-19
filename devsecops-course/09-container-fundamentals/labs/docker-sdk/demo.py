import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import fake_docker as fd

client = fd.FakeDockerClient.from_fixture(str(Path(__file__).parent / "fixtures" / "daemon-state.json"))
print("ping:", client.ping(), "| server:", client.version()["Version"])
print("running:", [c.name for c in client.containers.list()])
print("all    :", [(c.name, c.status) for c in client.containers.list(all=True)])

img = client.images.pull("nginx", tag="1.27")
print("pulled :", img.tags, img.short_id)
try:
    client.images.pull("evil/miner", tag="1")
except fd.ImageNotFound as e:
    print("pull failed (as expected):", e)

c = client.containers.run("alpine:3.20", "echo hi", detach=True, name="demo", environment={"A": "1"})
print("run    :", c.name, c.status, "| logs:", c.logs().decode().strip())
c.stop(); c.remove()
print("after remove:", [x.name for x in client.containers.list(all=True)])

print("\naudit(client):")
for f in fd.audit(client):
    print("  -", f)

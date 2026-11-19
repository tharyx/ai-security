import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import datastore as ds

host = ds.Host()
mounts = [ds.parse_v("dbdata:/var/lib/db"), ds.parse_v("/srv/app-config:/etc/app"), ds.Mount("tmpfs", "", "/run/secrets")]
c = host.run(mounts)
for path in ["/var/lib/db/table.dat", "/etc/app/app.conf", "/run/secrets/token", "/tmp/scratch"]:
    print(f"write {path:<24} -> {c.write(path, 'x')}")
c.rm()
print("\nAfter docker rm:")
print("  volume dbdata still has:", list(host.volumes["dbdata"]))
print("  host file changed      :", "/srv/app-config/app.conf" in host.host_fs and host.host_fs["/srv/app-config/app.conf"])
print("  writable layer / tmpfs :", c.layer, c.tmpfs)
print("\nRisk analysis:")
for spec in ["dbdata:/var/lib/db", "/var/run/docker.sock:/var/run/docker.sock", "/etc:/host-etc", "/srv/app:/app", "/srv/app:/app:ro", "/data"]:
    m = ds.parse_v(spec)
    rs = ds.risks(m)
    print(f"  {spec:<46}", rs[0][0] + ": " + rs[0][1] if rs else "OK")

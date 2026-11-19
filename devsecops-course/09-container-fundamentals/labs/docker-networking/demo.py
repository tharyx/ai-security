import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import netsim

t = netsim.Topology.load(str(Path(__file__).parent / "fixtures" / "topology.json"))
for src, dst, port in [("web", "api", 3000), ("web", "db", 5432), ("api", "db", 5432),
                       ("legacy1", "legacy2", 9000), ("worker-a", "worker-b", 7001), ("batch", "web", 80)]:
    ok, why = t.can_reach(src, dst, port)
    print(f"{src:>9} -> {dst:<9}:{port:<5} {'YES' if ok else 'NO ':<3} {why}")
print("host-network monitor can reach host localhost ports:", t.host_localhost_reachable("monitor"))
print("\nExposure:")
for e in t.exposure():
    print(f"  {e['container']:<8} {e['binding']:<22} {e['scope']}")
print("\nFindings:")
for f in t.findings():
    print(" -", f)

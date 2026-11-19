import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import recon

data = recon.load(str(Path(__file__).parent / "fixtures"))
print(f"{'container':<11}{'image':<17}{'user':<15}{'score':>5}  level")
for it in recon.inventory(data):
    print(f"{it.name:<11}{it.image:<17}{it.user:<15}{it.score:>5}  {it.level}")
print()
worst = recon.inventory(data)[0]
print(f"Why {worst.name} scores {worst.score}:", "; ".join(worst.risks))
print("\nHost-level findings:")
for f in recon.host_findings(data):
    print(" -", f)

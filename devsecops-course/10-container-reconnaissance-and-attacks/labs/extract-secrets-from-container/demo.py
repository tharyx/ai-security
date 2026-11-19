import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import extractor as ex

fx = ex.build_fixture()
finds = ex.investigate(fx)
print(f"{'source':<16}{'where':<44}{'kind':<36}preview")
for f in finds:
    print(f"{f['source']:<16}{f['where'][:42]:<44}{f['kind'][:34]:<36}{f['preview']}")
leaks = [f for f in finds if f["is_leak"]]
print(f"\n{len(leaks)} leaks, {len(finds) - len(leaks)} fine. Same token in {sum(1 for f in leaks if 'TOKEN' in f['where'].upper() or 'token' in f['where'])} places: rotate it everywhere.")
for src in dict.fromkeys(f["source"] for f in leaks):
    print(f"  fix [{src}]: {ex.ADVICE[src]}")

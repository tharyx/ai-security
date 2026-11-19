import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import dockerfile as df

FIX = Path(__file__).parent / "fixtures"
ctx = {"app.py": 20, "requirements.txt": 2, "static/logo.png": 300}
single = (FIX / "single-stage.Dockerfile").read_text()

cache: set[str] = set()
b1 = df.build(single, ctx, cache)
print("Build 1 (cold cache):")
for l in b1["layers"]:
    print(f"  {l.id}  {l.size_kb:>9} KB  {'CACHED' if l.cached else 'built '}  {l.created_by[:52]}")
print("  metadata:", b1["meta"])

ctx2 = dict(ctx, **{"app.py": 21})     # one source file changed
b2 = df.build(single, ctx2, cache)
print("\nBuild 2 (app.py edited): COPY comes BEFORE pip install, so everything after it is rebuilt")
for line in df.explain_cache(b1, b2):
    print("  " + line[:70])

multi = df.build((FIX / "multi-stage.Dockerfile").read_text(), {"go.mod": 1, "go.sum": 1, "main.go": 40}, set())
print(f"\nMulti-stage: final image {multi['size_kb']} KB, discarded stages: {multi['discarded_stages']}")
print(f"Single-stage image: {b1['size_kb']} KB")

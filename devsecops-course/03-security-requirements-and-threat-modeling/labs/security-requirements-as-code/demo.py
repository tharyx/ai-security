import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import reqs  # noqa: E402

cat = reqs.load_catalog(HERE / "fixtures" / "requirements.yaml")
for name in ("app_config.json", "app_config_weak.json"):
    print(f"== {name}")
    res = reqs.evaluate(cat, reqs.load_config(HERE / "fixtures" / name))
    print(reqs.render(res))
    print("gate exit code:", reqs.gate(res))

print("== write the missing check, run again with the good config")


@reqs.check("upload_limits")
def _upload(cfg):
    u = cfg.get("upload", {})
    ok = u.get("max_bytes", 0) > 0 and bool(u.get("allowed_types"))
    return ok, f"max_bytes={u.get('max_bytes')} types={u.get('allowed_types')}"


res = reqs.evaluate(cat, reqs.load_config(HERE / "fixtures" / "app_config.json"))
print("gate exit code:", reqs.gate(res))
print("== threat traceability")
for threat, items in reqs.traceability(cat, res).items():
    print(threat, "->", ", ".join(items))

"""From repo root:
    .venv/Scripts/python devsecops-course/13-secrets-management/labs/secrets-in-env-and-images/demo.py
"""
from pathlib import Path

import yaml

import leak_finder as lf

FIX = Path(__file__).parent / "fixtures"
cfg = lf.load_json(FIX / "image_config.json")
inspect = lf.load_json(FIX / "docker_inspect.json")
history = lf.load_json(FIX / "image_history.json")
compose = lf.load_yaml(FIX / "compose_before.yml")
log = (FIX / "app_startup.log").read_text()

print("== Image config (what anyone who pulls the image can read) ==")
print(lf.render(lf.scan_image_config(cfg)))
print("\n== docker inspect (what anyone with docker access can read) ==")
print(lf.render(lf.scan_docker_inspect(inspect)))
print("\n== Image history (docker history --no-trunc) ==")
print(lf.render(lf.scan_history(history)))
print("\n== Log file ==")
print(lf.render(lf.scan_log(log)))
print("\n== /proc/<pid>/environ of the running container ==")
print(lf.render(lf.scan_proc_environ(lf.make_proc_environ(cfg["config"]["Env"]))))
print("\n== Compose file before ==")
print(lf.render(lf.scan_compose(compose)))

print("\n== FIX: runtime injection ==")
fixed, secret_names = lf.rewrite_compose(compose)
print("secrets to inject at deploy time:", secret_names)
print(yaml.safe_dump(fixed, sort_keys=False).replace("registry.example/shop/", "<registry>/")[:700])
print("findings after the fix:", len(lf.scan_compose(fixed)))
clean_env, to_mount = lf.runtime_injection(cfg["config"]["Env"])
print("image Env after fix:", [e for e in clean_env if "FILE" in e])
files = {"/run/secrets/db_password": "value-injected-at-run-time"}  # a tmpfs file in real life
print("app reads DB_PASSWORD via the _FILE convention:", lf.read_secret("DB_PASSWORD", {"DB_PASSWORD_FILE": "/run/secrets/db_password"}, files.__getitem__))
print("\nREMEMBER: everything that leaked must be rotated. Fixing the file does not un-leak the old value.")

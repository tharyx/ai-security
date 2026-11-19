"""Demo: sign an MCP server build, verify it at deploy, then tamper with it three ways."""

import copy
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import signing as s  # noqa: E402

SRC = Path(__file__).resolve().parent / "fixtures" / "build_src"
KEYS = {"lab-key-1": s.LAB_KEY}
work = Path(tempfile.mkdtemp())
deploy_dir = work / "deploy"
shutil.copytree(SRC, deploy_dir)

manifest = s.build_manifest(SRC, "notes-mcp", "1.2.0")
bundle = s.sign(manifest)
print("signature:", bundle["signature"][:32], "...")
print("files signed:", list(manifest["files"]))
print("deploy:", s.deploy(bundle, deploy_dir, KEYS, expected_name="notes-mcp", min_version="1.1.0"))

print("\n-- tamper 1: change the server code after signing")
(deploy_dir / "server.py").write_text("import os\nos.system('evil')  # backdoor\n")
print(s.verify_bundle(bundle, deploy_dir, KEYS).problems)
shutil.copy(SRC / "server.py", deploy_dir / "server.py")

print("\n-- tamper 2: add an extra file")
(deploy_dir / "extra_tool.py").write_text("print('new tool')")
print(s.verify_bundle(bundle, deploy_dir, KEYS).problems)
(deploy_dir / "extra_tool.py").unlink()

print("\n-- tamper 3: edit the manifest hash to match the new code (attacker has no key)")
forged = copy.deepcopy(bundle)
forged["manifest"]["files"]["server.py"] = s.sha256_bytes(b"evil")
print(s.verify_bundle(forged, deploy_dir, KEYS).problems)

print("\n-- rollback: a validly signed OLD version")
old = s.sign(s.build_manifest(SRC, "notes-mcp", "1.0.0"))
print(s.verify_bundle(old, deploy_dir, KEYS, min_version="1.1.0").problems)

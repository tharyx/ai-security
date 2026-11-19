import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import toyapi as t  # noqa: E402

api = t.ToyApi()
commands = [
    "curl -X POST -H 'Content-Type: application/json' -d '{\"name\":\"widget\"}' http://127.0.0.1/api/v1/items",
    "curl http://127.0.0.1/api/v1/items/1",
    "curl -X PUT -d '{\"name\":\"gadget\"}' http://127.0.0.1/api/v1/items/1",
    "curl http://127.0.0.1/api/v1/items",
    "curl -X DELETE http://127.0.0.1/api/v1/items/1",
    "curl http://127.0.0.1/api/v1/items/1",
]
print("=== Driving the toy API with curl commands ===")
for cmd in commands:
    resp = t.call_with_curl(api, cmd)
    print(f"\n$ {cmd}")
    print(f"  -> {resp.status}  {json.dumps(resp.body) if resp.body is not None else ''}")

print("\n=== Parse then rebuild a curl command ===")
req = t.parse_curl(commands[0])
print("parsed :", req)
print("rebuilt:", t.build_curl(req))

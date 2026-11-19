import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import mock_api
import scanner

# a port nobody listens on: bind then release
s = socket.socket(); s.bind(("127.0.0.1", 0)); closed_port = s.getsockname()[1]; s.close()

with mock_api.MockDockerServer(auth_token=None) as open_srv, mock_api.MockDockerServer(auth_token="s3cret-canary") as locked_srv:
    targets = [("127.0.0.1", open_srv.port), ("127.0.0.1", locked_srv.port), ("127.0.0.1", closed_port), ("203.0.113.10", 2375), ("example.com", 2375)]
    for r in scanner.scan(targets):
        print(f"{r['endpoint']:<22} {r['state']}")
        for e in r["evidence"]:
            print("    ", e[:110])
        if "impact" in r:
            print("     impact:", r["impact"][:100])

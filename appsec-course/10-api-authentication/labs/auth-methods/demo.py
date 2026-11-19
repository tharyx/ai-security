import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import authapi as a  # noqa: E402

api = a.AuthApi()


def show(label, result):
    status, _, body = result
    print(f"  {label:<44} -> {status} {body}")


print("=== No authentication ===")
show("GET /public", api.handle("GET", "/public"))

print("\n=== HTTP Basic ===")
show("GET /basic (right user:pass)", api.handle("GET", "/basic", a.basic_header(api.basic_user, api.basic_pass)))
show("GET /basic (wrong password)", api.handle("GET", "/basic", a.basic_header(api.basic_user, "nope")))

print("\n=== API key ===")
show("GET /apikey  X-API-Key header", api.handle("GET", "/apikey", {"X-API-Key": api.api_key}))
show("GET /apikey?api_key=... (in the URL)", api.handle("GET", "/apikey?api_key=" + api.api_key))

print("\n=== OAuth 2.0 client_credentials -> JWT bearer ===")
body = (f"grant_type=client_credentials&client_id={api.client_id}"
        f"&client_secret={api.client_secret}&scope=orders:read")
status, headers, resp = api.handle("POST", "/oauth/token", body=body)
print(f"  POST /oauth/token -> {status} token_type={resp['token_type']} "
      f"expires_in={resp['expires_in']} Cache-Control={headers['Cache-Control']}")
tok = resp["access_token"]
show("GET /bearer (issued token)", api.handle("GET", "/bearer", {"Authorization": "Bearer " + tok}))
show("GET /bearer (signature tampered)", api.handle("GET", "/bearer", {"Authorization": "Bearer " + tok[:-4] + "AAAA"}))

print("\n=== Mutual TLS (simulated) ===")
show("GET /mtls (verified cert from TLS layer)", api.handle("GET", "/mtls", tls_client_fp=api.trusted_client_fp))
show("GET /mtls (client sends X-Client-Cert header)", api.handle("GET", "/mtls", {"X-Client-Cert": api.trusted_client_fp}))

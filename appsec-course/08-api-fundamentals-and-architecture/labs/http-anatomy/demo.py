import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import httpmsg as h  # noqa: E402

token = h.make_fake_token()

raw_req = (
    f"GET /api/v1/orders/42 HTTP/1.1\r\n"
    f"Host: shop.example\r\n"
    f"Authorization: Bearer {token}\r\n"
    f"Accept: application/json\r\n\r\n"
)

print("=== Request anatomy ===")
req = h.parse_request(raw_req)
print("method :", req.method)
print("target :", req.target)
print("version:", req.version)
print("headers:", req.headers)

print("\n=== Response codes ===")
for code in (200, 201, 301, 401, 404, 429, 500):
    print(f"  {code} {h.STATUS_TEXT[code]:<22} -> {h.status_class(code)}")

print("\n=== Stateless API (token on every call, no server memory) ===")
api = h.StatelessApi({token})
with_tok = h.parse_request(f"GET /me HTTP/1.1\r\nAuthorization: Bearer {token}\r\n\r\n")
no_tok = h.parse_request("GET /me HTTP/1.1\r\n\r\n")
print("with token :", api.handle(with_tok).status)
print("no token   :", api.handle(no_tok).status)
print("server_state_entries:", api.server_state_entries)

print("\n=== Stateful API (server-side session keyed by cookie) ===")
sapi = h.StatefulApi()
login = sapi.login("alice")
sid = login.header("set-cookie").split("session=", 1)[1].split(";", 1)[0]
print("Set-Cookie :", login.header("set-cookie"))
good = h.parse_request(f"GET /me HTTP/1.1\r\nCookie: session={sid}\r\n\r\n")
print("with cookie:", sapi.handle(good).status, "->", sapi.handle(good).body)
print("server_state_entries:", sapi.server_state_entries)

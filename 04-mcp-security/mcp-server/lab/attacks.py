"""Attack inputs for the MCP server-trust lab.

The malicious *servers* live in servers.py (typosquat, impostor, shadow, rug pull).
This file holds the HTTP requests used against a local Streamable HTTP server.
All hosts are reserved .example names or private lab addresses. Nothing is sent anywhere.
"""

LOCAL_PORT = 8765
LOCAL_TOKEN = "lab-local-token-not-a-real-secret"  # the per-launch token a local server would print

# Each case: (bind address of the local server, headers of the incoming request)
HTTP_REQUESTS = {
    # A web page on evil.example re-points its DNS name to 127.0.0.1 after loading.
    # The browser now sends requests to the local server, but the Host header still
    # says rebind.evil.example.
    "dns_rebinding": ("127.0.0.1", {
        "Host": f"rebind.evil.example:{LOCAL_PORT}",
        "Origin": f"http://rebind.evil.example:{LOCAL_PORT}",
    }),
    # A page on evil.example sends a "simple" cross-site POST straight to localhost.
    "browser_drive_by": ("127.0.0.1", {
        "Host": f"localhost:{LOCAL_PORT}",
        "Origin": "https://evil.example",
    }),
    # The server listens on all interfaces; another machine on the café Wi-Fi calls it.
    "lan_exposure": ("0.0.0.0", {
        "Host": f"192.168.1.20:{LOCAL_PORT}",
    }),
}

# The desktop host itself: no browser Origin, correct Host, the launch token.
BENIGN_REQUEST = ("127.0.0.1", {
    "Host": f"localhost:{LOCAL_PORT}",
    "Authorization": f"Bearer {LOCAL_TOKEN}",
})

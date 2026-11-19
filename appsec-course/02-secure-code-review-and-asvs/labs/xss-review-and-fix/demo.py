import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import render  # noqa: E402

print("Clean user, secure page:")
print(" ", render.page_secure(render.SAFE_USER))
print("  findings:", render.xss_findings(render.page_secure(render.SAFE_USER)))
print()
for field, payload in render.PAYLOADS.items():
    u = render.with_payload(field)
    print(f"[{field}] payload: {payload}")
    print("   vuln findings  :", render.xss_findings(render.page_vuln(u)))
    print("   secure findings:", render.xss_findings(render.page_secure(u)))

breakout = dict(render.SAFE_USER, nickname="</script><script>alert(1)</script>")
print("\n[nickname] </script> breakout")
print("   vuln findings  :", render.xss_findings(render.page_vuln(breakout)))
print("   secure output  :", render.page_secure(breakout).split("<p")[0].split("</div>")[1])
print("   secure findings:", render.xss_findings(render.page_secure(breakout)))

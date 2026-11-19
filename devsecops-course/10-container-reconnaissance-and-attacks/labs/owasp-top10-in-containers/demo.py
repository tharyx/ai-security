import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import owasp_containers as oc

for code, name, container_angle, lab in oc.TOP10[:3]:
    print(f"{code} {name}: {container_angle[:70]}...")
print("... (10 rows in total)\n")
print("SSRF to the metadata service from a container app:")
for scenario, url, status in oc.ssrf_matrix():
    verdict = {200: "fetched normally" if scenario.endswith("legit") else "LEAK (credentials returned)", 401: "stopped (token needed)", 403: "stopped (filter)"}[status]
    print(f"  {scenario:<52} {status}  {verdict}")
print("\nWhat 'LEAK' looks like (canary values):", oc.role_credentials())

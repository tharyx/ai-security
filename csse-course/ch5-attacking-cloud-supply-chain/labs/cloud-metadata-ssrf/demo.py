"""Demo: SSRF against IMDSv1, IMDSv2, Azure and GCP simulations."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import imds  # noqa: E402

URL = "http://169.254.169.254/latest/meta-data/iam/security-credentials/web-role"
for label, svc in (("IMDSv1 (optional)", imds.AwsIMDS(v2_required=False)), ("IMDSv2 (required)", imds.AwsIMDS(v2_required=True))):
    net = imds.Network(aws=svc)
    code, body = imds.vulnerable_preview(net, URL)
    print(f"{label:18} simple GET SSRF -> {code} {body[:48]}")

net = imds.Network(aws=imds.AwsIMDS(v2_required=True, hop_limit=1))
code, _ = net.request("PUT", "http://169.254.169.254/latest/api/token", {"X-aws-ec2-metadata-token-ttl-seconds": "60"}, hops=2)
print("IMDSv2 token request from a container (2 hops) ->", code, "(dropped)")

net = imds.Network(azure=imds.AzureIMDS(), gcp=imds.GcpMetadata())
az = "http://169.254.169.254/metadata/instance"
gcp = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
print("Azure GET without Metadata header ->", imds.vulnerable_preview(net, az)[0])
print("Azure with attacker-set header    ->", imds.vulnerable_preview(net, az, True)[0])
print("GCP no Metadata-Flavor            ->", imds.vulnerable_preview(net, gcp)[0])
print("safe_preview, decimal-IP form     ->", imds.safe_preview(imds.Network(aws=imds.AwsIMDS()), "http://2852039166/latest/meta-data/")[0])

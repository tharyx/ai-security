import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import reset as r  # noqa: E402

NOW = 1_700_000_000
print("=== Vulnerable reset ===")
v = r.VulnerableReset({"alice": "old-password-value"})
print("  request(ghost):", v.request("ghost", "shop.lab.example", NOW))
print("  request(alice, Host: evil.attacker.example):", v.request("alice", "evil.attacker.example", NOW))
print("  emailed link :", v.outbox[-1][1])
guess = r.VulnerableReset.make_token("alice", NOW)
print("  attacker-predicted token:", guess)
print("  confirm(guess) ->", v.confirm(guess, "attacker-pw", NOW + 5), "| alice's password now:", v.users["alice"])
print("  reuse 10 days later ->", v.confirm(guess, "again", NOW + 864000))

print("\n=== Secure reset ===")
s = r.SecureReset({"alice": "old-password-value"})
print("  request(ghost):", s.request("ghost", "evil.attacker.example", NOW))
print("  request(alice):", s.request("alice", "evil.attacker.example", NOW))
link = s.outbox[-1][1]
print("  emailed link :", link[:60] + "...")
tok = r.token_from_link(link)
print("  predicted token works? ->", s.confirm(guess, "a-new-long-passphrase", NOW))
s.request("alice", "h", NOW)
tok = r.token_from_link(s.outbox[-1][1])
print("  real token, first use ->", s.confirm(tok, "a-new-long-passphrase", NOW + 60))
print("  same token, reuse     ->", s.confirm(tok, "another-long-passphrase", NOW + 61))

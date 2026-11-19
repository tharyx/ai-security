# Marketplace skill scan

Scanned **301** skills: block=6, review=28, allow=267

## Findings by rule

| rule | skills |
|---|---|
| unknown_domain | 11 |
| pipe_to_shell | 6 |
| credential_paths | 6 |
| encoded_blob | 6 |
| injection_text | 5 |
| hidden_unicode | 5 |
| typosquat | 1 |

## Top 10 by risk

| skill | score | verdict | why |
|---|---|---|---|
| skill-0010 | 85 | block | pipe_to_shell; unknown_domain |
| skill-0043 | 85 | block | pipe_to_shell; unknown_domain |
| skill-0096 | 85 | block | pipe_to_shell; unknown_domain |
| skill-0154 | 85 | block | pipe_to_shell; unknown_domain |
| skill-0205 | 85 | block | pipe_to_shell; unknown_domain |
| skill-0257 | 85 | block | pipe_to_shell; unknown_domain |
| skill-0015 | 50 | review | credential_paths |
| skill-0056 | 50 | review | credential_paths |
| skill-0130 | 50 | review | credential_paths |
| skill-0164 | 50 | review | credential_paths |

_Triage only: a clean scan is not a safety guarantee._

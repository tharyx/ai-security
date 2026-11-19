# Agent trace dashboard

Traces: 3

## Findings

- **new_tool** (odd-1): tool 'http_post' never seen in baseline
- **new_tool** (odd-1): tool 'run_shell' never seen in baseline
- **new_decision** (odd-1): decision 'override_policy' never seen in baseline
- **new_tool** (odd-2): tool 'http_post' never seen in baseline
- **new_tool** (odd-2): tool 'run_shell' never seen in baseline
- **step_outlier** (odd-2): 22 spans (z=11.3)
- **new_tool** (odd-3): tool 'http_post' never seen in baseline
- **new_tool** (odd-3): tool 'run_shell' never seen in baseline
- **tool_mix_drift** (window): total variation distance 0.93 > 0.3

## Tool usage

| tool | calls |
|---|---|
| run_shell | 8 |
| http_post | 6 |
| search_kb | 1 |

### odd-1 (support-agent)

- `plan` plan: handle ticket (100 ms)
  - `llm` model (200 ms)
    - `tool` search_kb (100 ms)
  - `llm` model (200 ms)
    - `tool` run_shell (100 ms)
  - `llm` model (200 ms)
    - `tool` http_post (100 ms)
  - `decision` override_policy (10 ms)

### odd-2 (support-agent)

- `plan` plan: handle ticket (100 ms)
  - `llm` model (200 ms)
    - `tool` run_shell (100 ms)
  - `llm` model (200 ms)
    - `tool` run_shell (100 ms)
  - `llm` model (200 ms)
    - `tool` run_shell (100 ms)
  - `llm` model (200 ms)
    - `tool` run_shell (100 ms)
  - `llm` model (200 ms)
    - `tool` run_shell (100 ms)
  - `llm` model (200 ms)
    - `tool` run_shell (100 ms)
  - `llm` model (200 ms)
    - `tool` http_post (100 ms)
  - `llm` model (200 ms)
    - `tool` http_post (100 ms)
  - `llm` model (200 ms)
    - `tool` http_post (100 ms)
  - `llm` model (200 ms)
    - `tool` http_post (100 ms)
  - `decision` answer (10 ms)

### odd-3 (support-agent)

- `plan` plan: handle ticket (100 ms)
  - `llm` model (200 ms)
    - `tool` http_post (100 ms)
  - `llm` model (200 ms)
    - `tool` run_shell (100 ms)
  - `decision` answer (10 ms)

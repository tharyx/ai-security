# Real tools: AI detections and SOAR in Microsoft Sentinel and Splunk

> **Brightix module 6** · [BX 6] SIEM/SOAR Alerting & AI Incident Response Lifecycle
> **Lab this guide mirrors:** [ai-soar-playbooks](../labs/ai-soar-playbooks/README.md) (same field names, same rules, same playbooks)
> **Background:** [SIEM, Sentinel and Splunk track](../../../cybersecurity-track/06-siem-sentinel-splunk/README.md) · [KQL/SPL cheat sheet](../../../cybersecurity-track/06-siem-sentinel-splunk/05-kql-spl-cheat-sheet.md) · [MCP logging, monitoring and detection](../../../cmcpse-course/ch4-defending-and-hardening-mcp-servers/06-logging-monitoring-detection.md) · [AI incident playbook template](../../../00-program/templates/ai-incident-playbook.md)

**Read this first.** Everything below is a sketch to adapt, not copy-paste production content. Table names, connector names, portal menus, function names and SOAR APIs change often (Sentinel now lives in the Microsoft Defender portal for most tenants; Splunk SOAR block names differ between versions). **Verify every command, function and menu against the vendor documentation (or `--help`) for your version.** Test only on systems you own or have written permission to test. The repository's tests never need Sentinel or Splunk.

## 1. Get the AI telemetry in

| Source (lab file) | Sentinel (verify) | Splunk (verify) |
|---|---|---|
| LLM app gateway (`llm_app.jsonl`) | Logs Ingestion API + data collection rule (DCR) into a custom table, for example `AIAppTelemetry_CL`; or diagnostic settings if your AI platform offers them | HTTP Event Collector (HEC), `sourcetype=ai:llm_app` |
| Agent runtime (`agent_runtime.jsonl`) | Same DCR, or OpenTelemetry to Azure Monitor (Application Insights traces) | HEC, `sourcetype=ai:agent`, or the OpenTelemetry Collector |
| MCP gateway (`mcp_gateway.jsonl`) | Custom table `MCPGateway_CL` | HEC, `sourcetype=ai:mcp_gateway` |
| Platform AI alerts | Defender for Cloud AI threat protection alerts may arrive through the Defender XDR connector (check availability) | Add-on for your cloud provider |

To practise without a cloud tenant: a free Splunk trial (upload the three `.jsonl` files), or an Azure Data Explorer free cluster where you can ingest JSON and run KQL. The lab's `make_fixtures.py` produces the files.

## 2. Normalise once (the lab's `pipeline.load_events`)

**Sentinel:** save a KQL function (a "parser") called `AISecEvents` that unions the tables and renames columns to one schema. Detection rules then query only `AISecEvents`.

```kql
// Saved as function: AISecEvents  (column names assume DCR transforms kept the raw JSON names)
let llm = AIAppTelemetry_CL
    | project TimeGenerated, Source = "llm_app", Kind = "llm_request", Tenant = tenant, User = user,
              Session = session, TraceId = trace_id, PromptSha = tostring(prompt.sha256),
              PromptTokens = toint(prompt.tokens), CompletionTokens = toint(completion.tokens),
              LatencyMs = toint(latency_ms), GuardInput = tostring(guardrail.input),
              GuardContext = tostring(guardrail.context), Flags = completion.flags,
              Docs = retrieval.docs, SysPromptVer = sys_prompt_ver;
let agent = AgentRuntime_CL
    | project TimeGenerated, Source = "agent_runtime", Kind = "tool_call", Tenant = tenant_id,
              User = on_behalf_of, Session = session_id, TraceId = trace_id, Agent = agent, Tool = tool,
              Dest = tostring(parse_url(target).Host), Decision = decision, Taint = taint,
              BytesOut = tolong(bytes_out), Rows = toint(rows_returned);
let mcp = MCPGateway_CL
    | project TimeGenerated, Source = "mcp_gateway", Kind = iff(method == "tools/list", "mcp_list", "mcp_call"),
              Tenant = tenant, User = user, TraceId = trace_id, Agent = client, Tool = strcat(server, "/", tool),
              DescSha = desc_sha256, PinnedSha = pinned_sha256, Rows = toint(rows);
union llm, agent, mcp
```

**Splunk:** a search macro `ai_events` that searches the three sourcetypes and uses `eval`/`rename` (or field aliases in `props.conf`) to give the same names: `kind`, `user`, `session`, `trace_id`, `tokens`, `guard_context`, `docs`, `tool`, `dest`, `taint`, `desc_sha`, `pinned_sha`, `rows`. If you use Splunk Enterprise Security, map what you can to the Common Information Model (CIM) as well.

## 3. The tuned rules in KQL and SPL

Each rule below matches one function in `pipeline.py`. Keep the ATLAS technique name and OWASP name in the rule description or custom details (Sentinel's built-in tactic field is MITRE ATT&CK, not ATLAS).

### 3.1 `exfil_untrusted_egress`: tool call to a host outside the allow-list (critical if tainted)

```kql
let allow = toscalar(_GetWatchlist('EgressAllowlist') | summarize make_list(tostring(SearchKey)));
let injected = AISecEvents
    | where TimeGenerated > ago(1h) and Kind == "llm_request" and GuardContext == "flag"
    | summarize InjectedDocs = make_set(Docs) by TraceId;
AISecEvents
| where TimeGenerated > ago(1h) and Kind == "tool_call" and Dest contains "."
| extend Parent = strcat_array(array_slice(split(Dest, "."), 1, 20), ".")
| where array_length(set_intersect(allow, pack_array(Dest, Parent))) == 0   // host or its parent domain allowed?
| join kind=leftouter injected on TraceId
| extend Severity = iff(Taint != "none" or isnotempty(InjectedDocs), "Critical", "High")
| project TimeGenerated, User, Agent, Tool, Dest, BytesOut, TraceId, InjectedDocs, Severity
```

```spl
`ai_events` kind=tool_call dest="*.*"
| lookup egress_allowlist domain AS dest OUTPUT domain AS allowed
| eval parent=replace(dest, "^[^.]+\.", "")
| lookup egress_allowlist domain AS parent OUTPUT domain AS allowed_parent
| where isnull(allowed) AND isnull(allowed_parent)
| join type=left trace_id [ search `ai_events` kind=llm_request guard_context=flag | stats values(docs) AS injected_docs by trace_id ]
| eval severity=if(taint!="none" OR isnotnull(injected_docs), "critical", "high")
| table _time user agent tool dest bytes_out trace_id injected_docs severity
```

### 3.2 `token_burst`: 10-minute token sum vs the user's own baseline (cost-DoS)

```kql
let baseline = AISecEvents
    | where TimeGenerated between (ago(7d) .. ago(1h)) and Kind == "llm_request"
    | summarize Baseline = percentile(PromptTokens + CompletionTokens, 50) by User;
AISecEvents
| where TimeGenerated > ago(1h) and Kind == "llm_request"
| summarize Tokens = sum(PromptTokens + CompletionTokens), Requests = count() by User, bin(TimeGenerated, 10m)
| join kind=leftouter baseline on User
| extend Limit = max_of(100000.0, 10.0 * coalesce(Baseline, 0.0))
| where Tokens > Limit
```

`bin()` gives tumbling windows; a burst that straddles two bins can hide. The lab uses a rolling window. In SPL, `streamstats time_window=10m` gives a rolling sum (it needs events in time order; verify):

```spl
`ai_events` kind=llm_request
| eval tokens=prompt_tokens+completion_tokens
| sort 0 _time
| streamstats time_window=10m sum(tokens) AS tokens_10m count AS req_10m by user
| lookup ai_user_baseline user OUTPUT median_tokens
| eval limit=max(100000, 10*coalesce(median_tokens, 0))
| where tokens_10m > limit
| stats min(_time) AS first_seen max(tokens_10m) AS peak_tokens max(req_10m) AS peak_requests by user
```

Build `ai_user_baseline` with a scheduled search that writes `median(tokens)` per user to a lookup (`outputlookup`) every night.

### 3.3 `canary_leak`, `mcp_pin_mismatch`, `bulk_tool_read`

```kql
AISecEvents | where Kind == "llm_request" and Flags has "canary_hit"
| project TimeGenerated, User, Session, SysPromptVer

AISecEvents | where Kind in ("mcp_list", "mcp_call") and isnotempty(PinnedSha) and DescSha != PinnedSha
| summarize FirstSeen = min(TimeGenerated), Calls = countif(Kind == "mcp_call") by Tool, DescSha, PinnedSha

AISecEvents | where Kind == "mcp_call" and Rows > 1000
| project TimeGenerated, User, Agent, Tool, Rows, TraceId
```

```spl
`ai_events` kind=llm_request flags="canary_hit" | table _time user session sys_prompt_ver
`ai_events` kind IN ("mcp_list","mcp_call") pinned_sha=* | where desc_sha!=pinned_sha | stats min(_time) AS first_seen count(eval(kind="mcp_call")) AS calls by tool desc_sha pinned_sha
`ai_events` kind=mcp_call rows>1000 | table _time user agent tool rows trace_id
```

The gateway must log the **pinned** hash next to the observed one. Comparing with "the last description we saw" fires on every approved update (the lab's naive rule).

### 3.4 `shared_poisoned_doc` and `repeated_guard_blocks`

```kql
AISecEvents
| where TimeGenerated > ago(2h) and Kind == "llm_request" and GuardContext == "flag"
| mv-expand Doc = Docs to typeof(string)
| summarize Users = dcount(User), Who = make_set(User), First = min(TimeGenerated) by Doc
| where Users >= 3

let redteam = _GetWatchlist('RedTeamAccounts') | project User = tostring(SearchKey);
AISecEvents
| where TimeGenerated > ago(30m) and Kind == "llm_request" and GuardInput == "block"
| where User !in (redteam)
| summarize Blocks = count() by User
| where Blocks >= 3
```

```spl
`ai_events` kind=llm_request guard_context=flag earliest=-2h
| mvexpand docs
| stats dc(user) AS users values(user) AS who min(_time) AS first_seen by docs
| where users>=3

`ai_events` kind=llm_request guard_input=block earliest=-30m NOT [| inputlookup redteam_accounts | fields user]
| stats count AS blocks by user | where blocks>=3
```

Give every watchlist or lookup entry an owner, a ticket and an **expiry date**. A permanent red-team exclusion is a blind spot attackers love.

## 4. From rule to incident (correlation and risk)

**Sentinel analytics rule (scheduled), suggested settings:**

| Setting | Value for the lab rules | Why |
|---|---|---|
| Run every / look back | 5 min / 1 h (token burst, exfil); 1 h / 2 h (poisoned doc) | Lookback longer than the frequency so nothing falls in a gap |
| Entity mapping | Account = `User`; URL or DNS = `Dest`; custom: `TraceId`, `Tool`, `Doc` | Entities drive incident grouping and investigation graphs |
| Custom details | ATLAS technique name, OWASP name, `Severity` | ATLAS has no native field in Sentinel |
| Alert grouping | Group alerts into one incident when entities match, within 2-5 h | The lab's `correlate()`: one incident per trace/doc/tool, not per alert |
| Suppression | On for the same entity for 1 h | Same as the lab's "one alert per user per run" |

**Splunk Enterprise Security:** use risk-based alerting (RBA). Each rule adds a risk score to a risk object (user, agent, MCP tool) in the risk index; a second correlation search raises a notable only when an object's accumulated score passes a threshold. That is the lab's `build_risk()`. RBA scores do not decay by themselves: use a time-bounded window in the threshold search (for example the last 24 h) or weight by age with `eval`. Verify the current RBA configuration steps in the ES docs.

## 5. SOAR: Sentinel automation rule + Logic App playbook (idea, verify)

An **automation rule** runs when an incident is created with a tag such as `ai-incident` and calls a **playbook** (a Logic App). Outline of the flow, mirroring `PB-05-mcp-rug-pull` in the lab:

```text
Trigger: Microsoft Sentinel incident (called by the automation rule)
1. Enrich        Get incident entities; look up the user in a watchlist / Entra ID; look up Dest in threat intel
2. Evidence      Run a KQL query for every event in the incident's TraceId values
                 -> write JSON to an immutable (WORM) storage container; store its SHA-256 in an incident comment
3. Notify        Post to the SOC channel (Teams)
4. Approval      "Post adaptive card and wait for a response" to the SOC lead (timeout = escalate, never auto-approve)
5. Contain       If approved: HTTP action (managed identity) to YOUR AI gateway admin API:
                   disable MCP tool <Tool> | revoke agent token <Agent> | block egress <Dest>
                 If denied or timed out: add a comment, leave the step open
6. Close loop    Add a comment with every action and approver; update incident status/owner
```

AI-specific containment usually needs your own API (an AI gateway, the MCP gateway, the vector store's quarantine and re-index job, the prompt registry's rollback). Logic Apps call it; they do not know about MCP by themselves. Lint playbooks in code review: no destructive action before evidence, no destructive action without an approval.

## 6. SOAR: Splunk SOAR playbook (idea, verify)

Splunk SOAR playbooks are Python, built visually from blocks (action, decision, filter, format, prompt, utility). A sketch of `PB-04-poisoned-doc`, **pseudo-code, not a runnable playbook**:

```python
# on_start: container = the notable / event, artifacts include doc_id and affected users
def on_start(container):
    preserve_evidence(container)            # action block: run a Splunk query for the doc's retrievals,
                                            # save results as a vault file, record the SHA-256
    notify_soc(container)                   # action block: post to chat / email
    ask_content_owner(container)            # PROMPT block: approver = content owner, with a timeout

def ask_content_owner_callback(container, response):
    if response == "approve":
        quarantine_doc(container)           # action block: HTTP call to your vector-store admin API
        reindex(container)                  # action block: start the re-index job
        verify_not_retrievable(container)   # action block: query the retriever for the doc id
    else:
        add_note(container, "quarantine denied or timed out; doc still live")
```

## 7. Same idea in Google SecOps (YARA-L, verify syntax)

```text
rule ai_shared_poisoned_doc {
  meta:
    atlas = "RAG Poisoning"
  events:
    $e.metadata.product_name = "helpdesk-copilot"
    $e.additional.fields["guard_context"] = "flag"
    $e.additional.fields["doc"] = $doc
    $e.principal.user.userid = $user
  match:
    $doc over 2h
  condition:
    #user >= 3
}
```

## 8. Lab-to-product map

| Lab (`pipeline.py` / `soar.py`) | Sentinel | Splunk |
|---|---|---|
| `norm_llm`, `norm_agent`, `norm_mcp` | DCR transforms + `AISecEvents` function | props/transforms, field aliases, `ai_events` macro |
| `fixtures/watchlists.json` | Watchlists (`_GetWatchlist`) | Lookups (`inputlookup`, `lookup`) |
| tuned rules | Scheduled analytics rules | Correlation searches (ES) / saved searches |
| `build_risk` (decay) | UEBA scores, or your own scoring query | Risk-based alerting (risk index) |
| `correlate` | Alert grouping into incidents | Notables grouped by risk object / episodes |
| `Engine.run` + approval gates | Automation rule -> Logic App, adaptive card approval | SOAR playbook with prompt block |
| `EvidenceStore` | Immutable storage + hash in incident comment | SOAR vault + hash in a note |
| `ir_report.render` | Incident timeline + workbook | Mission Control / investigation timeline |

## 9. Check your port against the lab

Load the fixtures, run your queries over the lab's morning (2026-11-10, 08:00-12:00 UTC), and compare with `demo.py`: the tuned set should raise **7 alerts, 0 false positives, 5 incidents**. If your numbers differ, find out why before you trust the rule on production data. That is detection engineering: rules are code, and code has tests.

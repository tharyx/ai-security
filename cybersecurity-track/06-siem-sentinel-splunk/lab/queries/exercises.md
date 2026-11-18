# KQL and SPL exercises (12 questions)

Same questions, two languages. Use the real tools. Then check your answers with `check_answers.py`.
All data is synthetic (fake users, IPs from documentation ranges, `*.example` domains).

## 0. Load the data

### KQL (no ingestion needed)
Open one of these (all free):
- Azure Data Explorer free cluster: https://dataexplorer.azure.com (sign in with any Microsoft account)
- The Log Analytics demo workspace (search "Log Analytics demo environment" on Microsoft Learn)
- Your own Sentinel / Log Analytics workspace (query window)

Paste the whole content of `events_datatable.kql` at the top of the query window, then write your
query under it. It defines a table called `Events` with these columns:

| Column | Meaning |
|---|---|
| TimeGenerated (datetime, UTC) | event time |
| Source | `windows`, `entra`, `firewall`, `linux` |
| Action | `logon_failure`, `logon_success`, `group_add`, `process_create`, `network_allow`, `network_deny` |
| Host, User, SrcIp, DstIp, DstPort, Country | the usual fields |
| Process, ParentProcess, CommandLine | for process creation |
| Group, Member | for group changes |
| BytesOut | bytes sent (firewall) |

### SPL (Splunk Free or trial)
1. Settings > Add Data > Upload > choose `events.csv`.
2. Set the source type: new name `lab_events`. Check that the timestamp field is `ts`. Index: `main`.
3. Set your Splunk user time zone to UTC (Preferences), or hour questions will be shifted.
4. Search with `index=main sourcetype=lab_events`.

Field names in SPL are lowercase with small changes (`source` is a Splunk reserved word):
`ts, log_source, action, hostname, user, src_ip, dst_ip, dst_port, country, process, parent_process,
command_line, group_name, member, bytes_out`.

## 1. Questions

| # | Question | Answer type |
|---|---|---|
| Q1 | How many failed Windows logons are there in total? | number |
| Q2 | Which source IP has the most failed Windows logons? | IP |
| Q3 | How many different accounts failed to sign in to Entra ID from 198.51.100.66? | number |
| Q4 | Which user signed in successfully (Entra) from two different countries within 60 minutes? | user name |
| Q5 | Which member was added to the Domain Admins group? | user name |
| Q6 | How many process-creation events run PowerShell with an encoded command? | number |
| Q7 | On which host did an encoded PowerShell command run with WINWORD.EXE as parent? | host name |
| Q8 | Which allowed outbound destination port is not in the common list (53, 80, 123, 443, 8080, 8443)? | port |
| Q9 | How many MB (1 MB = 1,000,000 bytes) were allowed to 203.0.113.80? | number |
| Q10 | How many different source IPs have failed SSH logons on Linux? | number |
| Q11 | Which UTC hour (0-23) has the most failed logons across all sources? | number |
| Q12 | Which account had a successful Entra sign-in from the spraying IP 198.51.100.66? | user name |

Hints: Q4 needs `prev()` (KQL) or `streamstats` (SPL). Q6 needs a case-insensitive text match.
Q9 needs `sum()`. Q11 needs `hourofday()` (KQL) or `strftime()` (SPL).

## 2. Check yourself

```text
copy answers_template.json answers.json      (then fill in your answers)
python check_answers.py answers.json
```

Solutions (try first!): `solutions.kql` and `solutions.spl`.

# 05 · KQL and SPL side by side: the 20 most common SOC queries

> **Module:** 06 · SIEM, Sentinel and Splunk · **Weeks:** 9-10 · **Time:** ~8 hours
> **You will:** translate between KQL (Sentinel, Defender) and SPL (Splunk) and write the 20 queries that SOC analysts use every week.

| | |
|---|---|
| **Prerequisites** | Lessons 03 and 04 |
| **Lab** | [`lab/queries/`](lab/queries/): 12 exercises in both languages, with `solutions.kql`, `solutions.spl` and `check_answers.py` |
| **Maps to** | SC-200 (KQL for detection and hunting); Splunk Core Certified Power User topics; interview preparation |

---

## 1. Why it matters in a SOC / cloud-security job

Teams change tools. A SOC analyst who thinks in *questions* ("which IP failed against many users?") and can say them in two languages is valuable in any company. This page is a cheat sheet to keep open during your first months.

**Important:** table and field names depend on how your company onboarded the data. The queries below use the common Microsoft table names (`SigninLogs`, `SecurityEvent`, `CommonSecurityLog`, `DeviceProcessEvents`) and typical Splunk CIM-style fields for Windows data (`user`, `src`, `host`) or the Entra add-on fields. Always check the real field names with `| take 5` (KQL) or `| head 5` (SPL) first.

---

## 2. Understand it

### 2.1 Translation table

| Task | KQL | SPL |
|---|---|---|
| Choose data | `SigninLogs` (table name) | `index=... sourcetype=...` |
| Time filter | `where TimeGenerated > ago(24h)` | `earliest=-24h` (or the time picker) |
| Filter | `where Field == "x"` | `Field=x` or `\| where Field=="x"` |
| Case-insensitive equal | `=~` | search is case-insensitive; `where` is case-sensitive (use `lower()`) |
| Contains text | `contains` / `has` | `Field="*text*"` or `like()` / `match()` |
| In a list | `in ("a","b")` | `Field IN ("a","b")` |
| Not in a list | `!in` | `NOT Field IN (...)` |
| Pick columns | `project A, B` | `table A B` or `fields A B` |
| New field | `extend X = a + b` | `eval X = a + b` |
| Count rows | `count` | `stats count` |
| Group | `summarize count() by A` | `stats count by A` |
| Distinct count | `dcount(A)` | `dc(A)` |
| Values list | `make_set(A)` | `values(A)` |
| Time buckets | `bin(TimeGenerated, 10m)` | `bin _time span=10m` or `timechart span=10m` |
| Sort | `sort by n desc` | `sort - n` (use `sort 0 - n` for no limit) |
| Top N | `top 10 by n desc` | `sort 10 - n` or `top 10 A` |
| Unique rows | `distinct A, B` | `dedup A B` or `stats count by A B` |
| Join | `join kind=inner T2 on Key` | `lookup` (small), `join` (slow), or `stats` over `append` |
| Extract with regex | `extract("re", 1, s)` / `parse` | `rex field=... "re"` |
| Previous row | `prev(Field)` after `sort` | `streamstats current=f last(Field) as prev` |
| Having | `where n >= 10` after `summarize` | `where n>=10` after `stats` |
| Inline data | `datatable(...)[...]` | `\| makeresults` / upload CSV |
| Chart | `render timechart` | `timechart` |
| Time zone | UTC always | user setting! set UTC |

Mental model: **KQL is verbose and typed, SPL is compact and search-first.**

### 2.2 The 20 queries

Each query answers a SOC question. Replace names with those of your environment. Time ranges are examples.

**1. Failed logons on Windows (last 24h)**
```kusto
SecurityEvent
| where TimeGenerated > ago(24h) and EventID == 4625
| summarize Failures = count() by Account, IpAddress, Computer
| top 20 by Failures desc
```
```text
index=wineventlog EventCode=4625 earliest=-24h
| stats count as Failures by user, src, host
| sort 20 - Failures
```

**2. Failed Entra ID sign-ins by user**
```kusto
SigninLogs
| where TimeGenerated > ago(24h) and ResultType != "0"
| summarize Failures = count(), Reasons = make_set(ResultDescription, 5) by UserPrincipalName
| top 20 by Failures desc
```
```text
index=entra sourcetype="azure:aad:signin" earliest=-24h
| where 'status.errorCode' != 0
| stats count as Failures values(status.failureReason) as Reasons by userPrincipalName
| sort 20 - Failures
```

**3. Brute force: 10+ failures for one account from one IP in 5 minutes**
```kusto
SecurityEvent
| where EventID == 4625
| summarize Failures = count() by Account, IpAddress, bin(TimeGenerated, 5m)
| where Failures >= 10
```
```text
index=wineventlog EventCode=4625
| bin _time span=5m
| stats count as Failures by _time, user, src
| where Failures >= 10
```

**4. Password spray: one IP, 8+ different users (Entra error 50126)**
```kusto
SigninLogs
| where ResultType == "50126"
| summarize Users = dcount(UserPrincipalName), Attempts = count() by IPAddress, bin(TimeGenerated, 10m)
| where Users >= 8
```
```text
index=entra sourcetype="azure:aad:signin" status.errorCode=50126
| bin _time span=10m
| stats dc(userPrincipalName) as Users count as Attempts by _time, ipAddress
| where Users >= 8
```

**5. Success after failures from the same IP (possible compromise)**
```kusto
let bad = SigninLogs
    | where TimeGenerated > ago(1d) and ResultType == "50126"
    | summarize Users = dcount(UserPrincipalName) by IPAddress
    | where Users >= 8;
SigninLogs
| where TimeGenerated > ago(1d) and ResultType == "0"
| join kind=inner bad on IPAddress
| project TimeGenerated, UserPrincipalName, IPAddress, Location
```
```text
index=entra sourcetype="azure:aad:signin" earliest=-1d
| eval ok = if('status.errorCode' == 0, 1, 0)
| stats dc(eval(if(ok==0, userPrincipalName, null()))) as FailedUsers sum(ok) as Successes by ipAddress
| where FailedUsers >= 8 AND Successes >= 1
```

**6. Account lockouts (4740)**
```kusto
SecurityEvent
| where EventID == 4740
| project TimeGenerated, LockedAccount = TargetUserName, SourceComputer = TargetDomainName, DC = Computer
```
```text
index=wineventlog EventCode=4740
| table _time user host
```

**7. New member in a privileged group (4728, 4732, 4756)**
```kusto
SecurityEvent
| where EventID in (4728, 4732, 4756)
| where TargetUserName in ("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
| project TimeGenerated, Actor = SubjectUserName, Member = MemberName, Group = TargetUserName, Computer
```
```text
index=wineventlog (EventCode=4728 OR EventCode=4732 OR EventCode=4756)
  (Group_Name="Domain Admins" OR Group_Name="Enterprise Admins" OR Group_Name="Schema Admins" OR Group_Name="Administrators")
| table _time Subject_Account_Name Member_Name Group_Name host
```
(Field names for group events depend on the Windows add-on version. Check them.)

**8. New user account created (4720)**
```kusto
SecurityEvent
| where EventID == 4720
| project TimeGenerated, NewUser = TargetUserName, CreatedBy = SubjectUserName, Computer
```
```text
index=wineventlog EventCode=4720
| table _time user Subject_Account_Name host
```

**9. Rare process across the estate (14 days)**
```kusto
SecurityEvent
| where TimeGenerated > ago(14d) and EventID == 4688
| summarize Hosts = dcount(Computer), Runs = count(), Example = any(CommandLine) by NewProcessName
| where Hosts <= 2 and Runs <= 5
```
```text
index=wineventlog EventCode=4688 earliest=-14d
| stats dc(host) as Hosts count as Runs latest(Process_Command_Line) as Example by New_Process_Name
| where Hosts <= 2 AND Runs <= 5
```

**10. Encoded PowerShell**
```kusto
SecurityEvent
| where EventID == 4688 and NewProcessName endswith "powershell.exe"
| where CommandLine contains " -enc " or CommandLine contains " -encodedcommand "
| project TimeGenerated, Computer, SubjectUserName, ParentProcessName, CommandLine
```
```text
index=wineventlog EventCode=4688 New_Process_Name="*powershell.exe" (Process_Command_Line="* -enc *" OR Process_Command_Line="* -encodedcommand *")
| table _time host Subject_Account_Name Creator_Process_Name Process_Command_Line
```

**11. Office app starts a shell (macro behavior)** (Defender / Sysmon data)
```kusto
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```
```text
index=sysmon EventCode=1
  (ParentImage="*\\winword.exe" OR ParentImage="*\\excel.exe" OR ParentImage="*\\powerpnt.exe" OR ParentImage="*\\outlook.exe")
  (Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\wscript.exe" OR Image="*\\mshta.exe")
| table _time host User ParentImage Image CommandLine
```

**12. Impossible travel (two countries within 60 minutes)**
```kusto
SigninLogs
| where TimeGenerated > ago(1d) and ResultType == "0"
| sort by UserPrincipalName asc, TimeGenerated asc
| extend PrevUser = prev(UserPrincipalName), PrevCountry = prev(Location), PrevTime = prev(TimeGenerated)
| where UserPrincipalName == PrevUser and Location != PrevCountry and (TimeGenerated - PrevTime) <= 60m
| project UserPrincipalName, PrevCountry, Location, PrevTime, TimeGenerated
```
```text
index=entra sourcetype="azure:aad:signin" earliest=-1d status.errorCode=0
| sort 0 userPrincipalName _time
| streamstats current=f window=1 last(location.countryOrRegion) as prev_country last(_time) as prev_time by userPrincipalName
| where 'location.countryOrRegion' != prev_country AND (_time - prev_time) <= 3600
| table userPrincipalName prev_country location.countryOrRegion _time
```

**13. First sign-in from a new country (30-day baseline)**
```kusto
let known = SigninLogs
    | where TimeGenerated between (ago(30d) .. ago(1d)) and ResultType == "0"
    | distinct UserPrincipalName, Location;
SigninLogs
| where TimeGenerated > ago(1d) and ResultType == "0"
| join kind=leftanti known on UserPrincipalName, Location
| distinct UserPrincipalName, Location
```
```text
index=entra sourcetype="azure:aad:signin" earliest=-30d status.errorCode=0
| stats earliest(_time) as first_seen by userPrincipalName, location.countryOrRegion
| where first_seen > relative_time(now(), "-1d")
```

**14. Data exfiltration volume (bytes out per source and destination)**
```kusto
CommonSecurityLog
| where TimeGenerated > ago(1d) and DeviceAction == "Allow"
| summarize MB = sum(SentBytes) / 1000000 by SourceIP, DestinationIP
| where MB > 500
| sort by MB desc
```
```text
index=firewall action=allowed earliest=-1d
| stats sum(bytes_out) as bytes by src_ip, dest_ip
| eval MB = round(bytes/1000000, 1)
| where MB > 500
| sort - MB
```

**15. Rare outbound port**
```kusto
CommonSecurityLog
| where DeviceAction == "Allow" and DestinationPort !in (53, 80, 123, 443, 8080, 8443)
| summarize Flows = count(), MB = sum(SentBytes) / 1000000 by SourceIP, DestinationPort
```
```text
index=firewall action=allowed NOT dest_port IN (53, 80, 123, 443, 8080, 8443)
| stats count as Flows sum(bytes_out) as bytes by src_ip, dest_port
| eval MB = round(bytes/1000000, 1)
```

**16. Top DNS domains (find strange volume)**
```kusto
DnsEvents
| where TimeGenerated > ago(1d)
| summarize Queries = count() by Name
| top 20 by Queries desc
```
```text
index=dns earliest=-1d
| stats count as Queries by query
| sort 20 - Queries
```

**17. Audit log cleared (1102)**
```kusto
SecurityEvent | where EventID == 1102 | project TimeGenerated, Computer, Account
```
```text
index=wineventlog EventCode=1102 | table _time host user
```

**18. Legacy authentication or single-factor sign-ins**
```kusto
SigninLogs
| where ResultType == "0"
| where ClientAppUsed in ("IMAP4", "POP3", "SMTP", "Other clients") or AuthenticationRequirement == "singleFactorAuthentication"
| summarize Signins = count() by UserPrincipalName, ClientAppUsed, AuthenticationRequirement
```
```text
index=entra sourcetype="azure:aad:signin" status.errorCode=0
  (clientAppUsed IN ("IMAP4","POP3","SMTP","Other clients") OR authenticationRequirement="singleFactorAuthentication")
| stats count as Signins by userPrincipalName, clientAppUsed, authenticationRequirement
```

**19. New service installed (4697)**
```kusto
SecurityEvent | where EventID == 4697 | project TimeGenerated, Computer, ServiceName, ServiceFileName, SubjectUserName
```
```text
index=wineventlog EventCode=4697 | table _time host Service_Name Service_File_Name Subject_Account_Name
```

**20. Scheduled task created (4698)**
```kusto
SecurityEvent | where EventID == 4698 | project TimeGenerated, Computer, SubjectUserName, TaskName
```
```text
index=wineventlog EventCode=4698 | table _time host Subject_Account_Name Task_Name
```

Note: events 4697 and 4698 need the matching Windows audit policy to be enabled, and Entra field availability depends on your license and diagnostic settings. If a query returns nothing, first check that the data exists.

### 2.3 Habits that make queries good

1. Time first. Table or index first. Then filters.
2. Test with `take 10` / `head 10` before you add aggregation.
3. Name your result columns.
4. Think about **what is normal** (baseline) before alerting on "rare".
5. Save useful queries as hunting queries or saved searches, with a comment on what they find and their false positives.

### 2.4 From DBA to security

> **From DBA to security**
> - **You already know the logic.** `GROUP BY ... HAVING COUNT(*) >= 10` is query 3 in either language.
> - **Window functions.** `LAG()` in SQL is `prev()` in KQL and `streamstats` in SPL. Impossible travel is a `LAG` query.
> - **Anti-join.** `NOT EXISTS` / `LEFT JOIN ... WHERE b.id IS NULL` is `join kind=leftanti` in KQL. "New country" is an anti-join against a baseline.
> - **Performance.** Filter early, select few columns, narrow time range: the same rules as tuning SQL.

---

## 3. Hands-on

### 3.1 Repo lab: practice both languages on the same data

The 12 questions in `lab/queries/exercises.md` cover queries 1, 3, 4, 5 (Q12), 7, 10, 12 (Q4), 14, 15 and more. Work like this:

1. Solve each question in **KQL** (paste `events_datatable.kql`), write the answer in `answers.json`.
2. Solve the same question in **SPL** (upload `events.csv`). Do your two answers match? If not, one query is wrong. That is a great debugging exercise.
3. Run the checker:

```bash
python cybersecurity-track/06-siem-sentinel-splunk/lab/queries/check_answers.py cybersecurity-track/06-siem-sentinel-splunk/lab/queries/answers.json
```

4. Run the full test suite of both modules (it must stay green):

```bash
python -m pytest cybersecurity-track/05-soc-fundamentals cybersecurity-track/06-siem-sentinel-splunk
```

```text
........................................................................ [ 92%]
......                                                                   [100%]
78 passed in 0.50s
```

### 3.2 Build your own cheat sheet

Make a personal page with the 20 queries adapted to **your company's** real field names (ask your team). Add: what the query finds, expected false positives, ATT&CK technique, and the next step for the analyst.

### 3.3 Practice platforms
- **TryHackMe:** Splunk and Sentinel/KQL rooms; SOC Level 1/2 paths.
- **HTB Academy:** SOC Analyst path; **HTB Labs:** Sherlocks (write the queries you would use).
- **Kusto Detective Agency** (free KQL game) and BOTS datasets (SPL).

---

## 4. Real-world scenarios

**Scenario 1: "Did anyone else log in from that IP?"** Use query 5. In SPL `stats` replaces the join. Output a list of accounts and reset the successful ones.

**Scenario 2: "Show me all admin changes last month for the auditor."** Use query 7 with a 30-day range, add `Actor` and `Member`, export to CSV. Check that retention covers the period.

**Scenario 3: "Is this PowerShell normal?"** Query 10 finds the events; query 9 tells you if the process is rare; query 11 tells you if Office started it. Together they build the case.

---

## 5. Common mistakes

- Copying a query without checking field names.
- Time zone mistakes (always UTC).
- `ResultType` is a string in KQL: `== "0"`, not `== 0`.
- Using `join` in SPL when `stats` can do it.
- Counting events when you need distinct users (`dcount`/`dc`).
- Forgetting `sort` before `prev()` / `streamstats`.
- No baseline for "rare" and "new".

---

## 6. Interview questions

<details><summary><b>Q1. Write "top 10 IPs by failed logons" in KQL and SPL.</b></summary>
KQL: `SecurityEvent | where EventID == 4625 | summarize n = count() by IpAddress | top 10 by n desc`. SPL: `index=wineventlog EventCode=4625 | stats count by src | sort 10 - count`.
</details>

<details><summary><b>Q2. KQL `has` vs `contains`?</b></summary>
`has` matches whole terms and uses the index, so it is faster. `contains` matches any substring and is slower. Use `contains` for patterns like ` -enc `.
</details>

<details><summary><b>Q3. How do you do a left join "rows with no match" in KQL?</b></summary>
`join kind=leftanti`. It is useful for "new" activity versus a baseline.
</details>

<details><summary><b>Q4. SPL equivalent of `summarize dcount(User) by IP`?</b></summary>
`stats dc(User) by IP`.
</details>

<details><summary><b>Q5. How do you compare each event with the previous one?</b></summary>
KQL: sort, then `prev()`. SPL: `sort 0` then `streamstats current=f last(field)`.
</details>

<details><summary><b>Q6. How do you find the rarest process?</b></summary>
Count by process name and distinct hosts over a long window, then keep the lowest counts. SPL also has `rare`. Always add context: signed, parent, path.
</details>

<details><summary><b>Q7. Detect data exfiltration by volume.</b></summary>
Sum bytes out per source and destination over a day, compare with a baseline or a fixed threshold, and exclude known backup targets. Check whether the user's account is compromised.
</details>

<details><summary><b>Q8. A KQL query returns nothing. How do you debug it?</b></summary>
Remove filters one by one, check the time range, check that the table has data, inspect field values with `distinct` or `take`, and watch for string vs number types and case.
</details>

<details><summary><b>Q9. Which query would you use to find password spray and why `dcount`?</b></summary>
Group by source IP over a short window and count distinct users. Spray touches many accounts few times each, so total attempts is not enough.
</details>

<details><summary><b>Q10. Why does time zone matter?</b></summary>
Windows, cloud services and users use different zones. A wrong zone shifts windows and breaks correlation. Use UTC everywhere, including Splunk user settings.
</details>

<details><summary><b>Q11. How would you move a Splunk detection to Sentinel?</b></summary>
Map the data source and fields (CIM to ASIM or table columns), rewrite the logic in KQL, test with true-positive and benign events, then recreate the schedule, threshold, entity mapping and ATT&CK tags.
</details>

<details><summary><b>Q12. How can Sigma help with that?</b></summary>
If the rule is in Sigma, a converter generates KQL or SPL for each backend, and you adjust field mappings once.
</details>

---

## 7. Checklist

- [ ] I can translate the 15 basic operations in the table without notes.
- [ ] I can write queries 1, 3, 4, 7, 10, 12 and 14 in both languages from memory.
- [ ] I solved the 12 lab questions in both languages and the answers matched.
- [ ] I adapted the cheat sheet to my company's field names.
- [ ] `python -m pytest cybersecurity-track/05-soc-fundamentals cybersecurity-track/06-siem-sentinel-splunk` passes.

## 8. References

- Microsoft Learn, KQL quick reference: https://learn.microsoft.com/kusto/query/kql-quick-reference
- Splunk Docs, "Splunk SPL for SQL users" and "SPL to KQL" style comparison guides (search Microsoft Learn: "Splunk to Kusto cheat sheet").
- Microsoft Learn, "Windows security events: event IDs".
- Sentinel table reference (Azure Monitor tables reference).
- SigmaHQ: https://sigmahq.io

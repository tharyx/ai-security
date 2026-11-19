# {tm.name}: security summary for the sprint review

High-severity findings: **{high_count}** of {findings_count}.
{findings_high:ifnot:No high findings. The design can go ahead.
}{findings_high:if:Do not release until each high finding below is fixed or formally accepted.
}
{findings_high:repeat:- **{{item.target}}**: {{item.description}} -> fix: {{item.mitigation}} ({{item.requirement}})
}
## Security requirements for the backlog

{requirements:repeat:- [ ] {{item.id}} applies to: {{item.targets}}
}
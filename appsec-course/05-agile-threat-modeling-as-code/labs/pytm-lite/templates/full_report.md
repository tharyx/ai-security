# Threat model: {tm.name}

## System description

{tm.description}

## Elements

| Element | Type | Boundary |
|---|---|---|
{elements:repeat:| {{item.name}} | {{item.kind}} | {{item.inBoundary.name}} |
}
## Data flows

| Flow | From | To | Protocol | Encrypted |
|---|---|---|---|---|
{dataflows:repeat:| {{item.name}} | {{item.source.name}} | {{item.sink.name}} | {{item.protocol}} | {{item.isEncrypted}} |
}
## Findings ({findings_count})

{findings:repeat:<details>
<summary>{{item.sid}} | {{item.severity}} | {{item.target}}: {{item.description}}</summary>

- STRIDE: {{item.stride}}
- Mitigation: {{item.mitigation}}
- Requirement: {{item.requirement}}
- References: {{item.references}}
</details>
}

# AI Security Incident Playbook

## Incident types
- prompt injection leading to data exposure;
- unauthorized RAG retrieval;
- MCP token or tool compromise;
- agent unauthorized action;
- model/provider compromise or outage;
- sensitive data in prompts/logs;
- dataset/model supply-chain tampering;
- cost/resource abuse.

## First response
1. Declare incident and assign incident commander.
2. Preserve relevant audit events and system/model versions.
3. Stop or constrain affected tool execution.
4. Revoke compromised tokens and rotate affected secrets.
5. Disable affected MCP server/tool or agent workflow.
6. Isolate impacted tenant/data path if needed.
7. Assess data accessed, actions taken, affected users and jurisdictions.
8. Engage privacy, legal, security, business and provider contacts as required.
9. Restore from known-good configuration/artifacts.
10. Validate controls before re-enabling.

## Evidence to preserve
- request/correlation IDs;
- authenticated principal and delegated identity;
- model/provider/version;
- prompt template version;
- retrieval source IDs and ACL decisions;
- MCP server/tool and arguments (redacted);
- approval record;
- policy version and decision;
- cloud audit events;
- timestamps and affected resource IDs.

## Recovery and lessons learned
- root cause and attack path;
- scope and impact;
- control failure;
- corrective/preventive actions;
- notification/legal assessment;
- regression tests;
- owner and due date;
- post-incident review.

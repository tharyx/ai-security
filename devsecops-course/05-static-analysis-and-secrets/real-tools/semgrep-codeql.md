# Real tools: Semgrep and CodeQL for custom rules

> **Hedged guide.** Rule syntax, licensing and feature availability change. Verify at the project documentation. Scan only code you own. The course tests do not need these tools.

## Semgrep

Semgrep matches code **patterns** that look like the code itself, in many languages. The open-source engine (LGPL) can run rules locally and in CI; a commercial platform adds a managed rule registry, cross-file analysis and triage. A community fork, **Opengrep**, has existed since 2025. Check which features (for example cross-file taint) are in the engine you use.

Pattern rule (shape only, verify the syntax for your version):

```yaml
rules:
  - id: corpdb-dynamic-query
    languages: [python]
    severity: ERROR
    message: corpdb.execute() with a built query string; pass values as parameters.
    metadata: {cwe: "CWE-89"}
    patterns:
      - pattern: corpdb.execute($Q, ...)
      - pattern-not: corpdb.execute("...", ...)
```

Taint-mode rule (sources, sinks, sanitizers, as in the lab's graph detector):

```yaml
rules:
  - id: sqli-from-request
    mode: taint
    languages: [python]
    severity: ERROR
    message: Request data reaches a SQL execute call.
    pattern-sources:
      - pattern: request.args.get(...)
      - pattern: request.form[...]
    pattern-sanitizers:
      - pattern: int(...)
    pattern-sinks:
      - pattern: $CUR.execute($Q, ...)
```

Typical commands (verify):

```text
semgrep --config rules/ --error --sarif --output semgrep.sarif src/     # non-zero exit when findings exist
semgrep --test rules/                                                   # run rule tests (files annotated with ruleid: and ok: comments)
```

Rule tests matter: write one file with `# ruleid: corpdb-dynamic-query` lines that must match and `# ok: corpdb-dynamic-query` lines that must not.

## CodeQL

CodeQL turns a repository into a **database** and lets you query it with QL. Its libraries model data flow, control flow and taint tracking for many frameworks, which makes it strong for injection-style bugs.

```text
codeql database create db --language=python --source-root .
codeql database analyze db <query suite or pack> --format=sarif-latest --output=codeql.sarif
```

- Query packs, the licence terms for private code (GitHub Advanced Security, or free for open source) and available languages change; verify at the CodeQL documentation.
- A custom query defines sources, sinks and sanitizers using a taint-tracking configuration, the same three ideas as the lab.

## Choosing

| Need | Use |
|---|---|
| Quick custom pattern in many languages | Semgrep pattern rule |
| Source-to-sink flow with moderate effort | Semgrep taint mode |
| Deep, whole-program flow queries and variant analysis | CodeQL |
| Python-specific plugin checks, offline, tiny dependency | Bandit plugin |
| Java bytecode security checks | SpotBugs + find-sec-bugs |

Whichever you choose: version the rules, test them with good and bad samples, measure false positives, and enforce in CI ([lesson 03](../03-custom-rules-regex-ast-graph.md)).

# Real tools: SpotBugs + find-sec-bugs, Brakeman, Bandit

> **Hedged guide.** Commands, plugin coordinates and exit codes change between versions. Verify at each project's documentation. Scan only code you own. The course tests never need Java, Ruby or these tools.

## SpotBugs and find-sec-bugs (Java)

**FindBugs** (the name in the syllabus) is dead; **SpotBugs** is its maintained successor. It analyses compiled `.class` files, so build first. **find-sec-bugs** is a SpotBugs plugin with security patterns and CWE references.

Maven sketch (pin current versions; verify at Maven Central):

```xml
<plugin>
  <groupId>com.github.spotbugs</groupId>
  <artifactId>spotbugs-maven-plugin</artifactId>
  <configuration>
    <effort>Max</effort>
    <threshold>Medium</threshold>
    <failOnError>true</failOnError>
    <xmlOutput>true</xmlOutput>
    <excludeFilterFile>spotbugs-exclude.xml</excludeFilterFile>
    <plugins>
      <plugin>
        <groupId>com.h3xstream.findsecbugs</groupId>
        <artifactId>findsecbugs-plugin</artifactId>
        <version><!-- current version --></version>
      </plugin>
    </plugins>
  </configuration>
</plugin>
```

```text
mvn compile spotbugs:check          # fails the build when bugs at or above the threshold exist
mvn spotbugs:spotbugs               # writes target/spotbugsXml.xml (the format the lab parses)
```

- Exclusion filters (XML) skip test code or generated code, like the lab's `exclude_paths`.
- Newer SpotBugs releases can also write **SARIF** (verify your version) for code-scanning UIs.
- Ranks: 1-4 scariest, 5-9 scary, 10-14 troubling, 15-20 of concern. Gate on rank, not only on "priority".

## Brakeman (Ruby on Rails)

Static analyser that understands Rails controllers, models and views; it does not run the app.

```text
gem install brakeman                      # or add to the Gemfile (development group)
brakeman -q -f json -o brakeman.json      # JSON report like the lab fixture
brakeman -z                                # exit non-zero when warnings are found (verify the flag in your version)
brakeman -I                                # interactive ignore file (config/brakeman.ignore)
```

- `config/brakeman.ignore` stores decisions with fingerprints and notes, like the `ignored_warnings` block in the fixture.
- Confidence is High, Medium or Weak; there is no severity, so teams map warning types to severity themselves (the lab does it by CWE).

## Bandit (Python)

```text
pip install bandit
bandit -r app -f json -o bandit.json         # scan, JSON report
bandit -r app -ll -ii                        # medium-and-above severity and confidence
bandit -r app -b baseline.json               # only report issues not in the baseline
bandit -r app -c pyproject.toml              # config in [tool.bandit] (verify your version)
```

- Suppress a line with `# nosec` (add the test id and a reason: `# nosec B602 - input validated upstream`).
- Bandit has its own false positives (B608 on constant strings, for instance); use custom rules or targeted `nosec` with reasons.

### Real Bandit plugin skeleton (custom check)

This is the real-API shape the lab imitates. **Verify against the Bandit documentation for your version**; import paths and Issue fields have changed over time.

```python
# corp_bandit/checks.py
import bandit
from bandit.core import issue
from bandit.core import test_properties as test


@test.checks("Call")
@test.test_id("B901")                      # pick an id that does not collide with built-in ones
def corpdb_dynamic_query(context):
    if context.call_function_name_qual == "corpdb.execute":
        # inspect context.node.args[0] here, as the lab's dynamic_sql() does
        return bandit.Issue(
            severity=bandit.HIGH,
            confidence=bandit.HIGH,
            cwe=issue.Cwe.SQL_INJECTION,
            text="corpdb query text is built from non-constant input; pass values as parameters.",
        )
```

Register it with an **entry point** in the `bandit.plugins` group, install the package into the same environment as Bandit, and run Bandit normally:

```toml
# pyproject.toml of the plugin package (sketch)
[project.entry-points."bandit.plugins"]
corpdb_dynamic_query = "corp_bandit.checks:corpdb_dynamic_query"
```

```text
pip install -e ./corp_bandit
bandit -r app -t B901
```

Test the plugin the way the lab does: write fixture files with lines that must be flagged and lines that must not, and assert on the findings.

## CI pattern

1. Install the tool at a **pinned version** in CI.
2. Run on changed files for pull requests, full scan nightly.
3. Produce SARIF or JSON; upload to your code-scanning UI or [DefectDojo](../../14-vulnerability-management/README.md).
4. Fail on **new** findings above the agreed rank, severity or score.
5. Keep ignore files in the repository, reviewed like code, with reasons and dates.

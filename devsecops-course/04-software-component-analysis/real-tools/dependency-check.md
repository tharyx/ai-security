# Real tool: OWASP Dependency-Check

> **Hedged guide.** Flags, plugin versions and data-source behaviour change. Verify everything in the project documentation (owasp.org/www-project-dependency-check and its GitHub repository). Nothing in the course tests needs Java, Maven or a network. Never commit API keys.

## What it is

An open-source SCA tool, strongest for **Java** (Maven, Gradle, jars) and also able to analyse .NET, JavaScript, Python, Ruby and more. It builds **evidence** (vendor, product, version) from file names, manifests and pom data, guesses **CPE** names and matches them against NVD data (and, optionally, other sources such as OSS Index). Findings carry a **confidence** level because name matching can be wrong.

## Important current facts (verify)

- The NVD moved to **API 2.0**; Dependency-Check expects an **NVD API key** (free from NIST) for a practical update speed. Without one, updates are slow or can fail.
- The **first run downloads and builds a local database**, which takes time. Cache it between CI runs (a persistent volume or CI cache) or host an internal mirror.
- Because of CPE name matching it produces **false positives**. Plan for a **suppression file** (XML) with a reason for each entry.

## CLI sketch

```text
# set the key as a CI secret variable, never in the repository
dependency-check.sh --project shop-service --scan . \
  --format HTML --format JSON --out reports \
  --nvdApiKey "$NVD_API_KEY" \
  --failOnCVSS 7 \
  --suppression suppressions.xml
```

`--failOnCVSS 7` makes the exit code non-zero when any finding has a CVSS score of 7.0 or higher. This is the real version of the `break_build(fail_cvss=7.0)` function in the [lab](../labs/dependency-check-java/README.md).

## Maven plugin sketch

```xml
<plugin>
  <groupId>org.owasp</groupId>
  <artifactId>dependency-check-maven</artifactId>
  <!-- pin a current version; verify at Maven Central -->
  <configuration>
    <failBuildOnCVSS>7</failBuildOnCVSS>
    <suppressionFiles><suppressionFile>suppressions.xml</suppressionFile></suppressionFiles>
    <skipTestScope>true</skipTestScope>
    <nvdApiKeyEnvironmentVariable>NVD_API_KEY</nvdApiKeyEnvironmentVariable>
  </configuration>
  <executions><execution><goals><goal>check</goal></goals></execution></executions>
</plugin>
```

Option names differ between versions; check the plugin's goal documentation (`dependency-check:check`).

## Suppression file sketch

```xml
<suppressions xmlns="https://jeremylong.github.io/DependencyCheck/dependency-suppression.1.3.xsd">
  <suppress until="2027-09-30Z">
    <notes>False positive: widgetlib-docs ships only help pages, not the vulnerable class.</notes>
    <packageUrl regex="true">^pkg:maven/com\.example\.widget/widgetlib-docs@.*$</packageUrl>
    <cve>CVE-0000-00000</cve>
  </suppress>
</suppressions>
```

Always include `notes` and an `until` date, the real-tool version of the reason-and-expiry rule in the lab. (The CVE id above is a placeholder.)

## Pipeline pattern

1. Cache the data directory between runs, or use a mirror.
2. Run on pull requests against changed modules; run a full scan nightly.
3. Fail on CVSS 7 or higher at first; lower the threshold as the backlog shrinks.
4. Publish the HTML and JSON reports as artifacts, import the JSON into your vulnerability manager ([chapter 14](../../14-vulnerability-management/README.md)).
5. Review suppressions monthly.

## Alternatives for Java

OSV-based tools (osv-scanner), Snyk, Trivy on the built artifact or image, GitHub Dependabot alerts. Coordinate-based tools give fewer name-collision false positives; CPE-based tools can find components that have no clean coordinates.

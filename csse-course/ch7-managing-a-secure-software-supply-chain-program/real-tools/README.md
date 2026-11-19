# Real-tools guides (hedged, not tested)

These guides outline how to do the chapter's tool-based exercises on real software. **The repo author has not run them.** Commands, API fields, image names and features change. Treat each guide as a map: follow the project's current documentation and verify every claim. **Nothing in the repo tests needs these tools** (no Docker, network or cloud accounts).

| Guide | Course exercise | Offline twin (tested) |
|---|---|---|
| [SLSA provenance on GitHub and GitLab](slsa-github-gitlab.md) | Achieving SLSA Level 1 / Level 2 | [slsa-level-1](../labs/slsa-level-1/), [slsa-level-2](../labs/slsa-level-2/) |
| [DefectDojo with Docker Compose and the API](defectdojo.md) | Working with Defect Dojo; Vulnerability Management With DefectDojo | [defectdojo-basics](../labs/defectdojo-basics/), [vuln-management-defectdojo](../labs/vuln-management-defectdojo/) |
| [Scorecard, SBOM tools and the Best Practices Badge](scorecard-sbom-and-badge.md) | Establish a vetting process for open-source components | [oss-vetting-process](../labs/oss-vetting-process/) |

## Rules for every guide

- **Laptop budget:** DefectDojo with Docker Compose needs several GB of RAM and disk. Use the course's hosted lab if your laptop is small.
- **Fake secrets only:** `FAKE-REPLACE-ME` placeholders are not real. Real tokens go in environment variables or a secrets store, never into a committed file.
- **Bind to localhost.** Do not expose DefectDojo to a network.
- **Scan only what you own** or what the course lab provides.
- **Pin and verify** what you download; read install scripts before running them.

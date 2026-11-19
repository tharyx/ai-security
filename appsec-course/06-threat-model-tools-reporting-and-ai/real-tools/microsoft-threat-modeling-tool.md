# Real tool: Microsoft Threat Modeling Tool (hedged walkthrough)

> **Hedge.** Free Windows desktop tool from Microsoft; updates are infrequent. Menu names below are approximate: follow your course lab and the current Microsoft documentation (learn.microsoft.com, "Microsoft Threat Modeling Tool"). Nothing here was run by the course author for this guide. Use a fictional system. Only test systems you own or have written permission to test.

## Install

Download from the official Microsoft documentation page (it has been distributed as a ClickOnce installer; verify). Windows only. No account needed.

## Model a three-tier shop

1. **Create a model** from the default template (SDL TM Knowledge Base) or the Azure template.
2. **Design view:** drag a *Browser* (external interactor), *Web Application* (process), *Web API* (process), *SQL Database* (data store). Connect them with *Request* / *Response* data flows.
3. Draw **trust boundaries**: Internet boundary between the browser and the web app; a boundary between the API and the database.
4. Set **element properties** (authentication, protocol, "Is encrypted"). Properties change which threats are generated.
5. Switch to **Analysis view:** the tool lists generated threats per interaction, by STRIDE category.
6. For each threat set the **state** (Not Started, Needs Investigation, Not Applicable, Mitigated) and write a **justification**. "Not Applicable" without a justification is a red flag in review.
7. **Reports → Create full report** (HTML). Save the `.tm7` model in your repository even though diffs are hard.

## Tips

- Templates (`.tb7`) can be customised with your own stencils and threat rules (Template Editor).
- Copy the threats you keep into your backlog with stable ids ([lesson 01](../01-managing-threat-models.md)).
- For CI checks prefer a text model (pytm, Threagile, Threat Dragon JSON); use TMT for teaching STRIDE per interaction.

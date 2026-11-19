# Lab: DSOMM self-assessment

**Lesson:** [03 section 7](../../03-devsecops-toolchain-sdlc-and-dsomm.md#7-devsecops-maturity-model-dsomm-moving-from-level-2-to-level-4) · **Time:** 1 hour · **Safety:** offline, reads two YAML files.

> **This is a teaching model.** `activities.yaml` is a **simplified, DSOMM-like** list (5 dimensions, 4 levels, about 30 activities). It is **not** the official OWASP DSOMM, whose dimensions, activities and levels change between versions. Use <https://dsomm.owasp.org> for the real model and treat this lab as practice for the logic: score, find gaps, plan.

## What it does

1. Loads the activity list (`activities.yaml`) and your answers (`my-org.yaml`: `implemented`, `partial` or `not-started`).
2. Computes the **level per dimension**. The rule is strict, like a maturity model: a dimension is at level N only when **every** activity of levels 1 to N is implemented. One missing level-2 activity keeps you at level 1, even if you already do some level-3 things (those are reported as "ahead of level").
3. Shows the **gaps to the next level** per dimension.
4. Builds a **roadmap**: all missing activities up to the target level, lowest level first, cheapest effort first.
5. Rejects typos: an unknown activity id or an invalid status raises an error, so a mistyped answer never silently counts as "not started".

The overall level is the **weakest dimension**, because a chain is as strong as its weakest link. The average is shown too, but do not quote it as "our level".

## Steps

```text
.venv/Scripts/python devsecops-course/01-devops-devsecops-and-maturity/labs/dsomm-assessment/demo.py
.venv/Scripts/python -m pytest devsecops-course/01-devops-devsecops-and-maturity/labs/dsomm-assessment -v
```

1. Read `my-org.yaml` and guess the level of each dimension before you run the demo.
2. Run the demo. Why is "Build and Deployment" only level 1 even though the team has `bd-pipeline-as-code` and `bd-versioned-artifacts`? (`bd-secrets-not-in-code` is only *partial*.)
3. Call `assess(..., partial_credit=True)` (see the demo's last lines). What changes, and why is giving partial credit risky in a real assessment?
4. Edit `my-org.yaml` to describe **your own team** honestly. Which three roadmap items are cheapest?
5. Add a new activity to `activities.yaml` that matters in your company and a test that checks it appears in the roadmap.
6. Stretch: add a `--target 3` option and print the cost (sum of effort) per dimension.

## Expected output (real run)

```text
Team: webshop-team

Dimension                    Level  Next-level gaps
Build and Deployment         L1     bd-secrets-not-in-code
Culture and Organization     L1     co-threat-model-workshops
Implementation               L2     im-iac-reviewed, im-policy-as-code
Information Gathering        L1     ig-asset-inventory
Test and Verification        L2     tv-dast-in-ci, tv-break-build

Overall (weakest dimension): L1   average: 1.4

Roadmap to L2 in every dimension (3 activities):
   1. [L2 effort 2] bd-secrets-not-in-code       partial
   2. [L2 effort 2] co-threat-model-workshops    partial
   3. [L2 effort 2] ig-asset-inventory           partial

With partial credit: {'build-and-deployment': 'L2', 'culture-and-organization': 'L2', 'implementation': 'L2', 'information-gathering': 'L2', 'test-and-verification': 'L2'}
```

## Limits

- Activity lists and scoring are simplified. Real DSOMM activities have descriptions, evidence and references; this lab only uses an id, a level and a rough effort.
- Self-assessments are optimistic. In practice ask for **evidence** (a pipeline link, a ticket, a dashboard) for each "implemented".
- The effort numbers are guesses used only to sort the roadmap.

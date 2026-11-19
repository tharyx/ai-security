# US AI Legislation and Policy

> **Chapter:** 7 · **Time:** ~3 hours · **Related:** [EU AI Act summary](03-eu-ai-act-summary.md), [08-ai-compliance](../../08-ai-compliance/README.md)
> **You will:** describe the US approach (federal executive actions plus a patchwork of state laws, no single federal AI Act), name the main state laws and what they cover, and say what a security architect should do about it.

> **Educational, not legal advice. Verify every item at the source.** This area changes fast: laws are amended, delayed, challenged in court and replaced. The facts below are as understood in **November 2026**. Check the official text or a qualified lawyer before you rely on any date or scope. Record the date you checked.

---

## 1. The big picture

The US has **no single comprehensive federal AI law** like the EU AI Act. Instead:

1. **The federal executive branch** sets policy through executive orders and action plans. These direct agencies; they are not statutes and they change with administrations.
2. **States** pass their own AI laws, each with a different scope (frontier models, automated hiring, deepfakes, consumer decisions).
3. **Existing sector regulators** apply old laws to AI (consumer protection, civil rights, finance, health).
4. **Congress** has passed a few narrow AI-related statutes.

For a security architect this means: expect **several overlapping requirements**, and design controls that satisfy the strictest common denominator (inventory, risk assessment, logging, transparency, human review, incident handling).

---

## 2. Federal executive actions: a timeline

| Date | Action | What it did (simplified) | Note |
|---|---|---|---|
| Oct 2023 | **EO 14110** (Biden) | Safe, secure and trustworthy AI; reporting and testing duties | **Revoked** in January 2025 |
| Jan 2025 | **EO 14148**, then **EO 14179** | EO 14148 revoked EO 14110 (with other earlier orders); EO 14179 set a new policy to remove barriers to American AI leadership | Policy direction changed from safety-focused to innovation-focused |
| 23 Jul 2025 | **America's AI Action Plan** | A federal plan with many actions (23 July 2025) | A plan, not a statute |
| Dec 2025 | **EO 14365** | Sets up an **AI Litigation Task Force** to challenge state AI laws | An executive order **cannot repeal state law**; challenges go through courts |

**No federal statute broadly preempts state AI laws** (as of this writing). Preemption would need an Act of Congress, or a court finding that a specific state law conflicts with federal law or the Constitution. So state laws stay in force unless changed by the state or struck down. Watch the litigation and any new federal bills.

NIST still publishes AI guidance (AI RMF, AI 600-1; see [lesson 02](02-governance-standards-and-frameworks.md)). Those are voluntary frameworks, though other laws and contracts may refer to them.

---

## 3. State laws (examples)

| Law | What it is about | Key points (simplified) | Status (verify) |
|---|---|---|---|
| **California SB 53** (Transparency in Frontier AI Act) | Developers of the largest "frontier" models | Safety framework publication, transparency, critical incident reporting, whistleblower protection for covered developers | Took effect **1 Jan 2026** |
| **Texas TRAIGA** (HB 149, Texas Responsible AI Governance Act) | Use and development of AI in Texas | Prohibits certain harmful AI uses, transparency duties for government, enforcement by the state attorney general | Took effect **1 Jan 2026** |
| **Colorado**: AI Act **SB24-205**, replaced by **SB 26-189** | Automated decision-making affecting consumers | SB24-205 (high-risk AI, "algorithmic discrimination") was **repealed and replaced** by SB 26-189, a narrower automated decision-making technology (ADMT) law, signed 14 May 2026 | New law effective **1 Jan 2027** |
| **NYC Local Law 144** | Automated employment decision tools (hiring) | Bias audit by an independent auditor, publication of results, notice to candidates | In force in New York City |
| **Utah** (AI-related laws, such as its AI policy / disclosure law) | AI disclosure and consumer protection | Disclosure when consumers interact with generative AI in certain settings | Verify exact scope and current amendments |
| **TAKE IT DOWN Act** (2025) | **Federal** law: non-consensual intimate imagery, including AI-generated deepfakes | Criminalizes publishing such imagery and requires covered platforms to remove it on request within a set time | Federal statute (narrow subject) |

Notes:

- The TAKE IT DOWN Act is a real federal statute, but it is narrow: it does not regulate AI generally.
- Many other states have laws on deepfakes in elections, chatbots, health care AI and insurance. Do not assume the list above is complete.
- Items marked "verify" are summaries of fast-changing law; check the bill text and effective dates.

---

## 4. Sector regulators and general law

Even without an AI statute, existing law applies to AI:

- **FTC (Federal Trade Commission):** has enforced against deceptive or unfair practices, including false claims about what an AI product can do ("AI washing"), and misuse of data. The idea in plain words: **if you advertise AI capabilities or security, the claims must be true.**
- **Civil rights and employment law:** discrimination by an automated tool is still discrimination.
- **Financial and health regulators:** model risk management in banking, privacy and safety rules in health care.
- **Privacy and breach laws:** state privacy laws and breach notification apply when AI systems leak personal data.
- **Contracts and torts:** customers will put AI security requirements in contracts.

(Describe specific cases only from the original enforcement documents; this lesson deliberately does not list cases.)

---

## 5. What this means for a security architect

1. **Inventory first.** You cannot say which law applies without a list of AI systems, what they decide, where they run and who is affected ([07 lesson 01](../../07-ai-governance/01-ai-inventory-and-system-register.md)).
2. **Map once, satisfy many.** Build controls aligned to NIST AI RMF and ISO/IEC 42001, then map them to state requirements ([08 lesson 03](../../08-ai-compliance/03-control-mapping-and-evidence.md)).
3. **Track by jurisdiction of the people affected**, not only where your company sits. A Colorado resident, a Texas user and an EU customer can all bring different rules.
4. **Plan for change.** Keep a legal watch list and a re-review date. Laws such as Colorado's were replaced within a few years.
5. **Security-specific hooks:** incident reporting (SB 53 style), logging and evidence, bias and impact testing, deepfake handling and takedown processes, vendor risk questions ([07 policies: third-party risk](../../07-ai-governance/policies/05-ai-third-party-risk-assessment.md)).
6. **Truthful claims.** Marketing and security statements about AI must match reality (FTC angle). Review them with legal.
7. **Do not assume an executive order protects you.** An order against state laws does not remove your duty under them today.

---

## 6. Other jurisdictions (pointers)

| Jurisdiction | Where to start (verify) |
|---|---|
| **EU** | [EU AI Act summary](03-eu-ai-act-summary.md), [08 lesson 01](../../08-ai-compliance/01-eu-ai-act.md) |
| **UK** | Principles-based, regulator-led approach rather than one AI Act; NCSC secure AI guidelines ([lesson 02](02-governance-standards-and-frameworks.md)) |
| **China** | Targeted rules for algorithm recommendation, deep synthesis and generative AI services |
| **India** | DPDP Act and CERT-In AI security audit guidelines: [08 lesson 02](../../08-ai-compliance/02-privacy-gdpr-and-india-dpdp.md), [08 lesson 06](../../08-ai-compliance/06-cert-in-ai-security-audit.md) |

---

## 7. Interview preparation

<details><summary><b>Q1. Is there a federal AI law in the US?</b></summary>

No single comprehensive one. There are executive orders and plans, narrow statutes such as the TAKE IT DOWN Act, sector regulators applying existing law, and many state laws. Verify the current status.
</details>

<details><summary><b>Q2. What happened to EO 14110?</b></summary>

It was revoked in January 2025 (EO 14148); EO 14179 then set a new policy direction. America's AI Action Plan followed on 23 July 2025.
</details>

<details><summary><b>Q3. Can an executive order cancel state AI laws?</b></summary>

No. EO 14365 (December 2025) set up an AI Litigation Task Force to challenge state laws, but state laws stay in force unless repealed, amended or struck down by a court. No federal statute broadly preempts them.
</details>

<details><summary><b>Q4. What do California SB 53 and Texas TRAIGA do?</b></summary>

SB 53 is about transparency and incident reporting for frontier model developers; TRAIGA (HB 149) sets rules on certain AI uses with attorney-general enforcement. Both took effect 1 January 2026. Verify details.
</details>

<details><summary><b>Q5. What happened to the Colorado AI Act?</b></summary>

SB24-205 was repealed and replaced by SB 26-189, a narrower automated decision-making technology law signed 14 May 2026, effective 1 January 2027. Verify at source.
</details>

<details><summary><b>Q6. What is NYC Local Law 144?</b></summary>

A New York City law on automated employment decision tools: independent bias audit, public summary, and notice to candidates.
</details>

<details><summary><b>Q7. What is the TAKE IT DOWN Act?</b></summary>

A federal law (2025) about non-consensual intimate imagery, including AI-generated deepfakes, with takedown duties for covered platforms.
</details>

<details><summary><b>Q8. How does the FTC relate to AI?</b></summary>

It applies consumer protection law: deceptive or unfair practices, including inaccurate claims about AI capabilities. Be able to back every AI claim with evidence.
</details>

<details><summary><b>Q9. How do you stay compliant with many state laws at once?</b></summary>

Keep an AI inventory, adopt NIST AI RMF / ISO/IEC 42001-style controls, map them to each law, track affected people's jurisdictions, and review on a schedule.
</details>

<details><summary><b>Q10. Compare the US and EU approaches in two sentences.</b></summary>

The EU has one broad, risk-based regulation with phased dates. The US has no single federal AI Act: executive actions, narrow federal laws, sector regulators and a patchwork of state laws that you must track separately.
</details>

## 8. Checklist

- [ ] I can list the federal actions in order and say they are not statutes.
- [ ] I can explain why an executive order cannot repeal state law.
- [ ] I know what each named state law is about, and I checked at least one against its official text.
- [ ] I wrote down the date I verified each item.

## 9. References

- Federal Register (executive orders: EO 14110, 14148, 14179, 14365) and whitehouse.gov; America's AI Action Plan (July 2025).
- California Legislative Information (SB 53); Texas Legislature Online (HB 149); Colorado General Assembly (SB24-205, SB 26-189); NYC Department of Consumer and Worker Protection (Local Law 144); Utah Legislature; congress.gov (TAKE IT DOWN Act).
- FTC business guidance on AI claims (ftc.gov); NIST AI RMF (nist.gov).

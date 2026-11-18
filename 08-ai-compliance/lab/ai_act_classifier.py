"""EU AI Act applicability and classification questionnaire engine.

    EDUCATIONAL TOOL - NOT LEGAL ADVICE. It simplifies Regulation (EU) 2024/1689 to teach
    the *shape* of the decision. Real classification needs the official text, current
    Commission guidelines and qualified legal counsel. Dates and some obligations may be
    changed by later EU acts (the Commission proposed a "Digital Omnibus" in Nov 2025):
    check the current status before relying on any date here.

Input: one YAML mapping of answers per AI system (see fixtures/ai_act_cases.yaml).
Output: categories, the obligations for the organization's *role*, the date each one
applies from, and the open questions to take to counsel.

How it differs from the naive classifier in vulnerable_compliance.py:
    * Every question must be answered. Unknown answers fail closed (no silent "minimal").
    * Decisions are made in a fixed order: scope -> prohibited -> high-risk -> exception
      -> transparency -> GPAI. Each step is explained.
    * Obligations depend on the role (provider, deployer, importer, distributor).
    * The Article 6(3) exception is refused when the system profiles people.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from typing import Literal

from pydantic import BaseModel, ConfigDict, ValidationError

DISCLAIMER = "Educational, not legal advice. Verify against the official text and current EU guidance."
DATES_NOTE = ("Dates are those in Regulation (EU) 2024/1689 as adopted. Later EU acts may change them: "
              "check the current status.")

# Key application dates (Article 113, as adopted).
D_PROHIBITED = date(2025, 2, 2)    # Chapters I-II: definitions, AI literacy, prohibited practices
D_GPAI = date(2025, 8, 2)          # GPAI obligations, governance, penalties
D_GENERAL = date(2026, 8, 2)       # most other obligations, incl. Annex III high-risk and Art 50
D_ANNEX_I = date(2027, 8, 2)       # Art 6(1): high-risk safety components of Annex I products

PROHIBITED = {
    "harmful_manipulation": "subliminal, manipulative or deceptive techniques causing significant harm",
    "exploiting_vulnerabilities": "exploiting vulnerabilities due to age, disability or social/economic situation",
    "social_scoring": "social scoring leading to unjustified or unrelated detrimental treatment",
    "predictive_policing_profiling": "predicting criminal offences based solely on profiling or personality traits",
    "untargeted_face_scraping": "building facial recognition databases by untargeted scraping",
    "emotion_recognition_work_education": "emotion recognition in the workplace or education (except medical/safety)",
    "biometric_categorisation_sensitive": "biometric categorisation to infer sensitive traits such as race or religion",
    "realtime_remote_biometric_id_law_enforcement": "real-time remote biometric identification in public "
                                                    "spaces for law enforcement (narrow exceptions)",
}
AnnexIII = Literal["none", "biometrics", "critical_infrastructure", "education", "employment",
                   "essential_services", "law_enforcement", "migration_border", "justice_democracy"]
Art63 = Literal["none", "narrow_procedural_task", "improve_prior_human_activity",
                "detect_patterns_without_replacing_review", "preparatory_task"]


class Answers(BaseModel):
    """Every field is required on purpose: 'I don't know' must not become 'minimal risk'."""

    model_config = ConfigDict(extra="forbid")
    case: str
    system: str
    is_ai_system: bool
    eu_nexus: bool  # placed on the EU market, put into service in the EU, or output used in the EU
    exclusion: Literal["none", "military_defence_national_security", "scientific_research_only",
                       "personal_non_professional"]
    role: Literal["provider", "deployer", "importer", "distributor"]
    prohibited_practices: list[Literal[tuple(PROHIBITED)]]  # type: ignore[valid-type]
    annex_i_safety_component: bool
    annex_iii_area: AnnexIII
    art6_3_exception: Art63
    profiling: bool
    interacts_with_people: bool
    generates_synthetic_content: bool
    emotion_or_biometric_categorisation: bool
    deep_fake: bool
    public_interest_text: bool
    gpai_model_provider: bool
    gpai_systemic_risk: bool
    public_body_or_public_service: bool
    credit_or_life_health_insurance: bool  # Annex III point 5(b) or 5(c)


@dataclass
class Obligation:
    ref: str
    text: str
    applies_from: date

    def in_force(self, on: date) -> bool:
        return on >= self.applies_from


@dataclass
class Classification:
    case: str
    system: str
    role: str
    categories: list[str]
    reasons: list[str] = field(default_factory=list)
    obligations: list[Obligation] = field(default_factory=list)
    open_questions: list[str] = field(default_factory=list)
    disclaimer: str = DISCLAIMER

    @property
    def primary(self) -> str:
        return self.categories[0]

    @property
    def refs(self) -> set[str]:
        return {o.ref for o in self.obligations}


def _ob(ref: str, text: str, when: date) -> Obligation:
    return Obligation(ref, text, when)


def classify(raw: dict) -> Classification:
    """Classify one system. Raises ValueError (fail closed) if the answers are incomplete."""
    try:
        a = Answers.model_validate(raw)
    except ValidationError as exc:
        missing = sorted({str(e["loc"][0]) for e in exc.errors()})
        raise ValueError(f"questionnaire incomplete or invalid for '{raw.get('case', '?')}': {missing}") from exc

    c = Classification(a.case, a.system, a.role, [])
    add, why = c.obligations.append, c.reasons.append

    # 1. Scope -----------------------------------------------------------------------
    if not a.is_ai_system:
        c.categories = ["out_of_scope"]
        why("not an 'AI system' under Art 3(1); other laws (GDPR, consumer, sector rules) still apply")
        c.open_questions.append("Is the 'not an AI system' view documented, using the Commission's guidelines?")
        return c
    if not a.eu_nexus:
        c.categories = ["out_of_scope"]
        why("no EU market, EU use or EU-used output (Art 2(1))")
        c.open_questions.append("Re-check if you start selling in the EU or EU users receive the output.")
        return c
    if a.exclusion != "none":
        c.categories = ["out_of_scope"]
        why(f"excluded by Art 2: {a.exclusion.replace('_', ' ')}")
        c.open_questions.append("Confirm the exclusion with counsel; exclusions are read narrowly.")
        return c

    if a.role in {"provider", "deployer"}:
        add(_ob("Art 4", "AI literacy: staff who operate or use AI have sufficient AI literacy", D_PROHIBITED))

    # 2. Prohibited practices --------------------------------------------------------
    if a.prohibited_practices:
        c.categories = ["prohibited"]
        for p in a.prohibited_practices:
            why(f"Art 5 prohibited practice: {PROHIBITED[p]}")
        add(_ob("Art 5", "Do not place on the market, put into service or use this practice "
                         "(fines up to EUR 35m or 7% of worldwide turnover, Art 99)", D_PROHIBITED))
        return c

    # 3. High-risk ---------------------------------------------------------------------
    high_risk = False
    if a.annex_i_safety_component:
        high_risk = True
        why("Art 6(1): safety component of a product under Annex I law that needs third-party conformity assessment")
    if a.annex_iii_area != "none":
        if a.art6_3_exception != "none" and not a.profiling:
            c.categories.append("annex_iii_not_high_risk")
            why(f"Annex III area '{a.annex_iii_area}', but Art 6(3) exception '{a.art6_3_exception}' "
                "and no profiling")
            if a.role == "provider":
                add(_ob("Art 6(4)", "Document why the system is not high-risk before placing it on the market",
                        D_GENERAL))
                add(_ob("Art 49(2)", "Register the system in the EU database even though it is not high-risk",
                        D_GENERAL))
            c.open_questions.append("Does the Art 6(3) exception really fit? Ask counsel to review the record.")
        else:
            high_risk = True
            if a.art6_3_exception != "none" and a.profiling:
                why("Art 6(3) exception refused: the system profiles natural persons")
            why(f"Art 6(2) + Annex III area: {a.annex_iii_area}")
    if high_risk:
        c.categories.append("high_risk")
        when = D_ANNEX_I if a.annex_i_safety_component and a.annex_iii_area == "none" else D_GENERAL
        _high_risk_obligations(a, add, when, c.open_questions)

    # 4. Transparency (Art 50) --------------------------------------------------------
    transparency = []
    if a.role == "provider" and a.interacts_with_people:
        transparency.append(_ob("Art 50(1)", "Tell people they are interacting with an AI system "
                                             "(unless obvious)", D_GENERAL))
    if a.role == "provider" and a.generates_synthetic_content:
        transparency.append(_ob("Art 50(2)", "Mark synthetic audio, image, video or text in a "
                                             "machine-readable way", D_GENERAL))
    if a.role == "deployer" and a.emotion_or_biometric_categorisation:
        transparency.append(_ob("Art 50(3)", "Inform people exposed to emotion recognition or "
                                             "biometric categorisation", D_GENERAL))
    if a.role == "deployer" and a.deep_fake:
        transparency.append(_ob("Art 50(4)", "Disclose that deep-fake content is artificially "
                                             "generated or manipulated", D_GENERAL))
    if a.role == "deployer" and a.public_interest_text:
        transparency.append(_ob("Art 50(4)", "Disclose AI-generated text published on matters of public "
                                             "interest, unless under human editorial control", D_GENERAL))
    if transparency:
        c.categories.append("transparency")
        why("Art 50 transparency duties apply")
        c.obligations.extend(transparency)

    # 5. General-purpose AI models (a separate track, at model level) ------------------
    if a.gpai_model_provider:
        c.categories.append("gpai_systemic_risk" if a.gpai_systemic_risk else "gpai_model")
        why("provider of a general-purpose AI model (Chapter V)")
        add(_ob("Art 53(1)(a)", "Technical documentation of the model (Annex XI)", D_GPAI))
        add(_ob("Art 53(1)(b)", "Information and documentation for downstream providers (Annex XII)", D_GPAI))
        add(_ob("Art 53(1)(c)", "A policy to comply with EU copyright law, incl. text-and-data-mining opt-outs",
                D_GPAI))
        add(_ob("Art 53(1)(d)", "Publish a summary of the content used for training (Commission template)",
                D_GPAI))
        c.open_questions.append("Models placed on the market before 2 Aug 2025 have a transition period; "
                                "check which applies. Consider the GPAI Code of Practice.")
        if a.gpai_systemic_risk:
            why("GPAI model with systemic risk (Art 51)")
            add(_ob("Art 52", "Notify the Commission that the model meets the systemic-risk threshold", D_GPAI))
            add(_ob("Art 55(1)(a)", "Evaluate the model, including adversarial testing", D_GPAI))
            add(_ob("Art 55(1)(b)", "Assess and mitigate possible systemic risks at EU level", D_GPAI))
            add(_ob("Art 55(1)(c)", "Track, document and report serious incidents to the AI Office", D_GPAI))
            add(_ob("Art 55(1)(d)", "Ensure adequate cybersecurity for the model and its infrastructure", D_GPAI))

    if not c.categories:
        c.categories = ["minimal_risk"]
        why("no prohibited, high-risk, transparency or GPAI trigger; voluntary codes of conduct encouraged")
    return c


def _high_risk_obligations(a: Answers, add, when: date, questions: list[str]) -> None:
    if a.role == "provider":
        for ref, text in [
            ("Art 9", "Risk management system across the whole lifecycle"),
            ("Art 10", "Data and data governance for training, validation and test data"),
            ("Art 11", "Technical documentation (Annex IV), kept up to date"),
            ("Art 12", "Automatic recording of events (logs) over the system's lifetime"),
            ("Art 13", "Transparency and instructions for use for deployers"),
            ("Art 14", "Design for effective human oversight"),
            ("Art 15", "Accuracy, robustness and cybersecurity"),
            ("Art 17", "Quality management system"),
            ("Art 43", "Conformity assessment before placing on the market"),
            ("Art 47-48", "EU declaration of conformity and CE marking"),
            ("Art 49(1)", "Register in the EU database"),
            ("Art 72", "Post-market monitoring system and plan"),
            ("Art 73", "Report serious incidents to market surveillance authorities"),
        ]:
            add(_ob(ref, text, when))
    elif a.role == "deployer":
        for ref, text in [
            ("Art 26(1)", "Use the system according to the provider's instructions for use"),
            ("Art 26(2)", "Assign human oversight to people with competence, training and authority"),
            ("Art 26(4)", "Make sure input data you control is relevant and representative"),
            ("Art 26(5)", "Monitor operation; inform provider/authorities of risks and serious incidents"),
            ("Art 26(6)", "Keep automatically generated logs under your control for at least six months"),
            ("Art 26(11)", "Inform people that they are subject to the use of a high-risk AI system"),
            ("Art 86", "Be ready to explain individual decisions to affected persons on request"),
        ]:
            add(_ob(ref, text, when))
        if a.annex_iii_area == "employment":
            add(_ob("Art 26(7)", "Inform workers' representatives and affected workers before use", when))
        if a.public_body_or_public_service or a.credit_or_life_health_insurance:
            add(_ob("Art 27", "Fundamental rights impact assessment before first use", when))
        if a.public_body_or_public_service:
            add(_ob("Art 49(3)", "Public-authority deployers register their use in the EU database", when))
        questions.append("Art 25: putting your name on it, substantially modifying it, or changing its "
                         "intended purpose can make YOU the provider. Is any of that planned?")
    elif a.role == "importer":
        add(_ob("Art 23", "Before placing on the market, verify conformity assessment, documentation, "
                          "CE marking and authorised representative", when))
    elif a.role == "distributor":
        add(_ob("Art 24", "Verify CE marking, declaration of conformity and instructions before "
                          "making available", when))


def obligations_in_force(c: Classification, on: date) -> tuple[list[Obligation], list[Obligation]]:
    """Split obligations into (already applicable, upcoming) on a given date."""
    return [o for o in c.obligations if o.in_force(on)], [o for o in c.obligations if not o.in_force(on)]

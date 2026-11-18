"""AI incident triage: category, severity, first actions and the regulatory flags that start
Module 08's reporting clocks.

Rules this module teaches (from the AI incident playbooks in the reading list and from
classic incident response):
    * Severity follows real impact: data, privilege, actions taken, people harmed, scale.
      "An AI was involved" does not by itself raise or lower severity.
    * While harm is ongoing, severity stays high. It may be lowered only after containment
      has been verified (not just requested).
    * Triage outputs the facts Module 08's incident_clock.py needs (EU AI Act serious incident,
      personal data breach, CERT-In reportable incident) so the legal clocks start on time.

Severity scale (this lab's policy):
    SEV1  ongoing harm with sensitive data leaving, privileged access or unauthorized actions;
          or many people harmed; or critical-infrastructure disruption
    SEV2  confirmed exposure of personal/confidential data, unauthorized actions or privileged
          access (contained); or wrong decisions about people
    SEV3  limited impact: internal data, harmful output to a few users, policy breach
    SEV4  near miss: attempt blocked by a control, no impact

    python 07-ai-governance/lab/incident_triage.py 07-ai-governance/lab/fixtures/incidents.yaml
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from pathlib import Path

import yaml

# vector -> (category, OWASP LLM Top 10 2026, OWASP Agentic Top 10 2026, first containment action)
CATEGORIES = {
    "prompt_injection": ("Prompt injection / goal hijack", ["LLM01"], ["ASI01"],
                         "Disable the affected tools or connector (kill switch); keep the model read-only"),
    "tool_misuse": ("Agent tool misuse / excessive agency", ["LLM03"], ["ASI02", "ASI03"],
                    "Revoke the agent's credentials and pause its schedule; require approval for every action"),
    "data_leakage": ("Sensitive information disclosure", ["LLM02"], [],
                     "Block the leaking route (output filter, connector scope); purge caches"),
    "knowledge_poisoning": ("Data / knowledge-base poisoning", ["LLM05", "LLM09"], ["ASI06"],
                            "Quarantine the poisoned sources, rebuild the index from a known-good snapshot"),
    "memory_poisoning": ("Agent memory poisoning", ["LLM05"], ["ASI06"],
                         "Freeze and snapshot agent memory, then roll back to a known-good state"),
    "supply_chain": ("Model / component supply chain", ["LLM04"], ["ASI04"],
                     "Roll back to the last approved artifact hash; block the tampered package or model"),
    "key_theft": ("Stolen model gateway keys or connector tokens", ["LLM02", "LLM06"], ["ASI03"],
                  "Rotate and revoke keys/tokens; set spend and rate limits"),
    "harmful_output": ("Harmful or false output", ["LLM07"], ["ASI09"],
                       "Turn on stricter output filtering or a human check; correct affected answers"),
    "biased_decision": ("Biased or wrong decisions about people", ["LLM07"], [],
                        "Stop automated use; route all cases to human review; re-check affected decisions"),
    "shadow_ai_upload": ("Data uploaded to an unapproved AI service", ["LLM02"], [],
                         "Block the domain at the proxy; request deletion from the service"),
    "model_failure": ("Model failure / drift (no attacker)", ["LLM07"], ["ASI08"],
                      "Roll back the model version or fall back to the non-AI process"),
}
SENSITIVE = {"personal", "sensitive_personal", "confidential"}
MALICIOUS = {"prompt_injection", "tool_misuse", "data_leakage", "knowledge_poisoning", "memory_poisoning",
             "supply_chain", "key_theft"}


@dataclass
class Triage:
    incident_id: str
    category: str
    severity: str
    owasp_llm_2026: list[str]
    owasp_agentic: list[str]
    reasons: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
    clock_flags: dict = field(default_factory=dict)


def triage(inc: dict) -> Triage:
    vector = inc.get("vector")
    if vector not in CATEGORIES:
        raise ValueError(f"unknown vector '{vector}': classify by hand and add it to the catalog")
    name, llm, asi, first_action = CATEGORIES[vector]
    t = Triage(inc.get("id", "?"), name, "SEV4", llm, asi)
    why = t.reasons.append

    data = inc.get("data_exposed", "none")
    ongoing = inc.get("ongoing", False) and not inc.get("containment_verified", False)
    impact_flags = {
        "sensitive data exposed": data in SENSITIVE,
        "privileged access": inc.get("privileged_access", False),
        "unauthorized actions taken": inc.get("unauthorized_actions", False),
    }
    hits = [k for k, v in impact_flags.items() if v]

    if inc.get("blocked_by_control") and not hits and data == "none":
        why("attempt blocked by a control, no impact found")
    elif (ongoing and hits) or inc.get("people_harmed") == "many" or inc.get("critical_infrastructure"):
        t.severity = "SEV1"
        why("ongoing: " + ", ".join(hits) if ongoing and hits else "wide harm or critical infrastructure")
    elif hits or inc.get("decisions_about_people_wrong"):
        t.severity = "SEV2"
        why(", ".join(hits) or "wrong decisions about people")
    else:
        t.severity = "SEV3"
        why("limited impact: " + (f"{data} data" if data != "none" else "no sensitive data, no actions"))
    if inc.get("ongoing") and inc.get("containment_verified"):
        why("containment verified: severity reflects the contained state")

    # Actions: contain first, preserve evidence always.
    if t.severity == "SEV4":
        t.actions.append("Near miss: no containment needed; confirm the control worked and add the input "
                         "to the regression suite")
    else:
        t.actions.append(first_action)
    t.actions.append("Preserve evidence: prompts, retrieved document IDs, tool-call log, model and index "
                     "versions, agent memory snapshot")
    if t.severity in {"SEV1", "SEV2"}:
        t.actions.append("Open a major incident; inform the system owner, CISO, DPO and legal now")

    juris = set(inc.get("jurisdictions") or [])
    personal = data in {"personal", "sensitive_personal"}
    t.clock_flags = {
        "eu_high_risk_provider": bool(inc.get("eu_high_risk_provider")),
        "eu_serious_incident": bool(inc.get("eu_high_risk_provider")) and bool(
            inc.get("people_harmed") in {"individual", "many"} or inc.get("critical_infrastructure")
            or inc.get("fundamental_rights_infringed")),
        "personal_data_breach": personal,
        "eu_personal_data": personal and "eu" in juris,
        "india_personal_data": personal and "india" in juris,
        # CERT-In's list of reportable incident types is broad; a malicious incident on an Indian
        # system is treated as reportable until someone checks the list and decides otherwise.
        "india_reportable_cyber_incident": "india" in juris and vector in MALICIOUS and t.severity != "SEV4",
    }
    return t


def can_downgrade(inc: dict) -> bool:
    """Lower the severity only when containment is verified, not when it was merely requested."""
    return bool(inc.get("containment_verified"))


def main() -> None:
    p = argparse.ArgumentParser(description="Triage AI incidents.")
    p.add_argument("incidents", help="YAML list of incidents")
    args = p.parse_args()
    for inc in yaml.safe_load(Path(args.incidents).read_text(encoding="utf-8")):
        t = triage(inc)
        flags = [k for k, v in t.clock_flags.items() if v]
        print(f"{t.incident_id:7} {t.severity} {t.category:48} {'+'.join(t.owasp_llm_2026 + t.owasp_agentic)}")
        print(f"{'':8}why: {'; '.join(t.reasons)}")
        print(f"{'':8}first action: {t.actions[0]}")
        print(f"{'':8}clock flags for 08: {', '.join(flags) or '-'}")


if __name__ == "__main__":
    main()

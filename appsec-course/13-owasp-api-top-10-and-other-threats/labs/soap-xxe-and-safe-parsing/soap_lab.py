"""Attacking SOAP APIs safely: XXE, entity expansion (billion laughs), SOAPAction
spoofing, XML Signature Wrapping (XSW) and WSDL exposure.

Important: Python's xml.etree.ElementTree does NOT fetch external entities, and the
bundled expat (2.4.1+) limits entity amplification. To show what a misconfigured
parser in another stack (old Java/.NET/PHP/libxml2 settings) would do, legacy_parse()
SIMULATES entity resolution against a FAKE in-memory file system (a dict). No real file
or network access happens, and expansion is computed, not materialised.

safe_parse() is a defusedxml-style guard written by hand: reject any DOCTYPE/ENTITY,
then parse with ElementTree, then validate the operation against the WSDL allowlist.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import xml.etree.ElementTree as ET

SOAP_NS = "http://schemas.xmlsoap.org/soap/envelope/"
FAKE_FS = {"/etc/passwd": "root:x:0:0:FAKE:/root:/bin/bash", "/app/config.yml": "db_password: FAKE-" + secrets.token_hex(3)}

ENTITY_DECL = re.compile(r'<!ENTITY\s+(\w+)\s+(SYSTEM\s+"([^"]+)"|"([^"]*)")\s*>')


class XMLSecurityError(ValueError):
    pass


# ------------------------------------------------------------------ parsing


def legacy_parse(xml: str, max_report: int = 10**12):
    """Simulates a parser with DTDs and external entities ENABLED.
    Returns (text of <data>, expanded_size_estimate)."""
    entities: dict[str, str] = {}
    sizes: dict[str, int] = {}
    for name, _, system, literal in ENTITY_DECL.findall(xml):
        if system:  # external entity -> "read the file" (from the FAKE dict only)
            path = system.removeprefix("file://")
            entities[name] = FAKE_FS.get(path, "")
            sizes[name] = len(entities[name])
        else:
            refs = re.findall(r"&(\w+);", literal)
            sizes[name] = len(re.sub(r"&\w+;", "", literal)) + sum(sizes.get(r, 0) for r in refs)
            entities[name] = literal if sizes[name] < 10_000 else f"[{sizes[name]} bytes]"
    body = re.sub(r"<!DOCTYPE.*?\]>", "", xml, flags=re.S)
    m = re.search(r"<data>(.*?)</data>", body, re.S)
    text = m.group(1) if m else ""
    total = len(re.sub(r"&\w+;", "", text))
    for name in re.findall(r"&(\w+);", text):
        total += sizes.get(name, 0)
        if sizes.get(name, 0) < 10_000:
            text = text.replace(f"&{name};", entities[name])
    return text, min(total, max_report)


def safe_parse(xml: str, max_bytes: int = 100_000) -> ET.Element:
    if len(xml) > max_bytes:
        raise XMLSecurityError("message too large")
    if re.search(r"<!DOCTYPE|<!ENTITY", xml, re.I):
        raise XMLSecurityError("DTDs and entities are not allowed")
    return ET.fromstring(xml)


# ------------------------------------------------------------------ SOAP service

WSDL_PUBLIC_OPS = {"GetBalance"}
WSDL_ALL_OPS = WSDL_PUBLIC_OPS | {"AdminTransferFunds", "AdminDumpCustomers"}


def body_operation(env: ET.Element) -> ET.Element:
    body = env.find(f"{{{SOAP_NS}}}Body")
    if body is None or len(body) == 0:
        raise XMLSecurityError("no SOAP Body")
    return body[0]


def dispatch(xml: str, soap_action: str, role: str, secure: bool):
    env = safe_parse(xml) if secure else ET.fromstring(xml)
    op_el = body_operation(env)
    op = op_el.tag.split("}")[-1]
    authorized_by = soap_action if not secure else op  # vulnerable: authorize the HEADER, run the BODY
    if secure and soap_action.strip('"') != op:
        return 400, "SOAPAction does not match the Body operation"
    if secure and op not in (WSDL_ALL_OPS if role == "admin" else WSDL_PUBLIC_OPS):
        return 403, f"operation {op} not allowed"
    if not secure and authorized_by.strip('"').startswith("Admin") and role != "admin":
        return 403, "admin only"
    return 200, f"executed {op}"


def wsdl(secure: bool, env: str) -> str:
    """Vulnerable: ?wsdl in production lists every operation, including admin ones."""
    if secure and env == "prod":
        return "404 (WSDL not published in production; shared with partners out of band)"
    ops = WSDL_PUBLIC_OPS if secure else WSDL_ALL_OPS
    return "<definitions>" + "".join(f"<operation name='{o}'/>" for o in sorted(ops)) + "</definitions>"


# ------------------------------------------------------------------ XML Signature Wrapping (simplified)

KEY = secrets.token_bytes(32)


def sign_element(el: ET.Element) -> str:
    return hmac.new(KEY, ET.tostring(el), hashlib.sha256).hexdigest()


def make_signed_envelope(amount: int) -> str:
    env = ET.Element(f"{{{SOAP_NS}}}Envelope")
    header = ET.SubElement(env, f"{{{SOAP_NS}}}Header")
    body = ET.SubElement(env, f"{{{SOAP_NS}}}Body", {"Id": "body-1"})
    t = ET.SubElement(body, "Transfer")
    t.set("amount", str(amount))
    t.set("to", "acct-alice")
    sig = ET.SubElement(header, "Signature", {"ref": "body-1"})
    sig.text = sign_element(body)
    return ET.tostring(env, encoding="unicode")


def wrap_attack(signed_xml: str) -> str:
    """Move the signed Body into the Header (keeping its Id) and add a new, evil Body."""
    env = ET.fromstring(signed_xml)
    header = env.find(f"{{{SOAP_NS}}}Header")
    body = env.find(f"{{{SOAP_NS}}}Body")
    env.remove(body)
    wrapper = ET.SubElement(header, "Wrapper")
    wrapper.append(body)
    evil = ET.SubElement(env, f"{{{SOAP_NS}}}Body", {"Id": "body-evil"})
    t = ET.SubElement(evil, "Transfer")
    t.set("amount", "1000000")
    t.set("to", "acct-mallory")
    return ET.tostring(env, encoding="unicode")


def process_signed(xml: str, secure: bool):
    env = safe_parse(xml)
    sig = env.find(f".//{{{SOAP_NS}}}Header/Signature")
    ref = sig.get("ref")
    signed = next((e for e in env.iter() if e.get("Id") == ref), None)  # find by Id anywhere
    if signed is None or not hmac.compare_digest(sign_element(signed), sig.text):
        return "signature invalid"
    if secure:
        used = signed  # verify what you use: process exactly the signed element
        if signed is not env.find(f"{{{SOAP_NS}}}Body"):
            return "rejected: signed element is not the SOAP Body"
    else:
        used = env.find(f"{{{SOAP_NS}}}Body")  # business logic reads the first Body
    t = used.find("Transfer")
    return f"transfer {t.get('amount')} to {t.get('to')}"

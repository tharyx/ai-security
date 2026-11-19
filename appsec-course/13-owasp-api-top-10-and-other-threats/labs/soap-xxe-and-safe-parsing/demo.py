import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import soap_lab as s  # noqa: E402

XXE = """<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY xxe SYSTEM "file:///app/config.yml"> ]>
<r><data>&xxe;</data></r>"""
LAUGHS = '<?xml version="1.0"?>\n<!DOCTYPE r [\n <!ENTITY l0 "lol">\n' + "".join(
    f' <!ENTITY l{i} "{("&l" + str(i - 1) + ";") * 10}">\n' for i in range(1, 10)) + ']>\n<r><data>&l9;</data></r>'

print("== XXE (simulated legacy parser, FAKE file system) ==")
print("legacy parser returns:", s.legacy_parse(XXE)[0])
try:
    s.safe_parse(XXE)
except s.XMLSecurityError as e:
    print("safe_parse:", e)

print("\n== Billion laughs (", len(LAUGHS), "bytes of input ) ==")
print("legacy parser would expand to", f"{s.legacy_parse(LAUGHS)[1]:,}", "bytes")
try:
    s.safe_parse(LAUGHS)
except s.XMLSecurityError as e:
    print("safe_parse:", e)

print("\n== SOAPAction spoofing ==")
evil = (f'<soap:Envelope xmlns:soap="{s.SOAP_NS}"><soap:Body>'
        '<AdminTransferFunds xmlns="urn:bank"/></soap:Body></soap:Envelope>')
for secure in (False, True):
    print(f"{'secure' if secure else 'vuln  '}: SOAPAction=GetBalance, Body=AdminTransferFunds, role=user ->",
          s.dispatch(evil, '"GetBalance"', "user", secure))

print("\n== XML Signature Wrapping ==")
signed = s.make_signed_envelope(100)
attack = s.wrap_attack(signed)
for secure in (False, True):
    print(f"{'secure' if secure else 'vuln  '}: original ->", s.process_signed(signed, secure),
          "| wrapped ->", s.process_signed(attack, secure))

print("\n== WSDL exposure ==")
print("vulnerable ?wsdl in prod:", s.wsdl(False, "prod"))
print("secure ?wsdl in prod    :", s.wsdl(True, "prod"))

import xml.etree.ElementTree as ET

import pytest

from aisec_lab import load_lab_module

s = load_lab_module(__file__, "soap_lab")
XXE = '<?xml version="1.0"?><!DOCTYPE r [ <!ENTITY xxe SYSTEM "file:///app/config.yml"> ]><r><data>&xxe;</data></r>'
LAUGHS = ('<!DOCTYPE r [<!ENTITY l0 "lol">' + "".join(f'<!ENTITY l{i} "{("&l" + str(i - 1) + ";") * 10}">'
                                                     for i in range(1, 10)) + ']><r><data>&l9;</data></r>')
EVIL_ACTION = (f'<soap:Envelope xmlns:soap="{s.SOAP_NS}"><soap:Body>'
               '<AdminTransferFunds xmlns="urn:bank"/></soap:Body></soap:Envelope>')


def test_xxe_reads_fake_config_file_with_legacy_parser():
    assert s.legacy_parse(XXE)[0].startswith("db_password: FAKE-")


def test_safe_parse_rejects_doctype_and_entities():
    for doc in (XXE, LAUGHS):
        with pytest.raises(s.XMLSecurityError):
            s.safe_parse(doc)


def test_billion_laughs_expands_to_three_gigabytes_from_a_tiny_input():
    assert len(LAUGHS) < 1000 and s.legacy_parse(LAUGHS)[1] == 3 * 10**9


def test_python_elementtree_does_not_resolve_external_entities():
    with pytest.raises(ET.ParseError):
        ET.fromstring(XXE)  # undefined entity: stdlib refuses to fetch it


def test_soapaction_spoofing_runs_admin_operation_only_when_vulnerable():
    assert s.dispatch(EVIL_ACTION, '"GetBalance"', "user", secure=False) == (200, "executed AdminTransferFunds")
    assert s.dispatch(EVIL_ACTION, '"GetBalance"', "user", secure=True)[0] == 400
    assert s.dispatch(EVIL_ACTION, '"AdminTransferFunds"', "user", secure=True)[0] == 403
    assert s.dispatch(EVIL_ACTION, '"AdminTransferFunds"', "admin", secure=True)[0] == 200


def test_signature_wrapping_executes_unsigned_body_only_when_vulnerable():
    attack = s.wrap_attack(s.make_signed_envelope(100))
    assert s.process_signed(attack, secure=False) == "transfer 1000000 to acct-mallory"
    assert s.process_signed(attack, secure=True).startswith("rejected")


def test_untouched_signed_message_is_accepted_and_tampering_detected():
    signed = s.make_signed_envelope(100)
    assert s.process_signed(signed, secure=True) == "transfer 100 to acct-alice"
    assert s.process_signed(signed.replace('amount="100"', 'amount="999"'), secure=True) == "signature invalid"


def test_wsdl_lists_admin_operations_in_prod_only_when_vulnerable():
    assert "AdminDumpCustomers" in s.wsdl(False, "prod")
    assert s.wsdl(True, "prod").startswith("404")

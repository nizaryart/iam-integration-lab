"""Use case: SAML 2.0 federation. Signed assertions, group authorization, tampering, replay."""
import base64
import re

import lab


def post(browser, action, fields):
    return browser.s.post(action, data=fields)


def tamper(fields, old, new):
    xml = base64.b64decode(fields["SAMLResponse"]).decode()
    assert old in xml
    return {**fields, "SAMLResponse": base64.b64encode(xml.replace(old, new).encode()).decode()}


def test_finance_user_gets_finance_documents_only():
    b = lab.Browser()
    action, fields = b.saml_response("alice")
    page = post(b, action, fields)
    assert "Welcome alice" in page.text and "Finance" in page.text
    assert b.get(f"{lab.SAML_APP}/finance-documents").status_code == 200
    assert b.get(f"{lab.SAML_APP}/hr-documents").status_code == 403


def test_hr_user_gets_hr_documents_only():
    b = lab.Browser()
    post(b, *b.saml_response("bob"))
    assert b.get(f"{lab.SAML_APP}/hr-documents").status_code == 200
    assert b.get(f"{lab.SAML_APP}/finance-documents").status_code == 403


def test_assertion_and_response_are_signed_with_rsa_sha256():
    _, fields = lab.Browser().saml_response("alice")
    xml = base64.b64decode(fields["SAMLResponse"]).decode()
    assert len(re.findall(r"<(?:\w+:)?Signature[ >]", xml)) == 2      # Response + Assertion
    assert "rsa-sha256" in xml


def test_only_needed_attributes_are_released():
    _, fields = lab.Browser().saml_response("alice")
    xml = base64.b64decode(fields["SAMLResponse"]).decode()
    assert set(re.findall(r'<saml:Attribute Name="([^"]+)"', xml)) == {"email", "groups"}


def test_modified_group_attribute_is_rejected():
    b = lab.Browser()
    action, fields = b.saml_response("alice")
    forged = tamper(fields, ">Finance<", ">HR<")                        # privilege change
    assert post(b, action, forged).status_code == 403
    assert b.get(f"{lab.SAML_APP}/hr-documents", allow_redirects=False).status_code != 200


def test_modified_name_id_is_rejected():
    b = lab.Browser()
    action, fields = b.saml_response("alice")
    assert post(b, action, tamper(fields, ">alice<", ">carol<")).status_code == 403


def test_replayed_response_is_rejected():
    b = lab.Browser()
    action, fields = b.saml_response("alice")
    assert post(b, action, fields).status_code == 200
    assert post(b, action, fields).status_code == 403                    # same response again


def test_response_stolen_into_another_browser_is_rejected():
    victim, attacker = lab.Browser(), lab.Browser()
    action, fields = victim.saml_response("alice")
    attacker.get(f"{lab.SAML_APP}/login")                                # attacker's own request
    assert post(attacker, action, fields).status_code == 403             # InResponseTo mismatch


def test_unsolicited_response_is_rejected():
    _, fields = lab.Browser().saml_response("alice")
    fresh = lab.Browser()
    assert post(fresh, f"{lab.SAML_APP}/acs", fields).status_code == 403

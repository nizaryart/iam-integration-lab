"""Use case: privileged access. MFA is enforced by role, not left to the user."""
import lab


def test_admin_is_forced_to_enrol_totp_then_gets_admin_area():
    b = lab.Browser()
    page = b.portal_login("carol")                 # enrolment page appears, the helper completes it
    assert lab.logged_in(page)
    assert b.get(f"{lab.PORTAL}/admin").status_code == 200
    lab.CAROL_TOTP = b.enrolled_secret


def test_admin_login_requires_the_totp_code():
    page = lab.Browser().portal_login("carol")    # correct password, no code
    assert not lab.logged_in(page)
    assert 'id="kc-otp-login-form"' in page.text


def test_admin_login_with_wrong_code_fails_and_right_code_works():
    page = lab.Browser().portal_login("carol", otp_secret="WRONG")
    assert not lab.logged_in(page)
    assert "Invalid authenticator code" in page.text
    page = lab.Browser().portal_login("carol", otp_secret=lab.CAROL_TOTP)
    assert lab.logged_in(page)


def test_standard_user_is_not_asked_for_mfa():
    page = lab.Browser().portal_login("alice")
    assert lab.logged_in(page) and "kc-otp-login-form" not in page.text

import pytest

import lab


@pytest.fixture(scope="session")
def kc():
    return lab.admin()


@pytest.fixture(autouse=True, scope="session")
def clean_state(kc):
    """Known starting point: no brute-force lockouts, carol not yet enrolled in TOTP."""
    kc("DELETE", "/corp/attack-detection/brute-force/users")
    carol = lab.user_id(kc, "carol")
    if carol:
        for cred in kc("GET", f"/corp/users/{carol}/credentials"):
            if cred["type"] == "otp":
                kc("DELETE", f"/corp/users/{carol}/credentials/{cred['id']}")
    yield
    kc("DELETE", "/corp/attack-detection/brute-force/users")

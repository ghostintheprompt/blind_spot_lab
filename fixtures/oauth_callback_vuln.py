"""An OAuth callback that forgets the 'state' check, and compares a
token with ==. Should REJECT (CWE-352 + CWE-208). This is the
Omniscient-domain fixture: auth-logic, not endpoint behavior."""
import requests


def oauth_callback(request, session):
    # 'code' is exchanged for a token, but 'state' is never validated.
    # Classic authorization-code CSRF / interception exposure.
    code = request.args.get("code", "")
    resp = requests.post(
        "https://idp.example.com/token",
        data={"grant_type": "authorization_code", "code": code},
        timeout=10,
    )
    return resp.json()["access_token"]


def check_api_token(provided: str, expected_api_token: str) -> bool:
    # Byte-by-byte == on a secret leaks length/prefix via timing.
    return provided == expected_api_token

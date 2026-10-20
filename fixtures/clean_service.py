"""A clean OAuth callback + helpers. Should PASS the auditor."""
import hmac
import secrets
import subprocess

import requests


def oauth_callback(request, session):
    # State is validated against what we stored before the redirect.
    returned_state = request.args.get("state", "")
    stored_state = session.get("oauth_state", "")
    if not hmac.compare_digest(returned_state, stored_state):
        raise PermissionError("state mismatch")

    code = request.args.get("code", "")
    token = requests.post(
        "https://idp.example.com/token",
        data={"grant_type": "authorization_code", "code": code},
        verify=True,
        timeout=10,
    ).json()["access_token"]
    return token


def verify_webhook(payload: bytes, provided_signature: str, signing_key: bytes) -> bool:
    expected = hmac.new(signing_key, payload, "sha256").hexdigest()
    return hmac.compare_digest(expected, provided_signature)


def list_dir(path: str):
    # No shell, argument vector, no interpolation.
    return subprocess.run(["ls", "-la", path], capture_output=True, check=True)


def new_session_id() -> str:
    return secrets.token_urlsafe(32)

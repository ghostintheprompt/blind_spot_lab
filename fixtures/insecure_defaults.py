"""TLS off, weak hash on a password, a hard-coded key. Should REJECT."""
import hashlib

import requests

API_KEY = "sk_live_9f2a7c4e18b0d6"  # CWE-798 hard-coded secret


def fetch(url: str):
    # CWE-295 — certificate verification turned off.
    return requests.get(url, headers={"Authorization": API_KEY}, verify=False, timeout=10)


def hash_password(pw: str) -> str:
    # CWE-327 — md5 is broken for password storage.
    return hashlib.md5(pw.encode()).hexdigest()

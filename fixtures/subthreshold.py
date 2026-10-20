"""Four MEDIUM findings, nothing HIGH or CRITICAL. Risk score 8, under
the REJECT_THRESHOLD of 10, so the consensus verdict is PASS.

This fixture exists to make a known limitation visible, not to pass
cleanly: a pile of individually-MEDIUM weaknesses can clear the gate
even though, together, this module uses a broken hash in four places.
See the README 'Known limitations' section — this gap is documented,
not tuned away.
"""
import hashlib


def etag(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def cache_key(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def dedup_id(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def content_fingerprint(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()

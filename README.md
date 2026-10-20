# blind_spot_lab

Reviewing code with a system of agents that vote on a verdict is becoming
common. This lab is not another entry in the race to find the most bugs.
It looks at the other question: when a consensus of agents reviews code,
where does it go blind, and what walks through the gap?

To study that honestly you need a reviewer that actually works, so there
is one here. Two specialized agents read the same syntax tree, and a
verifier turns their findings into one PASS or REJECT. It uses the standard
library only, no API key, no network. The reviewer is the substrate. The
blind spots are what the lab is about.

```
python3 consensus_audit.py                      # audit the bundled fixtures
python3 consensus_audit.py path/to/file.py      # audit one file, JSON out
python3 -m unittest -v test_consensus_audit.py  # the test suite (10, all green)
```

## Blind spot 1: what the swarm never sees

A reviewer can only catch what it looks at the right way. The baseline
`naive_regex_review.py` is a reasonable grep-style reviewer. Run it and the
structural reviewer against the same two command injections:

```
$ python3 naive_regex_review.py fixtures/command_injection.py
REJECT
  L18   REGEX-CMD  possible command injection      # the "+ user_path" concat

$ python3 consensus_audit.py fixtures/command_injection.py   # (findings)
  L14 CTX-CMD-INJECTION CRITICAL CWE-78            # the f-string, missed by regex
  L18 CTX-CMD-INJECTION CRITICAL CWE-78
```

`os.system(f"ping -c 1 {user_host}")` has no `+` for a text pattern to
catch, so the baseline walks past it. The AST sees `os.system()` receiving a
non-literal command and flags it no matter how the string was assembled.
This is how a lot of adversarial code, and a lot of machine-generated code,
clears text-based review: the dangerous construct is shaped so the matcher
was never looking at it. The same gap matters more as agents start reviewing
generated code, which the OWASP Top 10 for LLM Applications files under
improper output handling. A reviewer that matches text gives the evasion
away for free.

Reading structure handles how the *string* is built. It does not, by
itself, handle how the *sink* is named, which I found by attacking the
detector. `from os import system` then a bare `system(...)` call slipped past
the first version; the reviewer now resolves imports statically and catches
it (`fixtures/import_alias_caught.py`). Rebinding the sink to a variable,
`run = os.system` (`fixtures/alias_blindspot.py`), still slips. That one is
the same no-value-tracking limitation as blind spot 2 below.

## Blind spot 2: what the verifier resolves wrong

This is the part specific to a consensus system, and the reason the lab
exists. The verifier aggregates, removes duplicates, scores, and returns one
verdict. Two failure modes are built in on purpose, demonstrated, and
asserted by the tests rather than hidden:

- **Slow accumulation of medium findings.** `fixtures/subthreshold.py` uses
  a broken hash in four places. Four MEDIUM findings score 8, under the
  `REJECT_THRESHOLD` of 10, so the verdict is **PASS**:

  ```
     PASS  subthreshold.py              score=8   findings=4
  ```

  A module broken in four places clears the gate. Nothing in it is
  individually bad enough, and the verifier has no sense that a pile of
  low-severity findings should add up to something worse. The threshold is a
  named constant so that choice stays visible rather than buried in a
  comparison.

- **No value tracking.** Every agent reads one file's syntax tree in one
  pass and reasons about the shapes it sees directly; it never follows a
  value from where it is set to where it is used. That is why `run =
  os.system` slips, and why a vulnerability assembled across function or
  module boundaries, tainted in one place and dangerous three calls away in
  another, sits outside what the reviewer can see. Catching either needs
  dataflow and taint tracking, which this lab does not do and does not claim
  to.

Stating those limits is the useful part, and most of what I know about them
came from attacking the reviewer rather than trusting it. Saying where a
consensus of agents goes blind, and roughly what it would take to close the
gap, is worth more than one more claim about how many bugs the thing finds.

## Where it does hold

So the blind spots read as chosen rather than accidental, the reviewer is
sharp everywhere else. It flags an OAuth callback that exchanges a `code` but
never validates `state` (CWE-352), a token checked with `==` instead of a
constant-time compare (CWE-208), `verify=False` disabling TLS (CWE-295),
unsafe deserialization (CWE-502), weak hashes (CWE-327), hard-coded secrets
(CWE-798), and eval/exec on dynamic input (CWE-95). It leaves alone the clean
fixture next door that validates `state` with `hmac.compare_digest`. Catching
the bug and staying quiet on the correct version is the harder half, and the
test suite pins both.

## Files

- `consensus_audit.py`: two agents and the verifier (the substrate).
- `naive_regex_review.py`: the string-matching baseline it beats (blind spot 1).
- `fixtures/`: clean, command-injection, OAuth-logic, insecure-defaults,
  and the sub-threshold blind-spot case.
- `test_consensus_audit.py`: 10 tests covering the catches, the clean-code
  quiet, and both blind spots.

## Standards referenced

CWE-78, CWE-95, CWE-208, CWE-295, CWE-327, CWE-352, CWE-502; OWASP Top 10 for
LLM Applications (improper output handling, as the frame for agents that
review model-generated code).

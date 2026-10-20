"""Command injection hidden in an f-string. Should REJECT (CWE-78).

The evasion target: a naive reviewer greps for string concatenation
(` + `) next to a shell sink. This builds the command with an f-string
instead, so that heuristic misses it. The AST sees os.system() receiving
a JoinedStr (non-literal) argument and flags it regardless of how the
string was assembled.
"""
import os


def ping_host(user_host: str):
    # user_host is attacker-controlled; f-string smuggles it into the shell.
    os.system(f"ping -c 1 {user_host}")


def archive(user_path: str):
    os.popen("tar czf /tmp/out.tgz " + user_path)

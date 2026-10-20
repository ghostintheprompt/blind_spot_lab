#!/usr/bin/env python3
"""Unit tests for the multi-agent auditor.

These assert what the harness catches AND, honestly, what it misses:
the sub-threshold blind spot and the f-string that defeats the regex
baseline are asserted as real behavior, not hidden. Stdlib only:

    python3 -m unittest -v test_consensus_audit.py
"""
import os
import unittest

import consensus_audit as ca
import naive_regex_review as naive

FX = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


def audit(name):
    return ca.audit_file(os.path.join(FX, name))

def rules(report):
    return {f["rule_id"] for f in report["findings"]}


class CleanCode(unittest.TestCase):
    def test_clean_service_passes(self):
        rep = audit("clean_service.py")
        self.assertEqual(rep["verdict"], "PASS", rep["findings"])
        self.assertEqual(rep["findings"], [])


class CommandInjection(unittest.TestCase):
    def setUp(self):
        self.rep = audit("command_injection.py")

    def test_rejected_as_critical(self):
        self.assertEqual(self.rep["verdict"], "REJECT")
        self.assertIn("CTX-CMD-INJECTION", rules(self.rep))
        self.assertTrue(any(f["severity"] == "CRITICAL" for f in self.rep["findings"]))

    def test_fstring_evades_the_regex_baseline(self):
        # The whole thesis: AST catches the f-string sink, regex does not.
        path = os.path.join(FX, "command_injection.py")
        with open(path, encoding="utf-8") as fh:
            src = fh.read()
        regex_hits = [h for h in naive.review(src) if h["rule_id"] == "REGEX-CMD"]
        fstring_line = next(l for l, t in enumerate(src.splitlines(), 1)
                            if "ping -c 1" in t)
        self.assertFalse(
            any(h["line"] == fstring_line for h in regex_hits),
            "regex baseline unexpectedly caught the f-string",
        )
        ast_lines = {f["line"] for f in self.rep["findings"]
                     if f["rule_id"] == "CTX-CMD-INJECTION"}
        self.assertIn(fstring_line, ast_lines,
                      "AST auditor missed the f-string command injection")


class OAuthLogic(unittest.TestCase):
    def setUp(self):
        self.rep = audit("oauth_callback_vuln.py")

    def test_missing_state_flagged(self):
        self.assertIn("CTX-OAUTH-STATE", rules(self.rep))

    def test_timing_unsafe_token_compare(self):
        self.assertIn("CTX-TIMING-COMPARE", rules(self.rep))
        hit = next(f for f in self.rep["findings"] if f["rule_id"] == "CTX-TIMING-COMPARE")
        self.assertEqual(hit["cwe"], "CWE-208")

    def test_rejected(self):
        self.assertEqual(self.rep["verdict"], "REJECT")

    def test_clean_callback_not_flagged_for_state(self):
        # The clean fixture validates state with compare_digest — no false positive.
        self.assertNotIn("CTX-OAUTH-STATE", rules(audit("clean_service.py")))


class InsecureDefaults(unittest.TestCase):
    def setUp(self):
        self.rep = audit("insecure_defaults.py")

    def test_all_three_classes(self):
        r = rules(self.rep)
        self.assertIn("CTX-TLS-DISABLED", r)      # CWE-295
        self.assertIn("AST-WEAK-HASH", r)         # CWE-327
        self.assertIn("AST-HARDCODED-SECRET", r)  # CWE-798
        self.assertEqual(self.rep["verdict"], "REJECT")


class ConsensusBlindSpot(unittest.TestCase):
    def test_subthreshold_pile_passes_and_that_is_the_bug(self):
        # Documented limitation: four MEDIUM md5 findings (score 8) sit
        # under REJECT_THRESHOLD (10), so a module that is broken in four
        # places still PASSes. Asserted as real behavior, not hidden.
        rep = audit("subthreshold.py")
        self.assertEqual(rep["metrics"]["findings"], 4)
        self.assertEqual(rep["metrics"]["risk_score"], 8)
        self.assertEqual(rep["verdict"], "PASS")

    def test_cross_agent_corroboration_is_kept(self):
        # Two different agents flagging one line must not be deduped away.
        src = (
            "import os\n"
            "API_TOKEN = 'abcdef123456'\n"
            "os.system('echo ' + API_TOKEN)\n"
        )
        rep = ca.audit_source(src)
        agents = {f["agent"] for f in rep["findings"]}
        self.assertEqual(agents, {"ast-inspector", "context-risk"})


class Aliasing(unittest.TestCase):
    def test_import_alias_now_caught(self):
        # `from os import system` used to slip; static import resolution
        # catches it now.
        rep = audit("import_alias_caught.py")
        self.assertIn("CTX-CMD-INJECTION", rules(rep))
        self.assertEqual(rep["verdict"], "REJECT")

    def test_variable_alias_is_a_known_blind_spot(self):
        # Sink rebound to a variable at runtime. No value tracking, so it
        # slips. Asserted as the documented blind spot, not hidden.
        rep = audit("alias_blindspot.py")
        self.assertEqual(rep["verdict"], "PASS")
        self.assertEqual(rep["findings"], [])


if __name__ == "__main__":
    unittest.main()

import unittest
from unittest.mock import patch

import full_ci
from pr_checks import select


class PRChecks(unittest.TestCase):
    def test_documentation_and_mixed_changes(self):
        self.assertEqual(select(["README.md", "docs/releases.md"]),
                         {"code": "false", "automation": "false", "integration": ""})
        self.assertEqual(select(["docs/releases.md", "web/src/app.tsx"])["code"], "true")
        self.assertTrue(select(["docs/recovery-sessions.sql"])["integration"])
        self.assertEqual(select(["web/package-lock.json"])["integration"], "")
        self.assertEqual(select(["scripts/publish_release.py"])["automation"], "true")

    def test_targeted_regressions(self):
        changed = ["internal/identity/migrations/0032_example.sql", "internal/oidcprovider/refresh.go"]
        pattern = select(changed)["integration"]
        for name in ("TestSchema30UpgradePreservesOIDCRegistrations", "TestConcurrentRefreshRevokesFamily",
                     "TestManagementOrganizationIsolationAndEligibility"):
            self.assertRegex(name, pattern)


class FullValidation(unittest.TestCase):
    repo = "example/memberid"
    sha = "1" * 40
    digest = "sha256:" + "2" * 64

    def test_trusts_only_the_matching_completed_job(self):
        run = {"path": ".github/workflows/full.yml", "event": "schedule", "head_branch": "main",
               "head_repository": {"full_name": self.repo}, "conclusion": "success"}
        job = {"name": f"Full validation {self.sha} {self.digest}", "conclusion": "success"}
        with patch.object(full_ci, "api", side_effect=lambda path: {"jobs": [job]} if "/jobs?" in path else run):
            self.assertTrue(full_ci.exact_run(self.repo, "42/1", self.sha, self.digest))
            self.assertFalse(full_ci.exact_run(self.repo, "42/1", "3" * 40, self.digest))
            self.assertFalse(full_ci.exact_run(self.repo, "42/1", self.sha, "sha256:" + "4" * 64))
            job["conclusion"] = "skipped"
            self.assertFalse(full_ci.exact_run(self.repo, "42/1", self.sha, self.digest))
            job["conclusion"] = "success"
            for key, value in (("path", ".github/workflows/ci.yml"), ("event", "pull_request"),
                               ("head_branch", "other"), ("conclusion", "failure")):
                with patch.dict(run, {key: value}):
                    self.assertFalse(full_ci.exact_run(self.repo, "42/1", self.sha, self.digest))

    def test_preview_dispatch_reuse_and_failure(self):
        url = "https://github.com/" + self.repo + "/actions/runs/42"
        with patch.object(full_ci, "gh") as gh, patch.object(full_ci, "exact_run") as exact:
            exact.return_value = False
            gh.return_value = ""
            self.assertIsNone(full_ci.validated_run(self.repo, "10/1", self.sha, self.digest, publish=False))
            self.assertEqual(gh.call_count, 1)
            gh.return_value = url + "/attempts/2"
            exact.side_effect = [False, True]
            self.assertEqual(full_ci.validated_run(self.repo, "10/1", self.sha, self.digest, publish=True), "42/2")
            for accepted in (True, False):
                gh.side_effect = ["", "42"]
                exact.side_effect = [False, accepted]
                with patch.object(full_ci, "api", return_value={"status": "completed", "run_attempt": 1}):
                    if accepted:
                        self.assertEqual(full_ci.validated_run(self.repo, "10/1", self.sha, self.digest, publish=True), "42/1")
                    else:
                        with self.assertRaisesRegex(ValueError, "did not validate"):
                            full_ci.validated_run(self.repo, "10/1", self.sha, self.digest, publish=True)

import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import publish_release as publish
from release_version import git, impact, plan


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.addCleanup(os.chdir, os.getcwd())
        os.chdir(directory.name)
        git("init", "--quiet", "-b", "main")
        git("config", "user.name", "Release Fixture")
        git("config", "user.email", "fixture@example.invalid")
        git("config", "commit.gpgsign", "false")
        schema = Path("internal/identity/database_upgrade.go")
        schema.parent.mkdir(parents=True)
        schema.write_text("package identity\nconst SchemaVersion = 30\n")
        git("add", ".")
        self.sha = self.commit("chore: establish fixture")

    def commit(self, title):
        git("commit", "--quiet", "--allow-empty", "-m", title)
        return git("rev-parse", "HEAD")

    def test_titles_and_bumps(self):
        for title in ("missing type", "fix: ", "fix: first\nsecond", "fix scope: incorrect"):
            with self.assertRaises(ValueError):
                impact(title)
        self.assertEqual(plan("stable", self.sha)[0], "0.1.0")
        git("tag", "0.1.0")
        sha = self.commit("docs: add a guide")
        with self.assertRaisesRegex(ValueError, "No release-bearing"):
            plan("rc", sha)
        sha = self.commit("fix(console): handle cancellation")
        self.assertEqual(plan("rc", sha)[0], "0.1.1-rc.1")
        git("tag", "0.1.1-rc.1")
        sha = self.commit("fix(api)!: remove obsolete field")
        self.assertEqual(plan("rc", sha)[0], "0.2.0-rc.1")
        git("tag", "0.2.0-rc.1")
        with self.assertRaisesRegex(ValueError, "superseded"):
            plan("promote", git("rev-parse", "0.1.1-rc.1"), "0.1.1-rc.1")
        self.assertEqual(plan("promote", sha, "0.2.0-rc.1")[0], "0.2.0")
        sha = self.commit("fix: polish")
        self.assertEqual(plan("rc", sha, declare_api=True)[0], "1.0.0-rc.1")
        git("tag", "1.0.0")
        self.assertEqual(plan("stable", self.commit("feat(oidc): add scope"))[0], "1.1.0")
        self.assertEqual(plan("stable", self.commit("fix(api)!: replace field"))[0], "2.0.0")

    def test_rc_numbers_and_release_branch(self):
        git("tag", "1.2.0")
        sha = self.commit("fix: correct input")
        git("tag", "1.2.1-rc.9")
        git("switch", "-c", "release/1.2")
        Path("fix").write_text("correction\n")
        git("add", "fix")
        sha = self.commit("fix: correct candidate")
        self.assertEqual(plan("rc", sha)[0], "1.2.1-rc.10")
        git("tag", "1.2.1-rc.10")
        git("tag", "1.2.1")
        git("switch", "main")
        newer = self.commit("feat: add a feature")
        with self.assertRaisesRegex(ValueError, "missing changes"):
            plan("rc", newer)
        git("cherry-pick", sha)
        self.assertEqual(plan("rc", git("rev-parse", "HEAD"))[0], "1.3.0-rc.1")

    def test_release_selection_and_retry(self):
        repo = "example/memberid"
        digest = "sha256:" + "a" * 64
        releases, aliases = {}, {}

        def api(path, payload=None):
            if payload is None:
                return releases.get(path.split("/")[-1])
            name = payload["tag_name"]
            git("tag", name, payload["target_commitish"])
            releases[name] = dict(payload, draft=False)

        def alias(digest, version, publish):
            if publish:
                self.assertEqual(aliases.setdefault(version, digest), digest)

        env = {"GITHUB_REPOSITORY": repo, "RELEASE_MODE": "rc", "RELEASE_SOURCE": "123/1",
               "CONFIRM_VERSION": "", "ROLLING_FROM": "", "DECLARE_API": "false"}
        with (patch.object(publish, "os", SimpleNamespace(environ=env)),
              patch.object(publish, "from_run", return_value=(self.sha, digest)),
              patch.object(publish, "api", side_effect=api) as api_mock,
              patch.object(publish, "Registry") as registry, contextlib.redirect_stdout(io.StringIO())):
            registry.return_value.alias.side_effect = alias
            publish.main()
            self.assertFalse(aliases or releases)
            env["CONFIRM_VERSION"] = "0.2.0-rc.1"
            with self.assertRaisesRegex(ValueError, "plan changed"):
                publish.main()
            env["CONFIRM_VERSION"] = "0.1.0-rc.1"
            # Simulate a failure after the image tag is created.
            api_mock.side_effect = OSError("interrupted")
            with self.assertRaises(OSError):
                publish.main()
            api_mock.side_effect = api
            publish.main()
            publish.main()
            self.commit("feat: advance main")
            env.update(RELEASE_MODE="promote", RELEASE_SOURCE="0.1.0-rc.1", CONFIRM_VERSION="0.1.0")
            publish.main()
            publish.main()
            self.assertEqual(git("rev-parse", "0.1.0"), self.sha)
            self.assertEqual(aliases, {"0.1.0-rc.1": digest, "0.1.0": digest})
            receipt = json.loads(releases["0.1.0"]["body"].splitlines()[1])
            self.assertEqual((receipt["commit"], receipt["schemaVersion"]), (self.sha, 30))

    def test_registry_preserves_exact_manifest(self):
        manifest = b'{"schemaVersion":2}'
        digest = "sha256:" + hashlib.sha256(manifest).hexdigest()
        manifests = {digest: (manifest, "application/vnd.oci.image.manifest.v1+json")}
        registry = publish.Registry.__new__(publish.Registry)
        registry.url, registry.token = "https://example.invalid/manifests/", "fixture"
        registry.read = manifests.get

        def put(request, timeout):
            self.assertEqual((request.method, request.data), ("PUT", manifest))
            manifests["0.1.0"] = (request.data, request.get_header("Content-type"))
            response = io.BytesIO()
            response.status = 201
            return response

        with patch("urllib.request.urlopen", side_effect=put) as transport:
            registry.alias(digest, "0.1.0", False)
            registry.alias(digest, "0.1.0", True)
            registry.alias(digest, "0.1.0", True)
            self.assertEqual(transport.call_count, 1)
            manifests["0.1.0"] = (b"different", "application/json")
            with self.assertRaisesRegex(ValueError, "different manifest"):
                registry.alias(digest, "0.1.0", True)

    def test_source_requires_matching_push_and_receipt(self):
        repo = "example/memberid"
        git("update-ref", "refs/remotes/origin/main", self.sha)
        run = {"path": ".github/workflows/ci.yml", "event": "push", "status": "completed",
               "conclusion": "success", "head_repository": {"full_name": repo},
               "head_sha": self.sha, "head_branch": "main"}
        receipt = {"commit": self.sha, "digest": "sha256:" + "b" * 64}

        def download(*args):
            self.assertIn("image-receipt-2", args)
            (Path(args[-1]) / "image.json").write_text(json.dumps(receipt))

        with patch.object(publish, "api", return_value=run), patch.object(publish, "gh", side_effect=download):
            self.assertEqual(publish.from_run(repo, "42/2"), (self.sha, receipt["digest"]))
            receipt["commit"] = "0" * 40
            with self.assertRaisesRegex(ValueError, "receipt"):
                publish.from_run(repo, "42/2")
            run["event"] = "pull_request"
            with self.assertRaisesRegex(ValueError, "successful CI push"):
                publish.from_run(repo, "42/2")

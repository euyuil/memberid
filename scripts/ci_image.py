"""Resolve immutable CI image receipts and GitHub Release records."""

import json
from pathlib import Path
import re
import subprocess
import tempfile

from release_version import SHA, git

DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
MAINTENANCE = re.compile(r"release/(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")


def gh(*args):
    return subprocess.check_output(["gh", *args], text=True, encoding="utf-8")


def api(path, payload=None):
    cmd = ["gh", "api", path]
    if payload is not None:
        cmd += ["--input", "-"]
    result = subprocess.run(cmd, input=json.dumps(payload) if payload is not None else None,
                            capture_output=True, encoding="utf-8")
    if result.returncode:
        if payload is None and "(HTTP 404)" in result.stderr:
            return None
        raise ValueError("GitHub API request failed: " + result.stderr.strip())
    return json.loads(result.stdout)


def from_run(repo, source):
    if not re.fullmatch(r"[1-9][0-9]*/[1-9][0-9]*", source):
        raise ValueError("Select a successful CI run as RUN_ID/ATTEMPT")
    run_id, attempt = source.split("/")
    run = api(f"repos/{repo}/actions/runs/{run_id}/attempts/{attempt}")
    if not run or not (run["path"] == ".github/workflows/ci.yml" and run["event"] == "push"
                       and run["conclusion"] == "success" and run["status"] == "completed"
                       and run["head_repository"]["full_name"].lower() == repo):
        raise ValueError("Select a successful CI push run from this repository")
    sha, branch = run["head_sha"], run["head_branch"]
    if not SHA.fullmatch(sha):
        raise ValueError("Invalid CI commit")
    if branch != "main" and not MAINTENANCE.fullmatch(branch):
        raise ValueError("Select a main or release/X.Y build")
    if sha not in git("rev-list", "--first-parent", "refs/remotes/origin/" + branch).splitlines():
        raise ValueError("The build is outside the selected branch history")
    if branch != "main":
        prefix = branch.removeprefix("release/") + "."
        if not any(tag.startswith(prefix) and "-rc." in tag for tag in
                   git("tag", "--merged", sha).splitlines()):
            raise ValueError("A stabilization branch must descend from its tagged RC")
    with tempfile.TemporaryDirectory() as directory:
        gh("run", "download", run_id, "--repo", repo, "--name",
           f"image-receipt-{attempt}", "--dir", directory)
        receipt = json.loads((Path(directory) / "image.json").read_text())
    if receipt["commit"] != sha or not DIGEST.fullmatch(receipt["digest"]):
        raise ValueError("Invalid CI image receipt")
    return sha, receipt["digest"]


def from_release(repo, name):
    release = api(f"repos/{repo}/releases/tags/{name}")
    if release is None:
        return None
    block = re.match(r"```json\n([^\n]+)\n```", release["body"].replace("\r\n", "\n"))
    if not block or release["draft"] or release["prerelease"] != ("-rc." in name):
        raise ValueError("Existing release has an unexpected format or state")
    receipt = json.loads(block[1])
    if (receipt["version"] != name or receipt["commit"] != git("rev-parse", name + "^{commit}")
            or not DIGEST.fullmatch(receipt["digest"]) or receipt["image"] != f"ghcr.io/{repo}@{receipt['digest']}"):
        raise ValueError("Release record, Git tag and image reference must agree")
    return receipt

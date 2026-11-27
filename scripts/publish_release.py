"""Manually publish the exact image selected by a CI run or a tested RC."""

import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request

from release_version import SHA, VERSION, git, plan, tags


DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
MAINTENANCE = re.compile(r"release/(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
MEDIA = ", ".join([
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
])


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


class Registry:
    def __init__(self, repo, publish):
        scope = "pull,push" if publish else "pull"
        query = urllib.parse.urlencode({"service": "ghcr.io", "scope": f"repository:{repo}:{scope}"})
        credentials = os.environ["GITHUB_ACTOR"] + ":" + os.environ["GH_TOKEN"]
        basic = base64.b64encode(credentials.encode()).decode()
        req = urllib.request.Request("https://ghcr.io/token?" + query,
                                     headers={"Authorization": "Basic " + basic})
        with urllib.request.urlopen(req, timeout=30) as response:
            self.token = json.load(response)["token"]
        self.url = f"https://ghcr.io/v2/{repo}/manifests/"

    def read(self, reference):
        req = urllib.request.Request(self.url + reference, headers={
            "Authorization": "Bearer " + self.token, "Accept": MEDIA})
        try:
            with urllib.request.urlopen(req, timeout=30) as response:
                return response.read(), response.headers.get_content_type()
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return None
            raise

    def alias(self, digest, version, publish):
        source = self.read(digest)
        if not source or "sha256:" + hashlib.sha256(source[0]).hexdigest() != digest:
            raise ValueError("The pinned CI manifest is unavailable or has changed")
        existing = self.read(version)
        if existing:
            if existing[0] != source[0]:
                raise ValueError("Versioned image tag already identifies a different manifest")
            return
        if publish:
            req = urllib.request.Request(self.url + version, data=source[0], method="PUT", headers={
                "Authorization": "Bearer " + self.token, "Content-Type": source[1]})
            with urllib.request.urlopen(req, timeout=30) as response:
                if response.status != 201:
                    raise ValueError("Registry did not confirm manifest publication")
            if self.read(version) != source:
                raise ValueError("Published manifest failed read-back verification")


def main():
    repo = os.environ["GITHUB_REPOSITORY"].lower()
    mode, source = os.environ["RELEASE_MODE"], os.environ["RELEASE_SOURCE"]
    confirm = os.environ.get("CONFIRM_VERSION", "").strip()
    declare_api = os.environ.get("DECLARE_API") == "true"
    rolling = sorted(set(os.environ.get("ROLLING_FROM", "").split()))
    known = tags()
    if confirm and not VERSION.fullmatch(confirm):
        raise ValueError("Confirmation must be the exact proposed version")
    if any(v not in known or len(known[v]) != 3 for v in rolling):
        raise ValueError("Rolling compatibility must name existing stable version tags")
    if mode == "promote":
        if source not in known or len(known[source]) != 4 or rolling or declare_api:
            raise ValueError("Promotion takes an existing RC tag and inherits its metadata")
        rc = from_release(repo, source)
        if not rc:
            raise ValueError("Missing published RC")
        sha, digest, rolling = rc["commit"], rc["digest"], rc["rollingFrom"]
    elif mode in {"rc", "stable"}:
        sha, digest = from_run(repo, source)
    else:
        raise ValueError("Unknown release operation")

    schema_source = git("show", f"{sha}:internal/identity/database_upgrade.go")
    schema_match = re.search(r"^const SchemaVersion = ([0-9]+)$", schema_source, re.M)
    if not schema_match:
        raise ValueError("Cannot establish the database schema of the selected build")
    schema = int(schema_match[1])
    if mode != "promote":
        for name in rolling:
            prior = from_release(repo, name)
            if not prior or prior["schemaVersion"] != schema:
                raise ValueError("A rolling source must have the same database schema")
    metadata = {"commit": sha, "digest": digest, "image": f"ghcr.io/{repo}@{digest}",
                "schemaVersion": schema, "rollingFrom": rolling, "operation": mode, "source": source}
    # A retry after publication must validate the original selection before returning.
    if confirm and confirm in known:
        existing = from_release(repo, confirm)
        if existing is not None:
            if existing != dict(metadata, version=confirm):
                raise ValueError("Confirmed version already exists with different release metadata")
            Registry(repo, True).alias(digest, confirm, True)
            print("Verified existing release", confirm)
            return
        # Recover the tag-only interval of a failed GitHub Release creation.
        if git("rev-parse", confirm + "^{commit}") != sha:
            raise ValueError("Existing Git tag points to a different commit")
        del known[confirm]
    version, base, titles = plan(mode, sha, source if mode == "promote" else None,
                                 declare_api, versions=known)
    if confirm and confirm != version:
        raise ValueError(f"Release plan changed. Review and confirm {version}")
    receipt = dict(metadata, version=version)
    print(f"{version} from {sha} at {digest}; schema {schema}; rolling from {rolling}")
    registry = Registry(repo, bool(confirm))
    registry.alias(digest, version, bool(confirm))
    if not confirm:
        return
    body = "```json\n" + json.dumps(receipt, sort_keys=True) + "\n```\n\n"
    earlier = {k: v for k, v in known.items() if len(v) == 4 and
               (not base or v[:3] > known[base])}
    if earlier:
        body += f"Supersedes candidate {max(earlier, key=earlier.get)}.\n\n"
    if base:
        body += f"Changes since {base}\n\n"
    body += "\n".join("- " + title for title in titles)
    api(f"repos/{repo}/releases", {"tag_name": version, "target_commitish": sha,
        "name": version, "prerelease": mode == "rc", "body": body,
        "make_latest": "false" if mode == "rc" else "true"})
    print("Published", version)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        sys.exit(str(error))

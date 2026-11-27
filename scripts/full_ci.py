"""Select an image for full CI and verify GitHub's results before publishing it."""

import os
import re
import time

from ci_image import api, from_release, from_run, gh
from release_version import VERSION


def exact_run(repo, run_ref, sha, digest):
    """Check the trusted attempt and its final dependent job, not just a status URL."""
    if not run_ref or not re.fullmatch(r"[1-9][0-9]*/[1-9][0-9]*", run_ref):
        return False
    run_id, attempt = run_ref.split("/")
    endpoint = f"repos/{repo}/actions/runs/{run_id}/attempts/{attempt}"
    run = api(endpoint)
    if not run or not (run["path"] == ".github/workflows/full.yml" and
                       run["event"] in {"schedule", "workflow_dispatch"} and
                       run["head_repository"]["full_name"].lower() == repo and
                       run["head_branch"] == "main" and run["conclusion"] == "success"):
        return False
    jobs = api(endpoint + "/jobs?per_page=100")["jobs"]
    return any(j["name"] == f"Full validation {sha} {digest}" and
               j["conclusion"] == "success" for j in jobs)


def validated_run(repo, source, sha, digest, previous=None, *, publish):
    if exact_run(repo, previous, sha, digest):
        print("Reusing full validation", previous)
        return previous
    prefix = f"https://github.com/{repo}/actions/runs/"
    urls = gh("api", "--paginate", f"repos/{repo}/commits/{sha}/statuses?per_page=100",
              "--jq", f'.[] | select(.context=="full-ci/{digest}" and .state=="success") | .target_url')
    for url in urls.splitlines():
        match = re.fullmatch(re.escape(prefix) + r"(\d+)/attempts/(\d+)", url)
        if match:
            run_ref = "/".join(match.groups())
            if exact_run(repo, run_ref, sha, digest):
                print("Reusing full validation", run_ref)
                return run_ref
    if not publish:
        print("Full validation pending. Confirming publication will run it.")
        return None

    run_id = gh("api", "--method", "POST", f"repos/{repo}/actions/workflows/full.yml/dispatches",
                "-H", "X-GitHub-Api-Version: 2022-11-28", "-f", "ref=main",
                "-f", "inputs[source]=" + source, "-F", "return_run_details=true",
                "--jq", ".workflow_run_id").strip()
    if not re.fullmatch(r"[1-9][0-9]*", run_id):
        raise ValueError("Full CI dispatch returned no identifiable run; inspect Actions before retrying")
    print("Waiting for full validation", prefix + run_id, flush=True)
    deadline = time.monotonic() + 45 * 60
    while time.monotonic() < deadline:
        run = api(f"repos/{repo}/actions/runs/{run_id}")
        if run and run["status"] == "completed":
            run_ref = f"{run_id}/{run['run_attempt']}"
            if not exact_run(repo, run_ref, sha, digest):
                raise ValueError("Full CI did not validate the selected commit and digest: " + prefix + run_id)
            return run_ref
        time.sleep(15)
    raise ValueError("Full CI still pending; retry publication after " + prefix + run_id)


def nightly_source(repo, sha):
    endpoint = f"repos/{repo}/actions/workflows/ci.yml/runs?branch=main&event=push&head_sha={sha}"
    for _ in range(30):
        runs = api(endpoint)["workflow_runs"]
        for run in runs:
            if run["conclusion"] == "success":
                return f"{run['id']}/{run['run_attempt']}"
        if runs and all(r["status"] == "completed" for r in runs):
            break
        time.sleep(10)
    raise ValueError("No successful SHA image build for the scheduled main commit " + sha)


if __name__ == "__main__":
    repo = os.environ["GITHUB_REPOSITORY"].lower()
    source = os.environ.get("CI_SOURCE") or nightly_source(repo, os.environ["GITHUB_SHA"])
    if VERSION.fullmatch(source) and "-rc." in source:
        receipt = from_release(repo, source)
        if not receipt:
            raise ValueError("Missing RC release record")
        sha, digest = receipt["commit"], receipt["digest"]
    else:
        sha, digest = from_run(repo, source)
    print("sha=" + sha)
    print("digest=" + digest)

"""Plan MemberID releases from squash commit titles and immutable Git tags."""

import re
import subprocess


TITLE = re.compile(
    r"(?P<type>feat|fix|perf|build|chore|ci|docs|refactor|style|test|revert)"
    r"(?:\([a-zA-Z0-9][a-zA-Z0-9._/-]*\))?(?P<breaking>!)?: [^\s\r\n][^\r\n]*"
)
NUMBER = r"(?:0|[1-9][0-9]*)"
VERSION = re.compile(rf"({NUMBER})\.({NUMBER})\.({NUMBER})(?:-rc\.([1-9][0-9]*))?")
SHA = re.compile(r"[0-9a-f]{40}")


def git(*args):
    return subprocess.check_output(["git", *args], text=True, encoding="utf-8").strip()


def impact(title):
    match = TITLE.fullmatch(title)
    if not match:
        raise ValueError(f"Invalid Conventional Commit title: {title!r}")
    if match["breaking"]:
        return 3
    if match["type"] == "feat":
        return 2
    return int(match["type"] in {"fix", "perf", "revert"})


def tags():
    versions = {}
    for name in git("tag", "--list").splitlines():
        match = VERSION.fullmatch(name)
        if match:
            versions[name] = tuple(int(n) for n in match.groups() if n is not None)
    return versions


def changes(base, sha):
    # A patch backported to release/X.Y and main can have different commit IDs.
    if not base:
        return git("log", "--first-parent", "--format=%s", sha).splitlines()
    lines = git("log", "--left-right", "--cherry-pick", "--first-parent",
                "--format=%m%s", f"{base}...{sha}").splitlines()
    if any(line.startswith("<") for line in lines):
        raise ValueError("The selected build is missing changes from the last stable release")
    return [line[1:] for line in lines if line.startswith(">")]


def plan(mode, sha, source_rc=None, declare_api=False, *, versions=None):
    if versions is None:
        versions = tags()
    stable = {k: v for k, v in versions.items() if len(v) == 3}
    base = max(stable, key=stable.get, default=None)
    previous = stable.get(base, (0, 0, 0))
    candidates = {k: v for k, v in versions.items() if len(v) == 4 and v[:3] > previous}
    latest_rc = max(candidates, key=candidates.get, default=None)
    titles = changes(base, sha)
    if mode == "promote":
        if not source_rc or source_rc != latest_rc:
            raise ValueError("Select the current RC; an older or superseded RC cannot be promoted")
        return source_rc.split("-")[0], base, titles
    if not titles:
        raise ValueError("This build has no changes since the last stable release")
    level = max(map(impact, titles))
    major, minor, patch = previous
    if declare_api:
        if major:
            raise ValueError("The first stable public API was already declared")
        target = (1, 0, 0)
    elif not base:
        target = (0, 1, 0)
    elif level == 3 and major:
        target = (major + 1, 0, 0)
    elif level >= 2:
        target = (major, minor + 1, 0)
    elif level == 1:
        target = (major, minor, patch + 1)
    else:
        raise ValueError("No release-bearing changes since the last stable release")
    version = ".".join(map(str, target))
    if latest_rc and target < candidates[latest_rc][:3]:
        raise ValueError("The selected target precedes the open RC series")
    if mode == "stable":
        if latest_rc and target == candidates[latest_rc][:3]:
            raise ValueError("Promote the current RC or cut a new RC for this target")
        return version, base, titles
    if latest_rc:
        # Accept either a descendant or an equivalent cherry-picked stabilization fix.
        changes(latest_rc, sha)
    sequence = 1
    if latest_rc and candidates[latest_rc][:3] == target:
        if git("rev-parse", latest_rc + "^{commit}") == sha:
            raise ValueError("This build is already the current RC")
        sequence = candidates[latest_rc][3] + 1
    return f"{version}-rc.{sequence}", base, titles

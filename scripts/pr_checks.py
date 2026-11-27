"""Select PR checks from both sides of a rename and the complete PR diff."""

import fnmatch
import os
import subprocess
import sys


def select(paths):
    docs = all(path in {"README.md", "AGENTS.md", "CONTRIBUTING.md"} or
               (path.startswith("docs/") and path.endswith(".md")) for path in paths)
    automation = any(path.startswith((".github/workflows/", "scripts/")) for path in paths)
    patterns = []
    if any(any(fnmatch.fnmatchcase(path, pattern) for pattern in (
            "internal/identity/*database*", "internal/identity/migrations/*", "internal/identity/*.sql",
            "internal/identity/testdata/*.sql", "internal/recovery/*", "cmd/memberid/database*",
            "docs/recovery-sessions.sql", "scripts/test-integration.sh")) for path in paths):
        patterns += ["TestDatabaseUpgrade", "TestSchema[0-9]+Upgrade", "TestInitializationRefuses"]
    if any(path.startswith(("internal/identity/", "internal/oidcprovider/", "internal/management/",
                            "internal/console/")) and path.endswith(".go") for path in paths):
        patterns += ["TestOrganizationIsolationAndExplicitBindings$", "TestManagementOrganizationIsolationAndEligibility$",
                     "TestRefreshRotationAndScopeNarrowing$", "TestConcurrentRefreshRevokesFamily$"]
    return {"code": str(not docs).lower(), "automation": str(automation).lower(),
            "integration": "^(" + "|".join(patterns) + ")" if patterns else ""}


if __name__ == "__main__":
    base, head = sys.argv[1:]
    names = subprocess.check_output(["git", "diff", "--no-renames", "--name-only", "-z", base + "..." + head])
    for key, value in select([os.fsdecode(p) for p in names.split(b"\0") if p]).items():
        print(f"{key}={value}")

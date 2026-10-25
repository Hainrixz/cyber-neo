#!/usr/bin/env python3
# Portions Copyright (c) 2026 Enrique Rocha (@soyenriquerocha) - see LICENSE for original authors
# SPDX-License-Identifier: MIT
# id: er-d5e6e8b1
"""
Cyber Neo — Lock File Integrity Checker
Verifies lock file presence, consistency, and security for package managers.
Outputs JSON findings for integration with the main agent.

Usage:
    python3 check_lockfiles.py <target_dir>
"""

import json
import os
import sys
from pathlib import Path

# ─── Package Manager Definitions ────────────────────────────────────────────

def _detect_js_package_manager(target_dir: Path) -> dict:
    """Detect which JS package manager is in use by checking for lock files and config."""
    if (target_dir / "pnpm-lock.yaml").exists() or (target_dir / "pnpm-workspace.yaml").exists():
        return {
            "name": "pnpm",
            "manifest": "package.json",
            "lockfiles": ["pnpm-lock.yaml"],
            "alt_lockfiles": [],
            "ci_command": "pnpm install --frozen-lockfile",
            "install_command": "pnpm install",
        }
    if (target_dir / "yarn.lock").exists() or (target_dir / ".yarnrc.yml").exists():
        return {
            "name": "yarn",
            "manifest": "package.json",
            "lockfiles": ["yarn.lock"],
            "alt_lockfiles": [],
            "ci_command": "yarn install --frozen-lockfile",
            "install_command": "yarn install",
        }
    if (target_dir / "bun.lockb").exists():
        return {
            "name": "bun",
            "manifest": "package.json",
            "lockfiles": ["bun.lockb"],
            "alt_lockfiles": [],
            "ci_command": "bun install --frozen-lockfile",
            "install_command": "bun install",
        }
    # Default to npm
    return {
        "name": "npm",
        "manifest": "package.json",
        "lockfiles": ["package-lock.json", "npm-shrinkwrap.json"],
        "alt_lockfiles": ["yarn.lock", "pnpm-lock.yaml", "bun.lockb"],
        "ci_command": "npm ci",
        "install_command": "npm install",
    }


PACKAGE_MANAGERS = [
    # NOTE: JS package managers (npm/yarn/pnpm/bun) are detected dynamically
    # by _detect_js_package_manager() and added in scan(). Only non-JS managers here.
    {
        "name": "pip",
        "manifest": "requirements.txt",
        "lockfiles": [],  # pip doesn't have a standard lock file
        "alt_lockfiles": [],
        "ci_command": "pip install -r requirements.txt",
        "install_command": "pip install -r requirements.txt",
    },
    {
        "name": "pipenv",
        "manifest": "Pipfile",
        "lockfiles": ["Pipfile.lock"],
        "alt_lockfiles": [],
        "ci_command": "pipenv install --deploy",
        "install_command": "pipenv install",
    },
    {
        "name": "poetry",
        "manifest": "pyproject.toml",
        "lockfiles": ["poetry.lock"],
        "alt_lockfiles": [],
        "ci_command": "poetry install --no-interaction",
        "install_command": "poetry install",
    },
    {
        "name": "cargo",
        "manifest": "Cargo.toml",
        "lockfiles": ["Cargo.lock"],
        "alt_lockfiles": [],
        "ci_command": "cargo build --locked",
        "install_command": "cargo build",
    },
    {
        "name": "bundler",
        "manifest": "Gemfile",
        "lockfiles": ["Gemfile.lock"],
        "alt_lockfiles": [],
        "ci_command": "bundle install --frozen",
        "install_command": "bundle install",
    },
    {
        "name": "composer",
        "manifest": "composer.json",
        "lockfiles": ["composer.lock"],
        "alt_lockfiles": [],
        "ci_command": "composer install --no-dev",
        "install_command": "composer install",
    },
    {
        "name": "go",
        "manifest": "go.mod",
        "lockfiles": ["go.sum"],
        "alt_lockfiles": [],
        "ci_command": "go build ./...",
        "install_command": "go mod download",
    },
]

# Common patterns indicating floating/unpinned versions
FLOATING_VERSION_PATTERNS = {
    "npm": {
        "caret": r'"[^"]+"\s*:\s*"\^',
        "tilde": r'"[^"]+"\s*:\s*"~',
        "star": r'"[^"]+"\s*:\s*"\*"',
        "latest": r'"[^"]+"\s*:\s*"latest"',
        "range": r'"[^"]+"\s*:\s*">=',
    },
}


def check_gitignore_for_lockfiles(target_dir: Path, lockfile_names: list) -> list:
    """Check if any lock files are incorrectly gitignored."""
    findings = []
    gitignore = target_dir / ".gitignore"

    if not gitignore.exists():
        return findings

    try:
        content = gitignore.read_text(encoding="utf-8")
        lines = [line.strip() for line in content.splitlines()
                 if line.strip() and not line.strip().startswith("#")]

        for lockfile in lockfile_names:
            for line in lines:
                # Check if the gitignore pattern would match the lock file
                if lockfile in line or line == lockfile:
                    findings.append({
                        "type": "Lock file gitignored",
                        "severity": "high",
                        "file": str(gitignore),
                        "line": 0,
                        "description": (
                            f"{lockfile} is in .gitignore — lock files should be committed "
                            f"to ensure reproducible builds and prevent supply chain attacks"
                        ),
                        "evidence": f".gitignore contains: {line}",
                        "cwe": "CWE-829",
                        "owasp": "A03:2025",
                    })
    except OSError:
        pass

    return findings


def check_npm_package_json(target_dir: Path) -> list:
    """Check package.json for security-relevant issues."""
    findings = []
    pkg_path = target_dir / "package.json"

    if not pkg_path.exists():
        return findings

    try:
        content = pkg_path.read_text(encoding="utf-8")
        pkg = json.loads(content)

        # Check for floating versions in dependencies
        for dep_type in ["dependencies", "devDependencies"]:
            deps = pkg.get(dep_type, {})
            floating = []
            for name, version in deps.items():
                if isinstance(version, str):
                    if version == "*" or version == "latest":
                        floating.append(f"{name}: {version}")
                    elif version.startswith(">=") and "<" not in version:
                        floating.append(f"{name}: {version}")

            if floating:
                findings.append({
                    "type": "Unpinned dependencies",
                    "severity": "medium",
                    "file": str(pkg_path),
                    "line": 0,
                    "description": (
                        f"Found {len(floating)} unpinned dependency version(s) in {dep_type}. "
                        f"Unpinned versions can introduce unexpected changes or malicious packages."
                    ),
                    "evidence": ", ".join(floating[:5]) + ("..." if len(floating) > 5 else ""),
                    "cwe": "CWE-829",
                    "owasp": "A03:2025",
                })

        # Check for lifecycle scripts that run arbitrary code
        scripts = pkg.get("scripts", {})
        risky_hooks = ["preinstall", "postinstall", "preuninstall", "postuninstall"]
        for hook in risky_hooks:
            if hook in scripts:
                findings.append({
                    "type": "Lifecycle script detected",
                    "severity": "info",
                    "file": str(pkg_path),
                    "line": 0,
                    "description": (
                        f"'{hook}' script found — lifecycle scripts execute automatically "
                        f"and are a common supply chain attack vector"
                    ),
                    "evidence": f"{hook}: {scripts[hook][:100]}",
                    "cwe": "CWE-829",
                    "owasp": "A03:2025",
                })

    except (json.JSONDecodeError, OSError):
        pass

    return findings


def check_pip_requirements(target_dir: Path) -> list:
    """Check requirements.txt for unpinned versions."""
    findings = []

    for req_file in ["requirements.txt", "requirements-dev.txt",
                     "requirements/base.txt", "requirements/production.txt"]:
        req_path = target_dir / req_file
        if not req_path.exists():
            continue

        try:
            content = req_path.read_text(encoding="utf-8")
            unpinned = []
            for line_num, line in enumerate(content.splitlines(), 1):
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                # Check for unpinned: no == in the line
                if "==" not in line and ">=" in line:
                    pkg_name = line.split(">=")[0].strip()
                    unpinned.append(f"{pkg_name} (line {line_num})")

            if unpinned:
                findings.append({
                    "type": "Unpinned Python dependencies",
                    "severity": "medium",
                    "file": str(req_path),
                    "line": 0,
                    "description": (
                        f"Found {len(unpinned)} dependency/ies with >= but no upper bound. "
                        f"Pin exact versions with == for reproducible builds."
                    ),
                    "evidence": ", ".join(unpinned[:5]) + ("..." if len(unpinned) > 5 else ""),
                    "cwe": "CWE-829",
                    "owasp": "A03:2025",
                })
        except OSError:
            pass

    return findings


def scan(target_dir: Path) -> dict:
    """Run all lock file checks on the target directory."""
    findings = []
    detected_managers = []

    # Build the actual package manager list, dynamically detecting JS manager
    managers_to_check = list(PACKAGE_MANAGERS)
    if (target_dir / "package.json").exists():
        js_pm = _detect_js_package_manager(target_dir)
        managers_to_check.insert(0, js_pm)

    for pm in managers_to_check:
        manifest_path = target_dir / pm["manifest"]
        if not manifest_path.exists():
            continue

        detected_managers.append(pm["name"])

        # Check for lock file existence
        has_lockfile = False
        has_alt_lockfile = False
        found_lockfile = None

        for lockfile in pm["lockfiles"]:
            if (target_dir / lockfile).exists():
                has_lockfile = True
                found_lockfile = lockfile
                break

        if not has_lockfile:
            for alt in pm.get("alt_lockfiles", []):
                if (target_dir / alt).exists():
                    has_alt_lockfile = True
                    found_lockfile = alt
                    break

        if pm["lockfiles"] and not has_lockfile and not has_alt_lockfile:
            findings.append({
                "type": "Missing lock file",
                "severity": "high",
                "file": str(manifest_path),
                "line": 0,
                "description": (
                    f"No lock file found for {pm['name']} (expected: {', '.join(pm['lockfiles'])}). "
                    f"Without a lock file, builds are non-reproducible and vulnerable to "
                    f"dependency confusion and supply chain attacks. "
                    f"Run '{pm['install_command']}' to generate one and commit it."
                ),
                "evidence": f"Found {pm['manifest']} but no {', '.join(pm['lockfiles'])}",
                "cwe": "CWE-829",
                "owasp": "A03:2025",
            })
        elif found_lockfile:
            # Check if lock file is gitignored
            all_lockfiles = pm["lockfiles"] + pm.get("alt_lockfiles", [])
            findings.extend(check_gitignore_for_lockfiles(target_dir, all_lockfiles))

    # Package-manager-specific checks
    js_managers = {"npm", "yarn", "pnpm", "bun"}
    if js_managers & set(detected_managers):
        findings.extend(check_npm_package_json(target_dir))

    if "pip" in detected_managers or "poetry" in detected_managers:
        findings.extend(check_pip_requirements(target_dir))

    return {
        "findings": findings,
        "metadata": {
            "detected_package_managers": detected_managers,
            "total_findings": len(findings),
        },
    }


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: check_lockfiles.py <target_dir>"}))
        sys.exit(1)

    target = Path(sys.argv[1]).resolve()
    if not target.is_dir():
        print(json.dumps({"error": f"Not a directory: {target}"}))
        sys.exit(1)

    result = scan(target)
    print(json.dumps(result, indent=2))

    if result["findings"]:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()

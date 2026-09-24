"""Run ecosystem audit commands and the GitHub advisory API."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import httpx


def project_root(path: str) -> Path:
    root = Path(path or os.environ.get("DEPS_ROOT") or ".").resolve()
    if not root.is_dir():
        raise FileNotFoundError(f"Project path does not exist: {root}")
    return root


def detect(path: str) -> str:
    root = project_root(path)
    kinds = []
    if (root / "package.json").is_file():
        kinds.append("npm")
    if (root / "pom.xml").is_file() or list(root.glob("*/pom.xml")):
        kinds.append("maven")
    if (root / "pyproject.toml").is_file() or (root / "requirements.txt").is_file():
        kinds.append("python")
    return json.dumps({"path": str(root), "ecosystems": kinds}, indent=2)


def _run(cmd: list[str], cwd: Path, timeout: int = 180) -> str:
    completed = subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    text = (completed.stdout or "") + ("\n" + completed.stderr if completed.stderr else "")
    return text[-12000:] or f"exit {completed.returncode}"


def npm_audit(path: str) -> str:
    root = project_root(path)
    if not (root / "package.json").is_file():
        return "No package.json in this directory."
    raw = _run(["npm", "audit", "--json"], root)
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return raw
    vulns = data.get("vulnerabilities") or {}
    summary = [
        {
            "name": name,
            "severity": item.get("severity"),
            "via": item.get("via") if isinstance(item.get("via"), str) else None,
            "fixAvailable": bool(item.get("fixAvailable")),
        }
        for name, item in list(vulns.items())[:40]
    ]
    meta = data.get("metadata", {}).get("vulnerabilities", {})
    return json.dumps({"summary": meta, "packages": summary}, indent=2)


def maven_tree(path: str) -> str:
    root = project_root(path)
    pom = root / "pom.xml"
    if not pom.is_file():
        nested = next(root.glob("*/pom.xml"), None)
        if nested:
            root = nested.parent
        else:
            return "No pom.xml in this directory."
    return _run(["mvn", "-q", "dependency:tree", "-DoutputType=text"], root, timeout=300)


def python_packages(path: str) -> str:
    root = project_root(path)
    req = root / "requirements.txt"
    pyproject = root / "pyproject.toml"
    if req.is_file():
        lines = [line.strip() for line in req.read_text(encoding="utf-8").splitlines() if line.strip() and not line.startswith("#")]
        return json.dumps({"source": "requirements.txt", "packages": lines[:200]}, indent=2)
    if pyproject.is_file():
        text = pyproject.read_text(encoding="utf-8")
        return json.dumps({"source": "pyproject.toml", "excerpt": text[:4000]}, indent=2)
    return "No requirements.txt or pyproject.toml in this directory."


def github_advisories(ecosystem: str, package: str, token: str = "") -> str:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "deps-mcp"}
    token = token or os.environ.get("GITHUB_TOKEN", "")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    params = {"ecosystem": ecosystem, "affects": package, "per_page": 10}
    with httpx.Client(timeout=30) as client:
        response = client.get("https://api.github.com/advisories", params=params, headers=headers)
    if response.status_code >= 400:
        return f"GitHub advisory API {response.status_code}: {response.text[:500]}"
    slim = [
        {
            "ghsa": item.get("ghsa_id"),
            "cve": item.get("cve_id"),
            "severity": item.get("severity"),
            "summary": item.get("summary"),
        }
        for item in response.json()[:10]
    ]
    return json.dumps(slim, indent=2)

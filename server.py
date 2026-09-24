"""
Deps MCP Server.

Author: Pawan Gunjkar (pawangunjkar@gmail.com)

Scan npm, Maven, and Python projects for vulnerable or declared dependencies.
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from deps_client import detect, github_advisories, maven_tree, npm_audit, python_packages

mcp = FastMCP(
    "deps",
    instructions=(
        "Dependency MCP. Point path at a project root, or set DEPS_ROOT. "
        "Use deps_detect, deps_npm_audit, deps_maven_tree, deps_python_packages, "
        "and deps_github_advisory. Set GITHUB_TOKEN for higher advisory rate limits. "
        "This server reads lockfiles and audit output. It does not upgrade packages."
    ),
)


@mcp.tool()
def deps_detect(path: str = "") -> str:
    """Detect npm, Maven, and Python manifests in a project directory."""
    try:
        return detect(path)
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool()
def deps_npm_audit(path: str = "") -> str:
    """Run npm audit --json and return severity counts plus the first 40 packages."""
    try:
        return npm_audit(path)
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool()
def deps_maven_tree(path: str = "") -> str:
    """Run mvn dependency:tree for a pom.xml in this directory or one level down."""
    try:
        return maven_tree(path)
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool()
def deps_python_packages(path: str = "") -> str:
    """List declared Python packages from requirements.txt or show pyproject.toml."""
    try:
        return python_packages(path)
    except Exception as exc:
        return f"Error: {exc}"


@mcp.tool()
def deps_github_advisory(ecosystem: str, package: str) -> str:
    """Look up GitHub security advisories. ecosystem is npm, maven, pip, or nuget."""
    try:
        return github_advisories(ecosystem, package)
    except Exception as exc:
        return f"Error: {exc}"


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()

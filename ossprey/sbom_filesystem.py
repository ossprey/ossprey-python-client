from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, Iterable, Tuple
from urllib.parse import urlparse

from ossbom.model.component import Component
from ossbom.model.dependency_env import DependencyEnv
from ossbom.model.ossbom import OSSBOM
from ossprey.sbom_javascript import (
    get_all_node_modules_packages,
    node_modules_directory_exists,
    get_all_package_lock_packages,
    get_all_yarn_lock_packages
)

# TODO All this code needs a refactor with the sbom_python and sbom_javascript code

Key = Tuple[str, str, str, str]  # (ptype, name, version, source)

_ignore_dirs = ["/proc", "/sys", "/dev", "/var/log", "/var/cache"]


def _iter_folders(root: Path, wildcard: str = "*", dir_only: bool = False) -> Iterable[Path]:
    for p in root.rglob(wildcard):
        if any(str(p).startswith(ignored) for ignored in _ignore_dirs):
            continue
        if p.is_dir() or not dir_only:
            yield p


def _iter_python_pkgs(root: Path) -> Iterable[tuple[str, str, Path]]:
    for p in _iter_folders(root, dir_only=True):
        if p.name.endswith(".dist-info") or p.name.endswith(".egg-info"):
            name, ver = None, None
            for meta in ("METADATA", "PKG-INFO"):
                f = p / meta
                if f.exists():
                    for line in f.read_text("utf-8", errors="ignore").splitlines():
                        if name is None and line.startswith("Name:"):
                            name = line.split(":", 1)[1].strip()
                        elif ver is None and line.startswith("Version:"):
                            ver = line.split(":", 1)[1].strip()
                        if name and ver:
                            break
            if name:
                yield name, ver or "", p


def _iter_node_modules(root: Path) -> Iterable[tuple[str, str, Path]]:
    for nm in _iter_folders(root, "node_modules", dir_only=True):
        path = nm.resolve()
        if node_modules_directory_exists(path):
            for c in get_all_node_modules_packages(path):
                yield c["name"], c.get("version", ""), path


def _iter_package_lock_files(root: Path) -> Iterable[tuple[str, str, Path]]:
    for f in _iter_folders(root, "package-lock.json"):
        print(f)
        packages = get_all_package_lock_packages(f.parent)
        for pkg in packages:
            yield pkg["name"], pkg["version"], f


def _iter_yarn_lock_files(root: Path) -> Iterable[tuple[str, str, Path]]:
    for f in _iter_folders(root, "yarn.lock"):
        packages = get_all_yarn_lock_packages(f.parent)
        for pkg in packages:
            yield pkg["name"], pkg["version"], f


def add(buckets: Dict[Key, set[str]], ptype: str, name: str, version: str, loc: Path | str, source: str) -> None:
    key: Key = (ptype, name, version, source)
    buckets.setdefault(key, set()).add(str(loc))


def _get_direct_url(dist_info_dir: Path) -> dict | None:
    """Load direct_url.json from a .dist-info/.egg-info directory if present."""
    try:
        f = dist_info_dir / "direct_url.json"
        if f.exists():
            return json.loads(f.read_text("utf-8", errors="ignore"))
    except Exception:
        # Best-effort read; ignore corrupt files
        return None
    return None


def _github_repo_from_direct_url(direct_url: dict | None) -> str | None:
    """Return 'org/repo' if the direct_url points to GitHub; otherwise None."""
    if not direct_url:
        return None
    url = direct_url.get("url") or ""
    if not url:
        return None
    # Strip common VCS prefix
    if url.startswith("git+"):
        url = url[4:]
    parsed = urlparse(url)
    host = (parsed.netloc or "").lower()
    if not host.endswith("github.com"):
        return None
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) < 2:
        return None
    org, repo = parts[0], parts[1]
    if repo.endswith(".git"):
        repo = repo[:-4]
    return f"{org}/{repo}"


def _github_version_from_direct_url(direct_url: dict | None) -> tuple[str, str | None]:
    """Determine a (version, branch) from PEP 610 'vcs_info'."""
    vcs = (direct_url or {}).get("vcs_info") or {}
    requested = vcs.get("requested_revision")
    commit = vcs.get("commit_id")
    if requested and (not commit or requested != commit):
        # Prefer branch/tag name as qualifier, keep version stable as 'latest'
        return "latest", requested
    if commit:
        return commit[:12], None
    return "latest", None


def _python_pkg_to_component_tuple(
    pypi_name: str, pypi_version: str, loc: Path, direct_url: dict | None
) -> tuple[str, str, str, str]:
    """
    Decide component identity for a Python package. Returns (ptype, name, version, source).
    If installed from GitHub (via direct_url.json), create a 'github' component using 'org/repo'.
    Else default to a 'pypi' component.
    """
    gh_repo = _github_repo_from_direct_url(direct_url)
    if gh_repo:
        ver, branch = _github_version_from_direct_url(direct_url)
        qs: list[str] = []
        if branch:
            qs.append(f"branch={branch}")
        qs.append(f"pypi_name={pypi_name}")
        qs.append(f"pypi_version={pypi_version}")
        return ("github", gh_repo, ver, "pkg_packages")

    return ("pypi", pypi_name, pypi_version, "pkg_packages")


def update_sbom_from_filesystem(ossbom: OSSBOM, project_folder: str = "/") -> OSSBOM:
    root = Path(project_folder).resolve()

    # Aggregate locations per (type, name, version)
    buckets: Dict[Key, set[str]] = {}

    # Python
    for name, version, loc in _iter_python_pkgs(root):
        direct_url = _get_direct_url(loc)
        ptype, cname, cver, source = _python_pkg_to_component_tuple(name, version, loc, direct_url)
        add(buckets, ptype, cname, cver, loc, source)

    # NPM
    for name, version, loc in _iter_node_modules(root):
        add(buckets, "npm", name, version, loc, "node_modules")

    for name, version, loc in _iter_package_lock_files(root):
        add(buckets, "npm", name, version, loc, "package-lock.json")

    for name, version, loc in _iter_yarn_lock_files(root):
        add(buckets, "npm", name, version, loc, "yarn.lock")

    # Emit Components with all locations
    components = [
        Component.create(
            name=name,
            version=version,
            type=ptype,
            env=DependencyEnv.PROD.value,
            source=source,
            location=sorted(locs),  # <-- list[str]
        )
        for (ptype, name, version, source), locs in buckets.items()
    ]
    ossbom.add_components(components)

    return ossbom

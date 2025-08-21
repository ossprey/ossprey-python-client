from __future__ import annotations

import json
import fnmatch
import os
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

from ossbom.model.dependency_env import DependencyEnv
from ossbom.model.component import Component
from ossbom.model.ossbom import OSSBOM
from ossprey.sbom_javascript import (
    get_all_node_modules_packages,
    node_modules_directory_exists,
    get_all_package_lock_packages,
    get_all_yarn_lock_packages,
    resolve_github_duplicates,
)

# TODO All this code needs a refactor with the sbom_python and sbom_javascript code
IGNORE_PREFIXES = ("/proc", "/sys", "/dev", "/var/log", "/var/cache")


def _is_ignored(path: str) -> bool:
    p = os.path.normpath(path)
    for pref in IGNORE_PREFIXES:
        q = os.path.normpath(pref)
        if p == q or p.startswith(q + os.sep):
            return True
    return False


def iter_paths(
    root: Path, wildcard: str = "*", dir_only: bool = False
) -> Iterable[Path]:
    """Yield paths under root matching wildcard, pruning ignored dirs."""
    root = root if root.is_absolute() else root.resolve()
    if _is_ignored(str(root)):
        return

    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        # prune before descending (skips /proc even when root is "/")
        dirnames[:] = [d for d in dirnames if not _is_ignored(os.path.join(dirpath, d))]
        base = Path(dirpath)

        if dir_only:
            for d in dirnames:
                if fnmatch.fnmatch(d, wildcard):
                    yield base / d
            continue

        for d in dirnames:
            if fnmatch.fnmatch(d, wildcard):
                yield base / d
        for f in filenames:
            if fnmatch.fnmatch(f, wildcard):
                yield base / f


def _iter_python_pkgs(root: Path) -> Iterable[Component]:

    python_pkgs = []
    for p in iter_paths(root, dir_only=True):
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
                python_pkgs.append((name, ver, p))

    components = []
    for name, version, loc in python_pkgs:
        direct_url = _get_direct_url(loc)
        ptype, cname, cver, source = _python_pkg_to_component_tuple(
            name, version, loc, direct_url
        )
        component = Component.create(
            type=ptype,
            name=cname,
            env=DependencyEnv.PROD.value,
            version=cver,
            source=source,
            location=[str(loc)],
        )
        components.append(component)
    return components


def _iter_node_modules(root: Path) -> Iterable[Component]:
    for nm in iter_paths(root, wildcard="node_modules", dir_only=True):
        path = nm.resolve().parent
        if node_modules_directory_exists(path):
            for c in get_all_node_modules_packages(path):
                c.add_location(str(path))
                yield c


def _iter_package_lock_files(root: Path) -> Iterable[Component]:
    for f in iter_paths(root, wildcard="package-lock.json"):
        for c in get_all_package_lock_packages(f.parent):
            c.add_location(str(f.parent))
            yield c


def _iter_yarn_lock_files(root: Path) -> Iterable[Component]:
    for f in iter_paths(root, wildcard="yarn.lock"):
        for c in get_all_yarn_lock_packages(f.parent):
            c.add_location(str(f.parent))
            yield c


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
    if commit:
        return commit[:12], requested
    elif requested:
        return "latest", requested
    else:
        return "latest", "main"


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

    components = []
    # Python
    components.extend(_iter_python_pkgs(root))

    # NPM
    components.extend(_iter_node_modules(root))
    components.extend(_iter_package_lock_files(root))
    components.extend(_iter_yarn_lock_files(root))

    # Resolve potential NPM - Github duplications
    components = resolve_github_duplicates(components)

    # Add to SBOM
    ossbom.add_components(components)

    return ossbom

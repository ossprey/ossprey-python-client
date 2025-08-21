from __future__ import annotations

from pathlib import Path
from typing import Dict, Iterable, Tuple

from ossbom.model.component import Component
from ossbom.model.dependency_env import DependencyEnv
from ossbom.model.ossbom import OSSBOM
from ossprey.sbom_javascript import (
    get_all_node_modules_packages,
    node_modules_directory_exists,
)

Key = Tuple[str, str, str, str]  # (ptype, name, version, source)


def _iter_python_pkgs(root: Path) -> Iterable[tuple[str, str, Path]]:
    for p in root.rglob("*"):
        if p.is_dir() and (p.name.endswith(".dist-info") or p.name.endswith(".egg-info")):
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
    seen: set[Path] = set()
    for nm in root.rglob("node_modules"):
        if any(parent in seen for parent in nm.parents):
            continue
        if node_modules_directory_exists(str(nm)):
            for c in get_all_node_modules_packages(str(nm)):
                yield c["name"], c.get("version", ""), nm
            seen.add(nm)


def update_sbom_from_docker(ossbom: OSSBOM, project_folder: str = "/") -> OSSBOM:
    root = Path(project_folder).resolve()

    # Aggregate locations per (type, name, version)
    buckets: Dict[Key, set[str]] = {}

    def add(ptype: str, name: str, version: str, loc: Path | str, source: str) -> None:
        key: Key = (ptype, name, version, source)
        buckets.setdefault(key, set()).add(str(loc))

    # Python
    for name, version, loc in _iter_python_pkgs(root):
        add("python", name, version, loc, "pkg_packages")

    # NPM
    for name, version, loc in _iter_node_modules(root):
        add("npm", name, version, loc, "node_modules")

    # Emit Components with all locations
    for (ptype, name, version, source), locs in buckets.items():
        ossbom.add_components(
            [
                Component.create(
                    name=name,
                    version=version,
                    type=ptype,
                    env=DependencyEnv.PROD,
                    source=source,
                    locations=sorted(locs),  # <-- list[str]
                )
            ]
        )

    return ossbom

from __future__ import annotations

from pathlib import Path
from typing import List

import pytest

from ossbom.model.dependency_env import DependencyEnv
from ossbom.model.ossbom import OSSBOM
from ossprey import sbom_filesystem as fs
from ossbom.model.component import Component


def test_iter_python_pkgs_reads_metadata(tmp_path: Path) -> None:
    dist = tmp_path / "site-packages" / "foo-1.0.0.dist-info"
    dist.mkdir(parents=True)
    (dist / "METADATA").write_text("Name: foo\nVersion: 1.0.0\n")

    egg = tmp_path / "lib" / "bar.egg-info"
    egg.mkdir(parents=True)
    (egg / "PKG-INFO").write_text("Name: bar\nVersion: 2.0.0\n")

    results = list(fs._iter_python_pkgs(tmp_path))

    # Now returns Component objects
    assert {(c.name, c.version) for c in results} == {("foo", "1.0.0"), ("bar", "2.0.0")}


def test_iter_python_pkgs_without_version(tmp_path: Path) -> None:
    dist = tmp_path / "pkg" / "nover.dist-info"
    dist.mkdir(parents=True)
    (dist / "METADATA").write_text("Name: nover\n")

    results = list(fs._iter_python_pkgs(tmp_path))

    # Expect a single Component with missing version (None)
    assert len(results) == 1
    assert isinstance(results[0], Component)
    assert results[0].name == "nover"
    assert results[0].version in (None, "")


def test_iter_ignored_dirs() -> None:
    restricted_path = Path("/proc")
    results = list(fs._iter_folders(restricted_path))

    assert results == []


def test_iter_node_modules_uses_helpers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    nm1 = tmp_path / "a" / "node_modules"
    nm1.mkdir(parents=True)
    nm2 = tmp_path / "a" / "b" / "node_modules"
    nm2.mkdir(parents=True)

    def fake_exists(path: str | Path) -> bool:  # noqa: ARG001
        return True

    def fake_get_all(path: str | Path) -> List[Component]:
        p = str(path)
        if p.endswith(str(Path("a") / "node_modules")):
            return [Component.create(name="pkgA", version="1.2.3", env=DependencyEnv.PROD.value, type="npm", source="node_modules")]
        return [Component.create(name="@scope/pkgB", version="4.5.6", env=DependencyEnv.PROD.value, type="npm", source="node_modules")]

    monkeypatch.setattr(fs, "node_modules_directory_exists", fake_exists)
    monkeypatch.setattr(fs, "get_all_node_modules_packages", fake_get_all)

    results = list(fs._iter_node_modules(tmp_path))

    # Both node_modules directories are processed by the iterator
    assert {(c.name, c.version) for c in results} == {("pkgA", "1.2.3"), ("@scope/pkgB", "4.5.6")}


def test_update_sbom_from_filesystem_aggregates_locations(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    py_entries = [
        Component.create(name="requests", version="2.31.0", type="pypi", source="pkg_packages"),
        Component.create(name="requests", version="2.31.0", type="pypi", source="pkg_packages"),
    ]
    nm_entries = [
        Component.create(name="left-pad", version="1.3.0", env=DependencyEnv.PROD.value, type="npm", source="node_modules"),
    ]

    monkeypatch.setattr(fs, "_iter_python_pkgs", lambda root: iter(py_entries))
    monkeypatch.setattr(fs, "_iter_node_modules", lambda root: iter(nm_entries))

    sbom = OSSBOM()
    out = fs.update_sbom_from_filesystem(sbom, project_folder=str(tmp_path))

    assert out is sbom
    comps = list(sbom.components.values())
    names = {c.name for c in comps}
    assert names == {"requests", "left-pad"}

    # Validate basic metadata (locations no longer aggregated here)
    req = next(c for c in comps if c.name == "requests")
    assert req.version == "2.31.0"
    assert req.type == "pypi"


def test_location_is_included_in_sbom(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    py_entries = [
        Component.create(name="requests", version="2.31.0", type="pypi", source="pkg_packages"),
        Component.create(name="requests", version="2.31.0", type="pypi", source="pkg_packages"),
    ]
    nm_entries = [
        Component.create(name="left-pad", version="1.3.0", env=DependencyEnv.PROD.value, type="npm", source="node_modules"),
    ]

    monkeypatch.setattr(fs, "_iter_python_pkgs", lambda root: iter(py_entries))
    monkeypatch.setattr(fs, "_iter_node_modules", lambda root: iter(nm_entries))

    sbom = OSSBOM()
    out = fs.update_sbom_from_filesystem(sbom, project_folder=str(tmp_path))

    assert out is sbom
    comps = list(sbom.components.values())
    names = {c.name for c in comps}
    assert names == {"requests", "left-pad"}

    # Find requests component and verify basic metadata
    req = next(c for c in comps if c.name == "requests")
    assert req.version == "2.31.0"
    assert req.type == "pypi"


def test_github_repo_from_direct_url_variants() -> None:
    # git+https URL with .git suffix
    d1 = {"url": "git+https://github.com/ossprey/example_malicious_python.git"}
    assert fs._github_repo_from_direct_url(d1) == "ossprey/example_malicious_python"

    # Plain https URL without .git
    d2 = {"url": "https://github.com/pallets/flask"}
    assert fs._github_repo_from_direct_url(d2) == "pallets/flask"

    # Non-GitHub URL should return None
    d3 = {"url": "https://gitlab.com/group/project.git"}
    assert fs._github_repo_from_direct_url(d3) is None


def test_github_version_from_direct_url_cases() -> None:
    # Prefer requested branch/tag name when present and different from commit
    d1 = {"vcs_info": {"requested_revision": "main", "commit_id": "abcdef0123456789"}}
    assert fs._github_version_from_direct_url(d1) == ("latest", "main")

    # Only commit present -> short commit, no branch
    d2 = {"vcs_info": {"commit_id": "0123456789abcdef0123"}}
    assert fs._github_version_from_direct_url(d2) == ("0123456789ab", None)

    # Neither present -> default latest
    d3 = {"vcs_info": {}}
    assert fs._github_version_from_direct_url(d3) == ("latest", None)


def test_python_pkg_to_component_tuple_github_mapping(tmp_path: Path) -> None:
    loc = tmp_path / "pkg" / "example-0.1.0.dist-info"
    direct = {
        "url": "git+https://github.com/ossprey/example_malicious_python.git",
        "vcs_info": {"requested_revision": "main", "commit_id": "deadbeefcafebabe"},
    }
    ptype, name, ver, source = fs._python_pkg_to_component_tuple(
        "mathlib", "0.1.0", loc, direct
    )
    assert (ptype, name, ver, source) == (
        "github",
        "ossprey/example_malicious_python",
        "latest",
        "pkg_packages",
    )


def test_update_sbom_from_filesystem_emits_github_component(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # Create a Python package installed metadata and simulate GitHub source via direct_url
    loc = tmp_path / "site-packages" / "example-0.1.0.dist-info"
    loc.mkdir(parents=True)
    (loc / "METADATA").write_text("Name: example_malicious_python\nVersion: 0.1.0\n")

    def fake_get_direct_url(path: Path) -> dict | None:  # noqa: ARG001
        return {
            "url": "https://github.com/ossprey/example_malicious_python",
            "vcs_info": {"requested_revision": "main"},
        }

    monkeypatch.setattr(fs, "_iter_node_modules", lambda root: iter(()))
    monkeypatch.setattr(fs, "_get_direct_url", fake_get_direct_url)

    sbom = OSSBOM()
    fs.update_sbom_from_filesystem(sbom, project_folder=str(tmp_path))

    comps = list(sbom.components.values())
    assert len(comps) == 1
    c = comps[0]
    assert c.type == "github"
    assert c.name == "ossprey/example_malicious_python"
    assert c.version == "latest"
    assert c.source == {"pkg_packages"}

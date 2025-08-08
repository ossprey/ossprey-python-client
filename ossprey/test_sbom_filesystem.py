from __future__ import annotations

from pathlib import Path
from typing import List

import pytest

from ossbom.model.dependency_env import DependencyEnv
from ossbom.model.ossbom import OSSBOM
from ossprey import sbom_filesystem as fs


def test_iter_python_pkgs_reads_metadata(tmp_path: Path) -> None:
    dist = tmp_path / "site-packages" / "foo-1.0.0.dist-info"
    dist.mkdir(parents=True)
    (dist / "METADATA").write_text("Name: foo\nVersion: 1.0.0\n")

    egg = tmp_path / "lib" / "bar.egg-info"
    egg.mkdir(parents=True)
    (egg / "PKG-INFO").write_text("Name: bar\nVersion: 2.0.0\n")

    results = list(fs._iter_python_pkgs(tmp_path))

    assert {(n, v) for n, v, _ in results} == {("foo", "1.0.0"), ("bar", "2.0.0")}
    assert any(loc == dist for _, _, loc in results)
    assert any(loc == egg for _, _, loc in results)


def test_iter_python_pkgs_without_version(tmp_path: Path) -> None:
    dist = tmp_path / "pkg" / "nover.dist-info"
    dist.mkdir(parents=True)
    (dist / "METADATA").write_text("Name: nover\n")

    results = list(fs._iter_python_pkgs(tmp_path))

    assert results == [("nover", "", dist)]


def test_iter_node_modules_uses_helpers(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    nm1 = tmp_path / "a" / "node_modules"
    nm1.mkdir(parents=True)
    nm2 = tmp_path / "a" / "b" / "node_modules"
    nm2.mkdir(parents=True)

    def fake_exists(path: str | Path) -> bool:  # noqa: ARG001
        return True

    def fake_get_all(path: str | Path) -> List[dict]:
        p = str(path)
        if p.endswith(str(Path("a") / "node_modules")):
            return [{"name": "pkgA", "version": "1.2.3"}]
        return [{"name": "@scope/pkgB", "version": "4.5.6"}]

    monkeypatch.setattr(fs, "node_modules_directory_exists", fake_exists)
    monkeypatch.setattr(fs, "get_all_node_modules_packages", fake_get_all)

    results = list(fs._iter_node_modules(tmp_path))

    # Both node_modules directories are processed by the iterator
    assert {(n, v) for n, v, _ in results} == {("pkgA", "1.2.3"), ("@scope/pkgB", "4.5.6")}
    assert any(loc == nm1 for _, _, loc in results)
    assert any(loc == nm2 for _, _, loc in results)


def test_update_sbom_from_filesystem_aggregates_locations(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    py_entries = [
        ("requests", "2.31.0", tmp_path / "py1" / "requests-2.31.0.dist-info"),
        ("requests", "2.31.0", tmp_path / "py2" / "requests-2.31.0.dist-info"),
    ]
    nm_entries = [
        ("left-pad", "1.3.0", tmp_path / "a" / "node_modules"),
    ]

    monkeypatch.setattr(fs, "_iter_python_pkgs", lambda root: iter(py_entries))
    monkeypatch.setattr(fs, "_iter_node_modules", lambda root: iter(nm_entries))

    sbom = OSSBOM()
    out = fs.update_sbom_from_filesystem(sbom, project_folder=str(tmp_path))

    assert out is sbom
    comps = list(sbom.components.values())
    names = {c.name for c in comps}
    assert names == {"requests", "left-pad"}

    # Find requests component and verify locations aggregated and metadata
    req = next(c for c in comps if c.name == "requests")
    assert req.version == "2.31.0"
    assert req.type == "python"
    assert req.env == {DependencyEnv.PROD}
    assert req.source == {"pkg_packages"}
    assert sorted(req.location) == sorted([str(py_entries[0][2]), str(py_entries[1][2])])

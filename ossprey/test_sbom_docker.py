from __future__ import annotations

import pytest
from pathlib import Path
from unittest.mock import patch

from ossbom.model.ossbom import OSSBOM
from ossprey.sbom_docker import (
    _iter_python_pkgs,
    _iter_node_modules,
    update_sbom_from_docker,
)


def test_iter_python_pkgs_dist_info(tmp_path: Path) -> None:
    """Test that dist-info directories are parsed correctly."""
    dist = tmp_path / "site-packages" / "foo-1.0.0.dist-info"
    dist.mkdir(parents=True)
    (dist / "METADATA").write_text("Name: foo\nVersion: 1.0.0\n")

    results = list(_iter_python_pkgs(tmp_path))

    assert len(results) == 1
    name, ver, path = results[0]
    assert name == "foo"
    assert ver == "1.0.0"
    assert path == dist


def test_iter_python_pkgs_egg_info(tmp_path: Path) -> None:
    """Test that egg-info directories are parsed via PKG-INFO."""
    egg = tmp_path / "lib" / "bar.egg-info"
    egg.mkdir(parents=True)
    (egg / "PKG-INFO").write_text("Name: bar\nVersion: 2.0.0\n")

    results = list(_iter_python_pkgs(tmp_path))

    assert len(results) == 1
    name, ver, path = results[0]
    assert name == "bar"
    assert ver == "2.0.0"
    assert path == egg


def test_iter_python_pkgs_no_version(tmp_path: Path) -> None:
    """Test that packages without a Version header have an empty string version."""
    dist = tmp_path / "pkg" / "nover.dist-info"
    dist.mkdir(parents=True)
    (dist / "METADATA").write_text("Name: nover\n")

    results = list(_iter_python_pkgs(tmp_path))

    assert len(results) == 1
    name, ver, path = results[0]
    assert name == "nover"
    assert ver == ""


def test_iter_python_pkgs_multiple(tmp_path: Path) -> None:
    """Test iteration over multiple packages."""
    for pkg_name, version in [("alpha", "1.0.0"), ("beta", "2.3.4")]:
        dist = tmp_path / f"{pkg_name}-{version}.dist-info"
        dist.mkdir(parents=True)
        (dist / "METADATA").write_text(f"Name: {pkg_name}\nVersion: {version}\n")

    results = list(_iter_python_pkgs(tmp_path))

    assert len(results) == 2
    names = {r[0] for r in results}
    assert names == {"alpha", "beta"}


def test_iter_python_pkgs_empty(tmp_path: Path) -> None:
    """Test that an empty directory yields no results."""
    results = list(_iter_python_pkgs(tmp_path))
    assert results == []


def test_iter_node_modules(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that node_modules directories are discovered and packages returned."""
    nm = tmp_path / "node_modules"
    nm.mkdir()

    import ossprey.sbom_docker as sbom_docker

    monkeypatch.setattr(sbom_docker, "node_modules_directory_exists", lambda p: True)
    monkeypatch.setattr(
        sbom_docker,
        "get_all_node_modules_packages",
        lambda p: [{"name": "pkgA", "version": "1.0.0"}],
    )

    results = list(_iter_node_modules(tmp_path))

    assert len(results) == 1
    name, ver, nm_path = results[0]
    assert name == "pkgA"
    assert ver == "1.0.0"
    assert nm_path == nm


def test_iter_node_modules_deduplicates_nested(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test that nested node_modules under a seen parent are skipped."""
    nm_outer = tmp_path / "node_modules"
    nm_outer.mkdir()
    nm_inner = tmp_path / "node_modules" / "some_pkg" / "node_modules"
    nm_inner.mkdir(parents=True)

    import ossprey.sbom_docker as sbom_docker

    call_count = {"count": 0}

    def fake_get_all(path):
        call_count["count"] += 1
        return [{"name": "pkgA", "version": "1.0.0"}]

    monkeypatch.setattr(sbom_docker, "node_modules_directory_exists", lambda p: True)
    monkeypatch.setattr(sbom_docker, "get_all_node_modules_packages", fake_get_all)

    results = list(_iter_node_modules(tmp_path))

    # Only the outer node_modules should be processed (inner is nested under it)
    assert call_count["count"] == 1
    assert len(results) == 1


def test_iter_node_modules_empty(tmp_path: Path) -> None:
    """Test that a directory without node_modules yields nothing."""
    results = list(_iter_node_modules(tmp_path))
    assert results == []


def test_update_sbom_from_docker_python(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that Python packages are correctly added to the SBOM."""
    dist = tmp_path / "site-packages" / "requests-2.31.0.dist-info"
    dist.mkdir(parents=True)
    (dist / "METADATA").write_text("Name: requests\nVersion: 2.31.0\n")

    import ossprey.sbom_docker as sbom_docker

    monkeypatch.setattr(sbom_docker, "node_modules_directory_exists", lambda p: False)

    sbom = OSSBOM()
    result = update_sbom_from_docker(sbom, str(tmp_path))

    assert result is sbom
    comps = list(sbom.components.values())
    assert len(comps) == 1
    c = comps[0]
    assert c.name == "requests"
    assert c.version == "2.31.0"
    assert c.type == "python"
    assert c.source == {"pkg_packages"}


def test_update_sbom_from_docker_npm(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that npm packages are correctly added to the SBOM."""
    nm = tmp_path / "node_modules"
    nm.mkdir()

    import ossprey.sbom_docker as sbom_docker

    monkeypatch.setattr(sbom_docker, "node_modules_directory_exists", lambda p: True)
    monkeypatch.setattr(
        sbom_docker,
        "get_all_node_modules_packages",
        lambda p: [{"name": "express", "version": "4.18.0"}],
    )

    sbom = OSSBOM()
    result = update_sbom_from_docker(sbom, str(tmp_path))

    assert result is sbom
    comps = list(sbom.components.values())
    npm_comps = [c for c in comps if c.type == "npm"]
    assert len(npm_comps) == 1
    assert npm_comps[0].name == "express"
    assert npm_comps[0].version == "4.18.0"
    assert npm_comps[0].source == {"node_modules"}


def test_update_sbom_from_docker_aggregates_locations(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test that multiple locations for the same package are aggregated."""
    for site in ["site1", "site2"]:
        dist = tmp_path / site / "requests-2.31.0.dist-info"
        dist.mkdir(parents=True)
        (dist / "METADATA").write_text("Name: requests\nVersion: 2.31.0\n")

    import ossprey.sbom_docker as sbom_docker

    monkeypatch.setattr(sbom_docker, "node_modules_directory_exists", lambda p: False)

    sbom = OSSBOM()
    update_sbom_from_docker(sbom, str(tmp_path))

    comps = list(sbom.components.values())
    assert len(comps) == 1
    c = comps[0]
    assert c.name == "requests"
    assert len(c.location) == 2


def test_update_sbom_from_docker_empty(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that an empty root yields an SBOM with no components."""
    import ossprey.sbom_docker as sbom_docker

    monkeypatch.setattr(sbom_docker, "node_modules_directory_exists", lambda p: False)

    sbom = OSSBOM()
    result = update_sbom_from_docker(sbom, str(tmp_path))

    assert result is sbom
    assert len(list(sbom.components.values())) == 0

from __future__ import annotations

from pathlib import Path
from typing import List

import json
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

    # Validate it returns components
    assert len(results) == 2
    assert all(isinstance(c, Component) for c in results)
    # Validate it includes the source and location
    pkg = next(c for c in results if c.name == "foo")
    print(pkg)
    assert pkg.version == "1.0.0"
    assert pkg.env == {DependencyEnv.PROD}
    assert pkg.type == "pypi"
    assert pkg.source == {"pkg_packages"}
    assert pkg.location == [str(dist)]

    assert all(
        val in ("pkg_packages", "egg_packages") for c in results for val in c.source
    )
    assert all(c.location == [str(dist)] or c.location == [str(egg)] for c in results)


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
    results = list(fs.iter_paths(restricted_path))

    assert results == []


def test_iter_node_modules_uses_helpers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    nm1 = tmp_path / "a" / "node_modules"
    nm1.mkdir(parents=True)
    nm2 = tmp_path / "a" / "b" / "node_modules"
    nm2.mkdir(parents=True)

    def fake_exists(path: str | Path) -> bool:  # noqa: ARG001
        return True

    def fake_get_all(path: str | Path) -> List[Component]:
        # _iter_node_modules passes the parent directory of the node_modules folder
        p = Path(path)
        if p.name == "a":
            return [
                Component.create(
                    name="pkgA",
                    version="1.2.3",
                    env=DependencyEnv.PROD.value,
                    type="npm",
                    source="node_modules",
                )
            ]
        return [
            Component.create(
                name="@scope/pkgB",
                version="4.5.6",
                env=DependencyEnv.PROD.value,
                type="npm",
                source="node_modules",
            )
        ]

    monkeypatch.setattr(fs, "node_modules_directory_exists", fake_exists)
    monkeypatch.setattr(fs, "get_all_node_modules_packages", fake_get_all)

    results = list(fs._iter_node_modules(tmp_path))

    # Assert results only contains Components
    assert len(results) == 2
    assert all(isinstance(c, Component) for c in results)
    # Source is node_modules
    assert all(val == "node_modules" for c in results for val in c.source)
    # Location is present
    assert all(len(c.location) > 0 for c in results)

    # Validate at least one is valid
    print([c.location for c in results])
    print(str(nm1.parent))
    assert any(
        c.name == "pkgA" and c.version == "1.2.3" and c.location == [str(nm1.parent)]
        for c in results
    )


def test_update_sbom_from_filesystem_aggregates_locations(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    py_entries = [
        Component.create(
            name="requests",
            version="2.31.0",
            type="pypi",
            source="pkg_packages",
            env=DependencyEnv.PROD.value,
            location=[str(tmp_path / "pkg" / "requests-2.31.0.dist-info")],
        ),
        Component.create(
            name="requests",
            version="2.31.0",
            type="pypi",
            source="pkg_packages",
            env=DependencyEnv.PROD.value,
            location=[str(tmp_path / "pkg" / "requests-2.31.0.dist-info")],
        ),
    ]
    nm_entries = [
        Component.create(
            name="left-pad",
            version="1.3.0",
            env=DependencyEnv.PROD.value,
            type="npm",
            source="node_modules",
            location=[str(tmp_path / "a" / "b" / "node_modules" / "left-pad")],
        ),
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

    # Validate locations
    print(req.location)
    assert req.location == [str(tmp_path / "pkg" / "requests-2.31.0.dist-info")] * 2
    left_pad = next(c for c in comps if c.name == "left-pad")
    assert left_pad.location == [
        str(tmp_path / "a" / "b" / "node_modules" / "left-pad")
    ]


def test_scan_handles_npm_and_pypi(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    py_entries = [
        Component.create(
            name="requests",
            version="2.31.0",
            type="pypi",
            source="pkg_packages",
            env=DependencyEnv.PROD.value,
        ),
        Component.create(
            name="requests",
            version="2.31.0",
            type="pypi",
            source="pkg_packages",
            env=DependencyEnv.PROD.value,
        ),
    ]
    nm_entries = [
        Component.create(
            name="left-pad",
            version="1.3.0",
            env=DependencyEnv.PROD.value,
            type="npm",
            source="node_modules",
        ),
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
    assert fs._github_version_from_direct_url(d1) == ("abcdef012345", "main")

    # Only commit present -> short commit, no branch
    d2 = {"vcs_info": {"commit_id": "0123456789abcdef0123"}}
    assert fs._github_version_from_direct_url(d2) == ("0123456789ab", None)

    # Neither present -> default latest
    d3 = {"vcs_info": {}}
    assert fs._github_version_from_direct_url(d3) == ("latest", "main")


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
        "deadbeefcafe",
        "pkg_packages",
    )


def test_update_sbom_from_filesystem_emits_github_component(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
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


def test__iter_python_pkgs_validity(tmp_path: Path) -> None:
    # Create a valid Python package metadata
    dist = tmp_path / "pkg" / "valid_pkg-1.0.0.dist-info"
    dist.mkdir(parents=True)
    (dist / "METADATA").write_text("Name: valid_pkg\nVersion: 1.0.0\n")

    # Create a second valid one with a github link
    dist2 = tmp_path / "pkg" / "valid_pkg_github-1.0.0.dist-info"
    dist2.mkdir(parents=True)
    (dist2 / "METADATA").write_text("Name: valid_pkg_github\nVersion: 1.0.0\n")
    (dist2 / "direct_url.json").write_text(
        '{"url": "git+https://github.com/ossprey/valid_pkg_github.git", "vcs_info": {"requested_revision": "main", "commit_id": "deadbeefcafebabe"}}'
    )

    results = list(fs._iter_python_pkgs(tmp_path))

    assert len(results) == 2
    assert all(isinstance(r, Component) for r in results)
    c = next(r for r in results if r.name == "valid_pkg")
    assert c.name == "valid_pkg"
    assert c.version == "1.0.0"
    assert c.type == "pypi"
    assert c.source == {"pkg_packages"}
    assert c.location == [str(dist)]

    d = next(r for r in results if r.name == "ossprey/valid_pkg_github")
    assert d.name == "ossprey/valid_pkg_github"
    assert d.version == "deadbeefcafebabe"[:12]
    assert d.type == "github"
    assert d.source == {"pkg_packages"}
    assert d.location == [str(dist2)]


def test__iter_node_modules(tmp_path):
    # Create a valid Node.js package metadata
    dist = tmp_path / "node_modules" / "valid_pkg"
    dist.mkdir(parents=True)
    (dist / "package.json").write_text('{"name": "valid_pkg", "version": "1.0.0"}')

    results = list(fs._iter_node_modules(tmp_path))

    assert len(results) == 1
    assert all(isinstance(r, Component) for r in results)
    c = results[0]
    assert c.name == "valid_pkg"
    assert c.version == "1.0.0"
    assert c.type == "npm"
    assert c.source == {"node_modules"}
    assert c.location == [str(tmp_path)]


def test__iter_package_lock_files(tmp_path):
    package_json = {
        "packages": {
            "node_modules/valid_pkg": {"version": "1.0.0"},
            "mathlib": {
                "version": "1.0.0",
                "resolved": "git+https://github.com/ossprey/special.git#abcdefgh",
            },
        }
    }

    # Create a valid package-lock.json
    lock_file = tmp_path / "package-lock.json"
    lock_file.write_text(json.dumps(package_json))

    results = list(fs._iter_package_lock_files(tmp_path))

    assert len(results) == 2
    assert all(isinstance(r, Component) for r in results)
    c = results[0]
    assert c.name == "valid_pkg"
    assert c.version == "1.0.0"
    assert c.type == "npm"
    assert c.source == {"package-lock.json"}
    assert c.location == [str(tmp_path)]

    d = results[1]
    assert d.name == "ossprey/special"
    assert d.version == "abcdefgh"
    assert d.type == "github"
    assert d.source == {"package-lock.json"}
    assert d.location == [str(tmp_path)]


# TODO BROKEN
def test__iter_yarn_lock_files(tmp_path):
    yarn_lock = """# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1


"@ampproject/remapping@^2.2.0":
  version "2.3.0"
  resolved "https://registry.npmjs.org/@ampproject/remapping/-/remapping-2.3.0.tgz"
  integrity sha512-30iZtAPgz+LTIYoeivqYo853f02jBYSd5uGnGpkFV0M3xOt9aN73erkgYAmZU43x4VfqcnLxW9Kpg3R5LC4YYw==
  dependencies:
    "@jridgewell/gen-mapping" "^0.3.5"
    "@jridgewell/trace-mapping" "^0.3.24"

"@babel/compat-data@^7.26.5":
  version "7.26.8"
  resolved "https://registry.npmjs.org/@babel/compat-data/-/compat-data-7.26.8.tgz"
  integrity sha512-oH5UPLMWR3L2wEFLnFJ1TZXqHufiTKAiLfqw5zkhS4dKXLJ10yVztfil/twG8EDTA4F/tvVNw9nOl4ZMslB8rQ==

    """

    # Create a valid yarn.lock
    lock_file = tmp_path / "yarn.lock"
    lock_file.write_text(yarn_lock)
    # tmp_path = Path("./test/docker_js_simple_math/javascript/")
    results = list(fs._iter_yarn_lock_files(tmp_path))

    assert len(results) == 2
    assert all(isinstance(r, Component) for r in results)
    c = results[0]
    assert c.name == "@ampproject/remapping"
    assert c.version == "2.3.0"
    assert c.type == "npm"
    assert c.source == {"yarn.lock"}
    assert c.location == [str(tmp_path)]

    d = results[1]
    assert d.name == "@babel/compat-data"
    assert d.version == "7.26.8"
    assert d.type == "npm"
    assert d.source == {"yarn.lock"}
    assert d.location == [str(tmp_path)]

"""
Smoke tests for ossprey — end-to-end CLI verification.

Invokes `python -m ossprey` via subprocess to exercise the full scanning pipeline.

By default uses --dry-run-safe (no API key needed).
If API_KEY env var is set, also runs a real API scan pass.

Usage:
    poetry run pytest test/smoke/ -v
    poetry run pytest test/smoke/ -v -m "smoke and not slow"
    poetry run pytest test/smoke/ -v -m "smoke and not network"
    API_KEY=<key> poetry run pytest test/smoke/ -v
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

PYTHON = sys.executable


def run_ossprey(
    package_dir: str | Path,
    *,
    mode: str = "auto",
    dry_run: str = "safe",
    output_file: str | Path | None = None,
    expect_exit: int = 0,
    extra_args: list[str] | None = None,
    timeout: int = 300,
) -> subprocess.CompletedProcess:
    """Run ``python -m ossprey`` as a subprocess and assert the exit code.

    Parameters
    ----------
    package_dir:
        Directory to scan.
    mode:
        Scanning mode (auto, pipenv, python-requirements, poetry, npm, yarn, fs).
    dry_run:
        "safe", "malicious", or None.  When None and API_KEY is available a
        real API scan is made, otherwise falls back to "safe".
    output_file:
        If provided, pass ``-o <path>`` so ossprey writes the SBOM JSON.
    expect_exit:
        Expected process exit code.
    extra_args:
        Additional CLI flags.
    timeout:
        Subprocess timeout in seconds.
    """
    cmd = [PYTHON, "-m", "ossprey", "--package", str(package_dir), "--mode", mode, "-v"]

    if dry_run == "safe":
        cmd.append("--dry-run-safe")
    elif dry_run == "malicious":
        cmd.append("--dry-run-malicious")
    else:
        # Real API scan — requires API_KEY
        api_key = os.environ.get("API_KEY")
        if api_key:
            cmd.extend(["--api-key", api_key])
        else:
            # Fall back to dry-run-safe when no key is present
            cmd.append("--dry-run-safe")

    if output_file is not None:
        cmd.extend(["-o", str(output_file)])

    if extra_args:
        cmd.extend(extra_args)

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=str(Path(__file__).resolve().parent.parent.parent),  # project root
    )

    assert result.returncode == expect_exit, (
        f"ossprey exited {result.returncode}, expected {expect_exit}.\n"
        f"CMD: {' '.join(cmd)}\n"
        f"STDOUT:\n{result.stdout[-2000:]}\n"
        f"STDERR:\n{result.stderr[-2000:]}"
    )
    return result


def assert_sbom_has_components(sbom_path: Path, min_components: int = 1):
    """Load an SBOM JSON file and assert it contains components."""
    assert sbom_path.exists(), f"SBOM output file not found: {sbom_path}"
    data = json.loads(sbom_path.read_text())
    components = data.get("components", [])
    assert (
        len(components) >= min_components
    ), f"Expected >= {min_components} components, got {len(components)} in {sbom_path}"
    return data


def maybe_run_api_scan(package_dir: str | Path, output_file: Path | None = None):
    """If API_KEY is set, also run a real API scan (non-dry-run)."""
    if os.environ.get("API_KEY"):
        run_ossprey(package_dir, dry_run=None, output_file=output_file)


# ---------------------------------------------------------------------------
# 1. Scan all existing test_packages
# ---------------------------------------------------------------------------

EXISTING_PACKAGES = [
    "python_simple_math",
    "poetry_simple_math",
    "poetry_broken_simple_math",
    "npm_simple_math",
    "yarn_simple_math",
    "yarn_massive_math",
]


@pytest.mark.smoke
@pytest.mark.parametrize("pkg_name", EXISTING_PACKAGES)
def test_existing_test_packages(pkg_name, test_packages_dir, tmp_path):
    """Scan each non-Docker test package and verify a clean SBOM is produced."""
    pkg_dir = test_packages_dir / pkg_name
    assert pkg_dir.is_dir(), f"Test package not found: {pkg_dir}"

    sbom_file = tmp_path / "sbom.json"
    result = run_ossprey(pkg_dir, output_file=sbom_file)

    # Verify stdout reports clean
    assert "No malware found" in result.stdout

    # Verify SBOM file has components
    assert_sbom_has_components(sbom_file)

    # Optionally exercise real API
    maybe_run_api_scan(pkg_dir)


# ---------------------------------------------------------------------------
# 1b. Packaging-format coverage — static fixtures that exercise each ecosystem.
#
# Each entry is (fixture_dir_name, expected_min_components). xfail-marked
# entries cover packaging formats the CLI doesn't yet detect (Pipfile,
# pnpm-lock.yaml) — they fail loudly so we can investigate and add parsers.
# ---------------------------------------------------------------------------

PACKAGING_VARIANTS = [
    pytest.param("uv_simple_math", 2, id="python-uv"),
    pytest.param("hatch_simple_math", 2, id="python-hatch"),
    pytest.param("pip_tools_simple_math", 2, id="python-pip-tools"),
    pytest.param("pipfile_simple_math", 2, id="python-pipenv"),
    pytest.param("npm_no_lock_simple_math", 1, id="js-npm-no-lock"),
    pytest.param("yarn_berry_simple_math", 2, id="js-yarn-berry"),
    pytest.param("pnpm_simple_math", 2, id="js-pnpm"),
]


@pytest.mark.smoke
@pytest.mark.parametrize("pkg_name, min_components", PACKAGING_VARIANTS)
def test_packaging_variants(pkg_name, min_components, test_packages_dir, tmp_path):
    """Scan static fixtures covering each packaging ecosystem (auto mode)."""
    pkg_dir = test_packages_dir / pkg_name
    assert pkg_dir.is_dir(), f"Packaging fixture not found: {pkg_dir}"

    sbom_file = tmp_path / "sbom.json"
    result = run_ossprey(pkg_dir, output_file=sbom_file, timeout=300)

    assert "No malware found" in result.stdout
    assert_sbom_has_components(sbom_file, min_components=min_components)


# ---------------------------------------------------------------------------
# 2. Dry-run malicious path
# ---------------------------------------------------------------------------


@pytest.mark.smoke
def test_dry_run_malicious(test_packages_dir, tmp_path):
    """Verify --dry-run-malicious injects a vulnerability and exits 1."""
    pkg_dir = test_packages_dir / "python_simple_math"
    sbom_file = tmp_path / "sbom.json"

    result = run_ossprey(
        pkg_dir,
        dry_run="malicious",
        output_file=sbom_file,
        expect_exit=1,
    )

    assert "malware" in result.stdout.lower() or "warning" in result.stdout.lower()

    # SBOM should contain a vulnerability
    data = json.loads(sbom_file.read_text())
    vulns = data.get("vulnerabilities", [])
    assert len(vulns) >= 1, "Expected at least 1 vulnerability in malicious dry-run"


# ---------------------------------------------------------------------------
# 3. Installable test packages (pip-installable projects scanned via auto)
# ---------------------------------------------------------------------------

INSTALLABLE_PACKAGES = [
    "python_simple_math",  # has setup.py + requirements.txt
    "poetry_simple_math",  # has pyproject.toml with build-system
]


@pytest.mark.smoke
@pytest.mark.slow
@pytest.mark.parametrize("pkg_name", INSTALLABLE_PACKAGES)
def test_installable_existing_packages(pkg_name, test_packages_dir, tmp_path):
    """Scan pip-installable test packages via auto mode."""
    pkg_dir = test_packages_dir / pkg_name
    sbom_file = tmp_path / "sbom.json"

    result = run_ossprey(pkg_dir, output_file=sbom_file, timeout=600)

    assert "No malware found" in result.stdout
    assert_sbom_has_components(sbom_file, min_components=2)


# ---------------------------------------------------------------------------
# 4. Real-world Python packages (requirements.txt scanning)
# ---------------------------------------------------------------------------

REAL_PYTHON_PACKAGES = [
    ("flask", "flask==3.0.0"),
    ("django", "django==5.0"),
    ("fastapi", "fastapi==0.109.0"),
    ("boto3", "boto3==1.34.0"),
    ("requests", "requests==2.31.0"),
    ("numpy", "numpy==1.26.3"),
]


@pytest.mark.smoke
@pytest.mark.network
@pytest.mark.parametrize(
    "name, spec", REAL_PYTHON_PACKAGES, ids=[p[0] for p in REAL_PYTHON_PACKAGES]
)
def test_real_world_python_requirements(name, spec, tmp_path):
    """Create a requirements.txt with a real package and scan it."""
    pkg_dir = tmp_path / name
    pkg_dir.mkdir()
    (pkg_dir / "requirements.txt").write_text(spec + "\n")

    sbom_file = tmp_path / f"{name}_sbom.json"
    result = run_ossprey(pkg_dir, output_file=sbom_file)

    assert "No malware found" in result.stdout
    data = assert_sbom_has_components(sbom_file)

    # The named package should appear in components
    comp_names = [c.get("name", "").lower() for c in data["components"]]
    assert name in comp_names, f"Expected '{name}' in components: {comp_names}"


# ---------------------------------------------------------------------------
# 5. Real-world Python packages (installable — full install via auto)
# ---------------------------------------------------------------------------

REAL_INSTALLABLE_PACKAGES = [
    ("flask_pkg", ["flask==3.0.0"], "flask"),
    ("django_pkg", ["django==5.0"], "django"),
    ("requests_numpy_pkg", ["requests==2.31.0", "numpy==1.26.3"], "requests"),
    ("boto3_pkg", ["boto3==1.34.0"], "boto3"),
    ("fastapi_pkg", ["fastapi==0.109.0"], "fastapi"),
]


def _create_installable_package(
    base_dir: Path, name: str, install_requires: list[str]
) -> Path:
    """Create a minimal pip-installable package with a requirements.txt for auto-detection."""
    pkg_dir = base_dir / name
    pkg_dir.mkdir()

    inner_pkg = pkg_dir / "mypkg"
    inner_pkg.mkdir()
    (inner_pkg / "__init__.py").write_text("")

    deps_str = ", ".join(f'"{d}"' for d in install_requires)
    setup_py = textwrap.dedent(
        f"""\
        from setuptools import setup, find_packages
        setup(
            name="{name}",
            version="0.0.1",
            packages=find_packages(),
            install_requires=[{deps_str}],
        )
    """
    )
    (pkg_dir / "setup.py").write_text(setup_py)

    # Also write requirements.txt so auto mode detects python-requirements
    (pkg_dir / "requirements.txt").write_text("\n".join(install_requires) + "\n")

    return pkg_dir


@pytest.mark.smoke
@pytest.mark.slow
@pytest.mark.network
@pytest.mark.parametrize(
    "name, deps, expected_component",
    REAL_INSTALLABLE_PACKAGES,
    ids=[p[0] for p in REAL_INSTALLABLE_PACKAGES],
)
def test_real_world_installable_packages(name, deps, expected_component, tmp_path):
    """Create a minimal installable package with requirements.txt, scan via auto mode."""
    pkg_dir = _create_installable_package(tmp_path, name, deps)
    sbom_file = tmp_path / f"{name}_sbom.json"

    result = run_ossprey(pkg_dir, output_file=sbom_file, timeout=600)

    assert "No malware found" in result.stdout

    data = assert_sbom_has_components(sbom_file)
    comp_names = [c.get("name", "").lower() for c in data["components"]]
    assert (
        expected_component in comp_names
    ), f"Expected '{expected_component}' in components: {comp_names}"


# ---------------------------------------------------------------------------
# 6. Real-world npm packages
# ---------------------------------------------------------------------------

REAL_NPM_PACKAGES = [
    ("express", {"express": "4.18.2"}),
    ("react", {"react": "18.2.0"}),
    ("axios", {"axios": "1.6.5"}),
    ("lodash", {"lodash": "4.17.21"}),
    ("typescript", {"typescript": "5.3.3"}),
]


def _create_npm_project(base_dir: Path, name: str, dependencies: dict) -> Path:
    """Create a directory with a package.json and run npm install."""
    pkg_dir = base_dir / name
    pkg_dir.mkdir()

    package_json = {
        "name": f"smoke-test-{name}",
        "version": "1.0.0",
        "private": True,
        "dependencies": dependencies,
    }
    (pkg_dir / "package.json").write_text(json.dumps(package_json, indent=2))

    # npm install to generate package-lock.json and node_modules
    subprocess.run(
        ["npm", "install", "--ignore-scripts"],
        cwd=str(pkg_dir),
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    return pkg_dir


@pytest.mark.smoke
@pytest.mark.network
@pytest.mark.parametrize(
    "name, deps", REAL_NPM_PACKAGES, ids=[p[0] for p in REAL_NPM_PACKAGES]
)
def test_real_world_npm_packages(name, deps, tmp_path):
    """Install a real npm package and scan it."""
    pkg_dir = _create_npm_project(tmp_path, name, deps)
    sbom_file = tmp_path / f"{name}_sbom.json"

    result = run_ossprey(pkg_dir, output_file=sbom_file)

    assert "No malware found" in result.stdout
    data = assert_sbom_has_components(sbom_file)

    comp_names = [c.get("name", "").lower() for c in data["components"]]
    assert name in comp_names, f"Expected '{name}' in components: {comp_names}"


# ---------------------------------------------------------------------------
# 6b. Real-world packages across every build system
#
# CLI is the entry point — fixtures are written statically (manifest + lock
# where applicable), no resolver invoked. Tests just point at a real package
# name + version and verify the CLI extracts it.
# ---------------------------------------------------------------------------


def _write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def _build_python_requirements(pkg_dir: Path, name: str, version: str) -> None:
    _write(pkg_dir / "requirements.txt", f"{name}=={version}\n")


def _build_python_pip_tools(pkg_dir: Path, name: str, version: str) -> None:
    _write(pkg_dir / "requirements.in", f"{name}\n")
    _write(
        pkg_dir / "requirements.txt",
        textwrap.dedent(
            f"""\
            # autogenerated by pip-compile
            {name}=={version}
                # via -r requirements.in
            """
        ),
    )


def _build_python_poetry(pkg_dir: Path, name: str, version: str) -> None:
    _write(
        pkg_dir / "pyproject.toml",
        textwrap.dedent(
            f"""\
            [project]
            name = "smoke-poetry-{name}"
            version = "0.1.0"
            requires-python = ">=3.12"
            dependencies = ["{name}=={version}"]

            [build-system]
            requires = ["poetry-core>=2.0.0,<3.0.0"]
            build-backend = "poetry.core.masonry.api"
            """
        ),
    )
    _write(
        pkg_dir / "poetry.lock",
        textwrap.dedent(
            f"""\
            # autogenerated
            [[package]]
            name = "{name}"
            version = "{version}"
            description = ""
            optional = false
            python-versions = ">=3.8"
            """
        ),
    )


def _build_python_uv(pkg_dir: Path, name: str, version: str) -> None:
    _write(
        pkg_dir / "pyproject.toml",
        textwrap.dedent(
            f"""\
            [project]
            name = "smoke-uv-{name}"
            version = "0.1.0"
            requires-python = ">=3.12"
            dependencies = ["{name}=={version}"]

            [build-system]
            requires = ["hatchling"]
            build-backend = "hatchling.build"

            [tool.hatch.build.targets.wheel]
            packages = ["smoke_uv_{name.replace('-', '_')}"]
            """
        ),
    )
    _write(
        pkg_dir / f"smoke_uv_{name.replace('-', '_')}" / "__init__.py", ""
    )


def _build_python_hatch(pkg_dir: Path, name: str, version: str) -> None:
    _write(
        pkg_dir / "pyproject.toml",
        textwrap.dedent(
            f"""\
            [project]
            name = "smoke-hatch-{name}"
            version = "0.1.0"
            requires-python = ">=3.12"
            dependencies = ["{name}=={version}"]

            [build-system]
            requires = ["hatchling"]
            build-backend = "hatchling.build"

            [tool.hatch.build.targets.wheel]
            packages = ["smoke_hatch_{name.replace('-', '_')}"]
            """
        ),
    )
    _write(
        pkg_dir / f"smoke_hatch_{name.replace('-', '_')}" / "__init__.py", ""
    )


def _build_python_pipenv(pkg_dir: Path, name: str, version: str) -> None:
    _write(
        pkg_dir / "Pipfile",
        textwrap.dedent(
            f"""\
            [[source]]
            url = "https://pypi.org/simple"
            verify_ssl = true
            name = "pypi"

            [packages]
            {name} = "=={version}"

            [requires]
            python_version = "3.12"
            """
        ),
    )
    _write(
        pkg_dir / "Pipfile.lock",
        json.dumps(
            {
                "_meta": {
                    "pipfile-spec": 6,
                    "requires": {"python_version": "3.12"},
                    "sources": [
                        {"name": "pypi", "url": "https://pypi.org/simple", "verify_ssl": True}
                    ],
                },
                "default": {
                    name: {"version": f"=={version}", "index": "pypi"}
                },
                "develop": {},
            },
            indent=2,
        ),
    )


def _build_js_npm_lock(pkg_dir: Path, name: str, version: str) -> None:
    _write(
        pkg_dir / "package.json",
        json.dumps(
            {
                "name": f"smoke-npm-{name}",
                "version": "1.0.0",
                "private": True,
                "dependencies": {name: version},
            },
            indent=2,
        ),
    )
    _write(
        pkg_dir / "package-lock.json",
        json.dumps(
            {
                "name": f"smoke-npm-{name}",
                "version": "1.0.0",
                "lockfileVersion": 3,
                "requires": True,
                "packages": {
                    "": {
                        "name": f"smoke-npm-{name}",
                        "version": "1.0.0",
                        "dependencies": {name: version},
                    },
                    f"node_modules/{name}": {"version": version},
                },
            },
            indent=2,
        ),
    )


def _build_js_npm_manifest_only(pkg_dir: Path, name: str, version: str) -> None:
    _write(
        pkg_dir / "package.json",
        json.dumps(
            {
                "name": f"smoke-npm-manifest-{name}",
                "version": "1.0.0",
                "private": True,
                "dependencies": {name: version},
            },
            indent=2,
        ),
    )


def _build_js_yarn_classic(pkg_dir: Path, name: str, version: str) -> None:
    _write(
        pkg_dir / "package.json",
        json.dumps(
            {
                "name": f"smoke-yarn-{name}",
                "version": "1.0.0",
                "private": True,
                "dependencies": {name: version},
            },
            indent=2,
        ),
    )
    _write(
        pkg_dir / "yarn.lock",
        textwrap.dedent(
            f"""\
            # THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
            # yarn lockfile v1


            "{name}@{version}":
              version "{version}"
              resolved "https://registry.yarnpkg.com/{name}/-/{name}-{version}.tgz"
            """
        ),
    )


def _build_js_yarn_berry(pkg_dir: Path, name: str, version: str) -> None:
    _write(
        pkg_dir / "package.json",
        json.dumps(
            {
                "name": f"smoke-yarn-berry-{name}",
                "version": "1.0.0",
                "private": True,
                "packageManager": "yarn@3.6.4",
                "dependencies": {name: version},
            },
            indent=2,
        ),
    )
    _write(
        pkg_dir / "yarn.lock",
        textwrap.dedent(
            f"""\
            # This file is generated by running "yarn install" inside your project.

            __metadata:
              version: 6
              cacheKey: 10c0

            "{name}@npm:{version}":
              version: {version}
              resolution: "{name}@npm:{version}"
              languageName: node
              linkType: hard
            """
        ),
    )


def _build_js_pnpm(pkg_dir: Path, name: str, version: str) -> None:
    _write(
        pkg_dir / "package.json",
        json.dumps(
            {
                "name": f"smoke-pnpm-{name}",
                "version": "1.0.0",
                "private": True,
                "packageManager": "pnpm@8.15.0",
                "dependencies": {name: version},
            },
            indent=2,
        ),
    )
    _write(
        pkg_dir / "pnpm-lock.yaml",
        textwrap.dedent(
            f"""\
            lockfileVersion: '6.0'

            dependencies:
              {name}:
                specifier: {version}
                version: {version}

            packages:

              /{name}@{version}:
                resolution: {{integrity: sha512-abc}}
                dev: false
            """
        ),
    )


# Build systems: (id, builder, xfail_strict_due_to_missing_parser)
PY_BUILDERS = [
    ("py-requirements", _build_python_requirements, False),
    ("py-pip-tools", _build_python_pip_tools, False),
    ("py-poetry", _build_python_poetry, False),
    ("py-uv", _build_python_uv, False),
    ("py-hatch", _build_python_hatch, False),
    ("py-pipenv", _build_python_pipenv, False),
]

JS_BUILDERS = [
    ("js-npm-lock", _build_js_npm_lock, False),
    ("js-npm-manifest-only", _build_js_npm_manifest_only, False),
    ("js-yarn-classic", _build_js_yarn_classic, False),
    ("js-yarn-berry", _build_js_yarn_berry, False),
    ("js-pnpm", _build_js_pnpm, False),
]

# Real packages — pinned versions known to resolve on PyPI / npm.
PY_PACKAGES = [
    ("flask", "3.0.0"),
    ("django", "5.0"),
    ("fastapi", "0.109.0"),
    ("requests", "2.31.0"),
    ("numpy", "1.26.3"),
    ("boto3", "1.34.0"),
    ("pandas", "2.1.4"),
    ("click", "8.1.7"),
    ("pydantic", "2.5.3"),
    ("sqlalchemy", "2.0.25"),
    ("pytest", "7.4.4"),
    ("urllib3", "2.1.0"),
    ("jinja2", "3.1.3"),
    ("certifi", "2023.11.17"),
    ("pyyaml", "6.0.1"),
]

JS_PACKAGES = [
    ("express", "4.18.2"),
    ("react", "18.2.0"),
    ("axios", "1.6.5"),
    ("lodash", "4.17.21"),
    ("typescript", "5.3.3"),
    ("vue", "3.4.5"),
    ("react-dom", "18.2.0"),
    ("webpack", "5.89.0"),
    ("eslint", "8.56.0"),
    ("prettier", "3.1.1"),
    ("jest", "29.7.0"),
    ("chalk", "4.1.2"),
    ("commander", "11.1.0"),
    ("debug", "4.3.4"),
    ("moment", "2.30.1"),
]


def _params(builders, packages):
    """Cross-product builders × packages. xfail-strict builders carry the mark
    on every combination so each missing-parser gap is fully covered."""
    out = []
    for case_id, builder, xfail in builders:
        marks = []
        if xfail:
            marks.append(
                pytest.mark.xfail(
                    strict=True,
                    reason=f"{case_id} not yet supported by CLI parsers — see wiki/plans/extend-cli-packaging-parsers.md",
                )
            )
        for name, version in packages:
            out.append(
                pytest.param(
                    builder, name, version, id=f"{case_id}-{name}", marks=marks
                )
            )
    return out


@pytest.mark.smoke
@pytest.mark.network
@pytest.mark.parametrize(
    "builder, name, version", _params(PY_BUILDERS, PY_PACKAGES)
)
def test_python_build_systems(builder, name, version, tmp_path):
    """Scan a real PyPI package surfaced through each Python build system."""
    pkg_dir = tmp_path / f"{builder.__name__}_{name}"
    pkg_dir.mkdir()
    builder(pkg_dir, name, version)

    sbom_file = tmp_path / f"{name}_sbom.json"
    result = run_ossprey(pkg_dir, output_file=sbom_file, timeout=300)

    assert "No malware found" in result.stdout
    data = assert_sbom_has_components(sbom_file)
    comp_names = [c.get("name", "").lower() for c in data["components"]]
    assert name in comp_names, f"Expected '{name}' in components: {comp_names}"


@pytest.mark.smoke
@pytest.mark.network
@pytest.mark.parametrize(
    "builder, name, version", _params(JS_BUILDERS, JS_PACKAGES)
)
def test_js_build_systems(builder, name, version, tmp_path):
    """Scan a real npm package surfaced through each JS build system."""
    pkg_dir = tmp_path / f"{builder.__name__}_{name}"
    pkg_dir.mkdir()
    builder(pkg_dir, name, version)

    sbom_file = tmp_path / f"{name}_sbom.json"
    result = run_ossprey(pkg_dir, output_file=sbom_file, timeout=300)

    assert "No malware found" in result.stdout
    data = assert_sbom_has_components(sbom_file)
    comp_names = [c.get("name", "").lower() for c in data["components"]]
    assert name in comp_names, f"Expected '{name}' in components: {comp_names}"


# ---------------------------------------------------------------------------
# 7. Real-world GitHub repos
# ---------------------------------------------------------------------------

GITHUB_REPOS = [
    # (repo_url, pre_scan_cmd, expected_component)
    (
        "https://github.com/pallets/click",
        None,
        # click itself won't appear — it's the root package; check a known dep
        "colorama",
    ),
    (
        "https://github.com/expressjs/express",
        ["npm", "install", "--ignore-scripts"],
        # express itself won't appear — it's the root package; check a known dep
        "body-parser",
    ),
    (
        "https://github.com/psf/requests",
        None,
        # requests itself won't appear — it's the root package; check a known dep
        "urllib3",
    ),
]


def _clone_repo(url: str, dest: Path, timeout: int = 120) -> Path:
    """Shallow-clone a GitHub repo."""
    subprocess.run(
        ["git", "clone", "--depth", "1", url, str(dest)],
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return dest


@pytest.mark.smoke
@pytest.mark.slow
@pytest.mark.network
@pytest.mark.parametrize(
    "repo_url, pre_cmd, expected_component",
    GITHUB_REPOS,
    ids=[r[0].split("/")[-1] for r in GITHUB_REPOS],
)
def test_real_world_github_repos(repo_url, pre_cmd, expected_component, tmp_path):
    """Clone a GitHub repo and scan it end-to-end."""
    repo_name = repo_url.rstrip("/").split("/")[-1]
    repo_dir = tmp_path / repo_name

    _clone_repo(repo_url, repo_dir)

    # Run any prerequisite command (e.g. npm install)
    if pre_cmd:
        subprocess.run(
            pre_cmd,
            cwd=str(repo_dir),
            check=True,
            capture_output=True,
            text=True,
            timeout=180,
        )

    sbom_file = tmp_path / f"{repo_name}_sbom.json"
    result = run_ossprey(repo_dir, output_file=sbom_file, timeout=600)

    assert "No malware found" in result.stdout

    data = assert_sbom_has_components(sbom_file)
    comp_names = [c.get("name", "").lower() for c in data["components"]]
    assert (
        expected_component in comp_names
    ), f"Expected '{expected_component}' in components: {comp_names}"


# ---------------------------------------------------------------------------
# 8. Combined scan — verify API path if key is available
# ---------------------------------------------------------------------------


@pytest.mark.smoke
@pytest.mark.network
def test_api_scan_if_key_available(test_packages_dir, tmp_path):
    """If API_KEY is set, run a full API scan on python_simple_math."""
    api_key = os.environ.get("API_KEY")
    if not api_key:
        pytest.skip("API_KEY not set — skipping real API scan test")

    pkg_dir = test_packages_dir / "python_simple_math"
    sbom_file = tmp_path / "api_sbom.json"

    result = run_ossprey(pkg_dir, dry_run=None, output_file=sbom_file)

    assert "No malware found" in result.stdout
    assert_sbom_has_components(sbom_file)

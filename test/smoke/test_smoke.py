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
        "requests",
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

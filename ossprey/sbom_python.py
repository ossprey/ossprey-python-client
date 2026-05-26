from __future__ import annotations
import logging
import subprocess
import json
import os
import re
import sys
import shutil
from pathlib import Path
import tomllib
from packageurl import PackageURL

from ossbom.converters.factory import SBOMConverterFactory
from ossbom.model.ossbom import OSSBOM
from ossbom.model.component import Component

from ossprey.virtualenv import VirtualEnv
from ossprey.exceptions import NotAPoetryProjectError

logger = logging.getLogger(__name__)


def get_cyclonedx_binary() -> str:
    if shutil.which("cyclonedx-py"):
        return "cyclonedx-py"

    venv_bin = Path(sys.executable).parent
    cmd = os.path.join(venv_bin, "cyclonedx-py")
    if os.path.exists(cmd):
        return cmd

    raise FileNotFoundError("cyclonedx-py binary not found.")


def create_sbom_from_requirements(requirements_file: str) -> OSSBOM:

    try:
        cmd = get_cyclonedx_binary()
        # This command generates an SBOM for the active virtual environment in JSON format
        result = subprocess.run(
            [cmd, "requirements", "--sv", "1.5", requirements_file],
            check=True,
            capture_output=True,
            text=True,
            env=os.environ.copy(),
        )

        ret = result.stdout

        cyclone_dict = json.loads(ret)

        ossbom = SBOMConverterFactory.from_cyclonedx_dict(cyclone_dict)

        return ossbom

    except subprocess.CalledProcessError as e:
        logger.error(f"Error running creating SBOM: {e}")
        logger.debug(e.stderr)
        logger.debug("--")
        logger.debug(e.stdout)
        raise e


def update_sbom_from_requirements(ossbom: OSSBOM, requirements_file: str) -> OSSBOM:
    sbom = create_sbom_from_requirements(requirements_file)
    ossbom.add_components(sbom.get_components())

    return ossbom


def create_sbom_from_env() -> OSSBOM:

    try:
        cmd = get_cyclonedx_binary()
        # This command generates an SBOM for the active virtual environment in JSON format
        result = subprocess.run(
            [cmd, "environment", "--sv", "1.5"],
            check=True,
            capture_output=True,
            text=True,
            env=os.environ.copy(),
        )

        ret = result.stdout

        cyclone_dict = json.loads(ret)

        ossbom = SBOMConverterFactory.from_cyclonedx_dict(cyclone_dict)

        return ossbom

    except subprocess.CalledProcessError as e:
        logger.error(f"Error running creating SBOM: {e}")
        logger.debug(e.stderr)
        logger.debug("--")
        logger.debug(e.stdout)
        raise e


def get_poetry_purls_from_lock(lockfile: str = "poetry.lock") -> list[PackageURL]:
    with open(lockfile, "rb") as f:
        lock_data = tomllib.load(f)

    purls = []
    for package in lock_data.get("package", []):
        name = package["name"]
        version = package["version"]
        purl = PackageURL(type="pypi", name=name.lower(), version=version)
        purls.append(purl)

    return purls


def update_sbom_from_poetry(ossbom: OSSBOM, package_dir: str) -> OSSBOM:
    lock_path = os.path.join(package_dir, "poetry.lock")
    if not os.path.exists(lock_path):
        raise NotAPoetryProjectError(
            f"Directory {package_dir} does not contain a poetry.lock file"
        )

    purls = get_poetry_purls_from_lock(lock_path)

    ossbom.add_components(
        [
            Component.create(
                name=purl.name, version=purl.version, source="poetry", type="pypi"
            )
            for purl in purls
        ]
    )

    return ossbom


def get_uv_binary() -> str:
    """Return path to the uv binary.

    uv ships as a Python wheel (declared in this package's dependencies) so it
    lands next to the active Python in the venv's bin/. Fall back to PATH lookup
    so users with a system-wide install also work.
    """
    venv_bin = Path(sys.executable).parent / "uv"
    if venv_bin.exists():
        return str(venv_bin)
    if shutil.which("uv"):
        return "uv"
    raise FileNotFoundError("uv binary not found")


_UV_REQ_LINE = re.compile(r"^([A-Za-z0-9_.\-]+)==([^\s;]+)")


def update_sbom_from_uv(ossbom: OSSBOM, package_dir: str) -> OSSBOM:
    """Resolve full dependency tree for a Python project via `uv pip compile --universal`.

    Universal resolution captures platform-marker-conditional deps (e.g.
    Windows-only colorama) that pip's per-environment resolver excludes.
    Reads pyproject.toml only — does not install, build, or execute project code.
    Works for any PEP 517 build backend (poetry-core, hatchling, setuptools, flit).
    """
    pyproject_path = os.path.join(package_dir, "pyproject.toml")
    if not os.path.exists(pyproject_path):
        raise FileNotFoundError(f"pyproject.toml not found in {package_dir}")

    cmd = [
        get_uv_binary(),
        "pip",
        "compile",
        "--universal",
        "--no-progress",
        pyproject_path,
    ]
    result = subprocess.run(
        cmd,
        check=True,
        capture_output=True,
        text=True,
        env=os.environ.copy(),
    )

    components = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = _UV_REQ_LINE.match(line)
        if not match:
            continue
        name, version = match.group(1), match.group(2)
        components.append(
            Component.create(name=name.lower(), version=version, source="uv", type="pypi")
        )
    ossbom.add_components(components)
    return ossbom


def update_sbom_from_virtualenv(ossbom: OSSBOM, package_name: str) -> OSSBOM:
    venv = VirtualEnv()
    try:
        venv.install_package(package_name)
        requirements_file = venv.create_requirements_file_from_env()

        ossbom = update_sbom_from_requirements(ossbom, requirements_file)
    finally:
        venv.exit()
    return ossbom

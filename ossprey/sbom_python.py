from __future__ import annotations
import logging
import subprocess
import json
import os
import sys
import shutil
from pathlib import Path
import tomllib
from packageurl import PackageURL

from ossbom.converters.factory import SBOMConverterFactory
from ossbom.model.ossbom import OSSBOM
from ossbom.model.component import Component

from ossprey.virtualenv import VirtualEnv

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
            [cmd, "requirements", requirements_file],
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
            [cmd, "environment"],
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


class PoetryNotFoundError(Exception):
    """Raised when poetry command is not available."""

    pass


class NotAPoetryProjectError(Exception):
    """Raised when the directory doesn't contain a valid poetry project."""

    pass


def _is_poetry_project(package_dir: str) -> bool:
    """Check if the directory contains a valid poetry project."""
    pyproject_path = os.path.join(package_dir, "pyproject.toml")
    if not os.path.exists(pyproject_path):
        return False

    try:
        with open(pyproject_path, "rb") as f:
            pyproject_data = tomllib.load(f)

        # Check if poetry is the build backend
        build_backend = pyproject_data.get("build-system", {}).get("build-backend", "")
        if "poetry" in build_backend:
            return True

        # Also check for [tool.poetry] section which indicates a poetry project
        if "tool" in pyproject_data and "poetry" in pyproject_data["tool"]:
            return True

        return False
    except Exception as e:
        logger.debug(f"Error reading pyproject.toml: {e}")
        return False


def update_sbom_from_poetry(ossbom: OSSBOM, package_dir: str) -> OSSBOM:

    if not os.path.exists(os.path.join(package_dir, "poetry.lock")):
        # Check if poetry is installed (only needed when generating poetry.lock)
        if not shutil.which("poetry"):
            raise PoetryNotFoundError("poetry command not found in PATH")
        # Run poetry install to generate the poetry.lock file
        # Note: poetry can handle both poetry-native projects and standard PEP 621 pyproject.toml
        try:
            subprocess.run(
                ["poetry", "install"],
                cwd=package_dir,
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as e:
            # If poetry install fails and this isn't a poetry project, raise a specific error
            if not _is_poetry_project(package_dir):
                raise NotAPoetryProjectError(
                    f"Directory {package_dir} does not contain a valid poetry project "
                    f"and poetry install failed"
                )
            logger.error(f"Error running poetry install: {e}")
            logger.debug(f"stderr: {e.stderr}")
            logger.debug(f"stdout: {e.stdout}")

            raise e

    # Get the packages from the poetry.lock file
    purls = get_poetry_purls_from_lock(os.path.join(package_dir, "poetry.lock"))

    ossbom.add_components(
        [
            Component.create(
                name=purl.name, version=purl.version, source="poetry", type="pypi"
            )
            for purl in purls
        ]
    )

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

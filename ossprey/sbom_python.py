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
            [cmd, 'requirements', requirements_file],
            check=True,
            capture_output=True,
            text=True,
            env=os.environ.copy()
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
            [cmd, 'environment'],
            check=True,
            capture_output=True,
            text=True,
            env=os.environ.copy()
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

    if not os.path.exists(os.path.join(package_dir, "poetry.lock")):
        # Run poetry install to generate the poetry.lock file
        try:
            subprocess.run(['poetry', 'install'], cwd=package_dir, check=True)
        except subprocess.CalledProcessError as e:
            logger.error(f"Error running poetry install: {e}")
            raise e
        
    # Get the packages from the poetry.lock file
    purls = get_poetry_purls_from_lock(os.path.join(package_dir, "poetry.lock"))

    ossbom.add_components([Component.create(name=purl.name, version=purl.version, source="poetry", type="pypi") for purl in purls])

    return ossbom

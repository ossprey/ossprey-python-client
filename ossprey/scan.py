from __future__ import annotations
import json
import logging
import os

from ossprey.environment import get_environment_details
from ossprey.log import init_logging
from ossprey.modes import get_modes, get_all_modes
from ossprey.sbom_python import update_sbom_from_requirements, update_sbom_from_poetry
from ossprey.sbom_javascript import update_sbom_from_npm, update_sbom_from_yarn
from ossprey.sbom_filesystem import update_sbom_from_filesystem
from ossprey.ossprey import Ossprey
from ossprey.virtualenv import VirtualEnv

from ossbom.converters.factory import SBOMConverterFactory
from ossbom.model.ossbom import OSSBOM

logger = logging.getLogger(__name__)


def scan(
    package_name: str,
    mode: str = "auto",
    local_scan: bool = False,
    url: str | None = None,
    api_key: str | None = None,
) -> OSSBOM:

    if mode == "auto":
        logger.debug("Auto mode selected")
        
        # Check the folder for files that map to different package managers
        modes = get_modes(package_name)
        if len(modes) == 0:
            logger.error("No package manager found")
            raise Exception("No package manager found in the directory")
    else:
        modes = [mode]

    logger.info(f"Scanning {package_name} with modes: {modes}")
    # If package location doesn't exist, raise an error
    if not os.path.exists(package_name):
        logger.error(f"Package {package_name} does not exist")
        raise Exception(f"Package {package_name} does not exist")

    sbom = OSSBOM()

    if any(mode not in get_all_modes() for mode in modes) or len(modes) == 0:
        raise Exception("Invalid scanning method: " + str(modes))

    if "pipenv" in modes:
        venv = VirtualEnv()
        venv.enter()

        venv.install_package(package_name)
        requirements_file = venv.create_requirements_file_from_env()

        sbom = update_sbom_from_requirements(sbom, requirements_file)

        venv.exit()

    if "python-requirements" in modes:
        sbom = update_sbom_from_requirements(sbom, package_name + "/requirements.txt")

    if "poetry" in modes:
        sbom = update_sbom_from_poetry(sbom, package_name)

    if "npm" in modes:
        sbom = update_sbom_from_npm(sbom, package_name)

    if "yarn" in modes:
        sbom = update_sbom_from_yarn(sbom, package_name)

    if "fs" in modes:
        sbom = update_sbom_from_filesystem(sbom, package_name)

    # Update sbom to contain the local environment
    env = get_environment_details(package_name)
    sbom.update_environment(env)

    logger.info(f"Scanning {len(sbom.get_components())}")

    if not local_scan:
        ossprey = Ossprey(url, api_key)

        # Compress to MINIBOM
        sbom = SBOMConverterFactory.to_minibom(sbom)

        sbom = ossprey.validate(sbom)
        if not sbom:
            raise Exception("Issue OSSPREY Service")

        # Convert to OSSBOM
        sbom = SBOMConverterFactory.from_minibom(sbom)

    logger.debug(json.dumps(sbom.to_dict(), indent=4))

    return sbom

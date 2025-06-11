import json
import logging
import os
import sys

from ossbom.converters.factory import SBOMConverterFactory

from ossprey.args import parse_arguments
from ossprey.github_actions_reporter import print_gh_action_errors
from ossprey.log import init_logging
from ossprey.sbom_python import update_sbom_from_requirements
from ossprey.sbom_javascript import update_sbom_from_npm, update_sbom_from_yarn
from ossprey.ossprey import Ossprey
from ossprey.virtualenv import VirtualEnv
from ossprey.environment import get_environment_details

from ossbom.model.ossbom import OSSBOM

logger = logging.getLogger(__name__)


def get_modes(directory):
    """
    Get the modes from the directory.
    :param directory: The directory to scan.
    :return: A list of modes.
    """

    # get all files in the directory
    files = [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
    logging.debug(f"Files in directory: {files}")
    modes = []

    # Check for requirements.txt
    if "requirements.txt" in files:
        modes.append("python-requirements")

    npm_files = [
        "package-lock.json",
        "package.json",
        "node_modules"
    ]
    # Check for package.json
    if any(npm_file in files for npm_file in npm_files):
        modes.append("npm")

    # Check for yarn.lock
    if "yarn.lock" in files:
        modes.append("yarn")

    return modes


def scan(package_name, mode="auto", local_scan=False, url=None, api_key=None):

    if mode == "auto":
        logging.debug("Auto mode selected")
        
        # Check the folder for files that map to different package managers
        modes = get_modes(package_name)
        if len(modes) == 0:
            logging.error("No package manager found")
            raise Exception("No package manager found in the directory")
    else:
        modes = [mode]

    # If package location doesn't exist, raise an error
    if not os.path.exists(package_name):
        logging.error(f"Package {package_name} does not exist")
        raise Exception(f"Package {package_name} does not exist")

    sbom = OSSBOM()

    if "pipenv" in modes:
        venv = VirtualEnv()
        venv.enter()

        venv.install_package(package_name)
        requirements_file = venv.create_requirements_file_from_env()

        sbom = update_sbom_from_requirements(sbom, requirements_file)

        venv.exit()
    elif "python-requirements" in modes:
        sbom = update_sbom_from_requirements(sbom, package_name + "/requirements.txt")
    elif "npm" in modes:
        sbom = update_sbom_from_npm(sbom, package_name)
    elif "yarn" in modes:
        sbom = update_sbom_from_yarn(sbom, package_name)
    else:
        raise Exception("Invalid scanning method: " + str(modes))

    # Update sbom to contain the local environment
    env = get_environment_details(package_name)
    sbom.update_environment(env)

    logging.info(f"Scanning {len(sbom.get_components())}")

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

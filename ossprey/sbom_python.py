import logging
import subprocess
import json
import os

from ossbom.converters.factory import SBOMConverterFactory
from ossbom.model.ossbom import OSSBOM

logger = logging.getLogger(__name__)


def create_sbom_from_requirements(requirements_file: str) -> OSSBOM:

    try:
        # This command generates an SBOM for the active virtual environment in JSON format
        result = subprocess.run(
            ['cyclonedx-py', 'requirements', requirements_file],
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
        logging.error(f"Error running creating SBOM: {e}")
        logging.debug(e.stderr)
        logging.debug("--")
        logging.debug(e.stdout)
        raise e


def update_sbom_from_requirements(ossbom: OSSBOM, requirements_file: str) -> OSSBOM:
    sbom = create_sbom_from_requirements(requirements_file)
    ossbom.add_components(sbom.get_components())
    
    return ossbom


def create_sbom_from_env() -> OSSBOM:

    try:
        # This command generates an SBOM for the active virtual environment in JSON format
        result = subprocess.run(
            ['cyclonedx-py', 'environment'],
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
        logging.error(f"Error running creating SBOM: {e}")
        logging.debug(result.stderr)
        logging.debug("--")
        logging.debug(result.stdout)
        raise e

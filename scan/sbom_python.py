import logging
import subprocess
import json
import os
import sys

from cyclonedx.model.bom import Bom
from cyclonedx.schema import SchemaVersion
from cyclonedx.validation.json import JsonStrictValidator

logger = logging.getLogger(__name__)


def create_sbom_from_requirements(requirements_file):

    # Step 1: Use subprocess to run cyclonedx-bom command
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
        # Step 2: Capture the output and load it into memory as a JSON object
        sbom_dict = json.loads(ret)

        # Inspiration from: https://github.com/CycloneDX/cyclonedx-python-lib/blob/main/examples/complex_deserialize.py
        my_json_validator = JsonStrictValidator(SchemaVersion.V1_5)
        validation_errors = my_json_validator.validate_str(ret)

        if validation_errors:
            raise Exception(f"JSON invalid - ValidationError: {repr(validation_errors)}")

        # Inspiration from: https://github.com/CycloneDX/cyclonedx-python-lib/blob/main/examples/complex_deserialize.py
        my_json_validator = JsonStrictValidator(SchemaVersion.V1_5)
        validation_errors = my_json_validator._validata_data(sbom_dict)

        if validation_errors:
            raise Exception(f"JSON invalid DICT - ValidationError: {repr(validation_errors)}")

        return sbom_dict

    except subprocess.CalledProcessError as e:
        logging.error(f"Error running creating SBOM: {e}")
        logging.debug(e.stderr)
        logging.debug("--")
        logging.debug(e.stdout)
        sys.exit(1)


def create_sbom_from_env():

    # Step 1: Use subprocess to run cyclonedx-bom command
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
        # Step 2: Capture the output and load it into memory as a JSON object
        return json.loads(ret)

    except subprocess.CalledProcessError as e:
        logging.error(f"Error running creating SBOM: {e}")
        logging.debug(result.stderr)
        logging.debug("--")
        logging.debug(result.stdout)
        sys.exit(1)


def dict_to_sbom(sbom_dict):
    # Inspiration from: https://github.com/CycloneDX/cyclonedx-python-lib/blob/main/examples/complex_deserialize.py
    my_json_validator = JsonStrictValidator(SchemaVersion.V1_6)
    validation_errors = my_json_validator._validata_data(sbom_dict)

    if validation_errors:
        raise Exception(f"JSON invalid - ValidationError: {repr(validation_errors)}")

    return Bom.from_json(sbom_dict)

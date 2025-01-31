import json
import logging
import sys

from scan.args import parse_arguments
from scan.github_actions_reporter import print_gh_action_errors
from scan.log import init_logging
from scan.sbom_python import create_sbom_from_requirements
from scan.sbom_javascript import create_sbom_from_npm, create_sbom_from_yarn
from scan.ossprey import Ossprey
from scan.virtualenv import VirtualEnv

logger = logging.getLogger(__name__)


def main():

    args = parse_arguments()

    init_logging(args.verbose)

    try:
        package_name = args.package

        mode = args.mode

        if mode == "pipenv":
            venv = VirtualEnv()
            venv.enter()

            venv.install_package(package_name)
            requirements_file = venv.create_requirements_file_from_env()

            sbom = create_sbom_from_requirements(requirements_file)

            venv.exit()
        elif mode == "python-requirements":
            sbom = create_sbom_from_requirements(package_name + "/requirements.txt")
        elif mode == "npm":
            sbom = create_sbom_from_npm(package_name)
        elif mode == "yarn":
            sbom = create_sbom_from_yarn(package_name)
        else:
            raise Exception("Invalid scanning method")

        if not args.dry_run:
            ossprey = Ossprey(args.url, args.api_key)

            sbom = ossprey.validate(sbom)

            if not sbom:
                raise Exception("Issue OSSPREY Service")

        if sbom:
            logger.debug(json.dumps(sbom, indent=4))

            # Process the result
            ret = print_gh_action_errors(sbom, args.package, args.github_comments)

            if not ret:
                raise Exception("Error Malicious Package Found")

    except Exception as e:
        if args.soft_error:
            logger.error(f"Error: {e}")
            logger.error("Failing gracefully")
            return 0
        else:
            logger.error(f"Error: {e}")
            return 1

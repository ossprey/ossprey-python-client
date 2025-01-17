import json
import logging
import sys

from scan.args import parse_arguments
from scan.github_actions_reporter import print_gh_action_errors
from scan.log import init_logging
from scan.sbom import create_sbom_from_requirements
from scan.ossprey import Ossprey
from scan.virtualenv import VirtualEnv

logger = logging.getLogger(__name__)


def main():

    args = parse_arguments()

    init_logging(args.verbose)

    package_name = args.package

    if args.pipenv:
        venv = VirtualEnv()
        venv.enter()

        venv.install_package(package_name)
        requirements_file = venv.create_requirements_file_from_env()

        sbom = create_sbom_from_requirements(requirements_file)

        venv.exit()
    elif args.requirements:
        sbom = create_sbom_from_requirements(package_name + "/requirements.txt")
    else:
        raise Exception("Invalid scanning method")

    if not args.dry_run:
        ossprey = Ossprey(args.url, args.api_key)

        sbom = ossprey.validate(sbom)

        if not sbom:
            logger.error("Error with OSSPREY Service")
            sys.exit(1)

    if sbom:
        logger.debug(json.dumps(sbom, indent=4))

        # Process the result
        ret = print_gh_action_errors(sbom, args.package, args.github_comments)

        if not ret:
            sys.exit(1)

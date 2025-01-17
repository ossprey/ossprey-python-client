import argparse
import os


# Used to pull booleans from env vars
def get_bool(value):
    return value.lower() in ("true", "1", "yes", "on") if value else False


###
# Parse the command line arguments
# Please Note: Everything argument needs a default value otherwise tests will fail
# @return: The parsed arguments
###
def parse_arguments():

    parser = argparse.ArgumentParser(description="API URL:")
    parser.add_argument(
        "--url",
        type=str,
        help="The URL to process",
        default=os.getenv("INPUT_URL", "https://api.ossprey.com")
    )
    parser.add_argument(
        "--package",
        type=str,
        help="The package to scan",
        default=os.getenv("INPUT_PACKAGE", "")
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Dry run mode",
        default=get_bool(os.getenv("INPUT_DRY_RUN"))
    )
    parser.add_argument(
        "--github-comments",
        action="store_true",
        help="GitHub mode, will attempt to post comments to GitHub",
        default=get_bool(os.getenv("INPUT_GITHUB_COMMENTS"))
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Verbose mode",
        default=get_bool(os.getenv("INPUT_VERBOSE"))
    )

    # Scanning methods
    parser.add_argument(
        '--pipenv',
        action='store_true',
        help="Install the package to generate the SBOM.",
        default=get_bool(os.getenv("INPUT_PIPENV"))
    )
    parser.add_argument(
        '--requirements',
        action='store_true',
        help="Path to the requirements file to generate the SBOM.",
        default=get_bool(os.getenv("INPUT_REQUIREMENTS"))
    )

    # Authentication
    parser.add_argument(
        '--api-key',
        type=str,
        help="API Key to authenticate with the API, this can also be set via the OSSPREY_API_KEY environment variable.",
        default=os.getenv("API_KEY")
    )

    args = parser.parse_args()

    # Validate mutual exclusivity for environment variables and CLI
    if args.pipenv and args.requirements:
        parser.error("Arguments --pipenv and --requirements are mutually exclusive. Set only one.")

    if not args.pipenv and not args.requirements:
        parser.error("One of --pipenv or --requirements must be provided, either as a CLI argument or via environment variables.")

    return args

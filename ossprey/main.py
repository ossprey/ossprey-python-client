import logging
import sys

from ossprey.args import parse_arguments
from ossprey.github_actions_reporter import print_gh_action_errors
from ossprey.log import init_logging
from ossprey.scan import scan

logger = logging.getLogger(__name__)


def main() -> None:

    args = parse_arguments()

    init_logging(args.verbose)

    try:

        sbom = scan(
             args.package, 
             mode=args.mode, 
             local_scan=args.dry_run, 
             url=args.url, 
             api_key=args.api_key
            )    

        if sbom:

            # Process the result
            ret = print_gh_action_errors(sbom, args.package, args.github_comments)

            if not ret:
                raise Exception("Error Malicious Package Found")
    
        sys.exit(0)

    except Exception as e:

        # Print the full stack trace
        logger.exception(e)

        if args.soft_error:
            logger.error(f"Error: {e}")
            logger.error("Failing gracefully")
            sys.exit(0)
        else:
            logger.error(f"Error: {e}")
            sys.exit(1)




from __future__ import annotations
import json
import logging
import sys

from ossprey.args import parse_arguments
from ossprey.exceptions import MaliciousPackageException, ScanSkippedException
from ossprey.github_actions_reporter import print_gh_action_errors, report_scan_skipped
from ossprey.log import init_logging
from ossprey.ossprey import Ossprey
from ossprey.scan import scan
from ossprey.utils import format_quota_usage

logger = logging.getLogger(__name__)


def main() -> None:

    args = parse_arguments()

    init_logging(args.verbose)

    try:
        local_scan = None
        client = None
        
        if args.dry_run_safe:
            local_scan = "dry-run-safe"
        elif args.dry_run_malicious:
            local_scan = "dry-run-malicious"
        else:
            # Only create the client when doing a real API scan
            client = Ossprey(args.url, args.api_key)

        sbom = scan(
            args.package,
            mode=args.mode,
            local_scan=local_scan,
            client=client,
            url=args.url,
            api_key=args.api_key
        )

        if sbom:

            if args.output:
                with open(args.output, "w") as f:
                    json.dump(sbom.to_dict(), f, indent=2)

            # Process the result
            ret = print_gh_action_errors(sbom, args.package, args.github_comments)

            if args.verbose and client:
                quota = client.get_usage()
                if quota:
                    logger.info(format_quota_usage(quota))

            if not ret:
                raise MaliciousPackageException("Error Malicious Package Found")

        sys.exit(0)

    except ScanSkippedException as e:
        report_scan_skipped(e.message, e.reset_at, args.github_comments)
        sys.exit(0)

    except Exception as e:
        # Print the full stack trace
        if args.verbose:
            logger.exception(e)

        if args.soft_error:
            logger.error(f"Error: {e}")
            logger.error("Failing gracefully")
            sys.exit(0)
        else:
            logger.error(f"Error: {e}")
            sys.exit(1)

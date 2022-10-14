"""
Copyright 2017-present Airbnb, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
import re

from streamalert.shared.logger import get_logger
from streamalert.threat_intel_downloader.main import ThreatStream
from streamalert_cli.helpers import save_parameter, user_input
from streamalert_cli.utils import (CLICommand, UniqueSortedListAction,
                                   add_memory_arg, add_schedule_expression_arg,
                                   add_timeout_arg, generate_subparser)

LOGGER = get_logger(__name__)


class ThreatIntelDownloaderCommand(CLICommand):
    description = 'Configure and update the threat intel downloader'

    @classmethod
    def setup_subparser(cls, subparser):
        """Add threat intel downloader subparser: manage.py threat-intel-downloader [subcommand]"""
        ti_subparsers = subparser.add_subparsers(dest='threat-intel-downloader subcommand',
                                                 required=True)

        cls._setup_threat_intel_configure_subparser(ti_subparsers)
        cls._setup_threat_intel_auth_subparser(ti_subparsers)

    @staticmethod
    def _setup_threat_intel_configure_subparser(subparsers):
        """Add threat intel downloader configure subparser

        manage.py threat-intel-downloader configure [options]
        """
        ti_downloader_configure_parser = generate_subparser(
            subparsers,
            'configure',
            description='Enable, disable, or configure the threat intel downloader function',
            subcommand=True)

        # Enable/Disable toggle group
        toggle_group = ti_downloader_configure_parser.add_mutually_exclusive_group(required=False)

        toggle_group.add_argument('-e',
                                  '--enable',
                                  dest='enable_threat_intel_downloader',
                                  help='Enable the threat intel downloader function',
                                  action='store_true')

        toggle_group.add_argument('-d',
                                  '--disable',
                                  dest='enable_threat_intel_downloader',
                                  help='Disable the threat intel downloader function',
                                  action='store_false')

        # Function schedule expression (rate) arg
        add_schedule_expression_arg(ti_downloader_configure_parser)

        # Function timeout arg
        add_timeout_arg(ti_downloader_configure_parser)

        # Function memory arg
        add_memory_arg(ti_downloader_configure_parser)

        ti_downloader_configure_parser.add_argument(
            '-r',
            '--table-rcu',
            help='Read capacity units to use for the DynamoDB table',
            type=int,
            default=10)

        ti_downloader_configure_parser.add_argument(
            '-w',
            '--table-wcu',
            help='Write capacity units to use for the DynamoDB table',
            type=int,
            default=10)

        ti_downloader_configure_parser.add_argument(
            '-k',
            '--ioc-keys',
            help='One or more IOC keys to store in DynamoDB table',
            nargs='+',
            action=UniqueSortedListAction,
            default=['expiration_ts', 'itype', 'source', 'type', 'value'])

        ti_downloader_configure_parser.add_argument(
            '-f',
            '--ioc-filters',
            help='One or more filters to apply when retrieving IOCs from Threat Feed',
            nargs='+',
            action=UniqueSortedListAction,
            default=['crowdstrike', '@airbnb.com'])

        ti_downloader_configure_parser.add_argument(
            '-i',
            '--ioc-types',
            help='One or more IOC type defined by the Threat Feed. IOC types can vary by feed',
            nargs='+',
            action=UniqueSortedListAction,
            default=['domain', 'ip', 'md5'])

        ti_downloader_configure_parser.add_argument(
            '-x',
            '--excluded-sub-types',
            help='IOC subtypes to be excluded',
            action=UniqueSortedListAction,
            default=['bot_ip', 'brute_ip', 'scan_ip', 'spam_ip', 'tor_ip'])

        ti_downloader_configure_parser.add_argument(
            '-a',
            '--autoscale',
            help='Enable auto scaling for the threat intel DynamoDB table',
            default=False,
            action='store_true')

        ti_downloader_configure_parser.add_argument(
            '--max-read-capacity',
            help='Maximum read capacity to use when auto scaling is enabled',
            type=int,
            default=5)

        ti_downloader_configure_parser.add_argument(
            '--min-read-capacity',
            help='Minimum read capacity to use when auto scaling is enabled',
            type=int,
            default=5)

        ti_downloader_configure_parser.add_argument(
            '-u',
            '--target-utilization',
            help=('Target percentage of consumed provisioned throughput at a point in time '
                  'to use for auto-scaling the read capacity units'),
            type=int,
            default=70)

    @staticmethod
    def _setup_threat_intel_auth_subparser(subparsers):
        """Add threat intel downloader update-auth subparser

        manage.py threat-intel-downloader update-auth
        """
        generate_subparser(
            subparsers,
            'update-auth',
            description='Enable, disable, or configure the threat intel downloader function',
            subcommand=True)

    @classmethod
    def handler(cls, options, config):
        """Configure Threat Intel Downloader from command line

        Args:
            options (argparse.Namespace): Parsed arguments
            config (CLIConfig): Loaded StreamAlert config

        Returns:
            bool: False if errors occurred, True otherwise
        """
        def _validate_options(options):
            if not options.interval:
                LOGGER.error('Missing command line argument --interval')
                return False

            if not options.timeout:
                LOGGER.error('Missing command line argument --timeout')
                return False

            if not options.memory:
                LOGGER.error('Missing command line argument --memory')
                return False

            return True

        if not options:
            return False

        if options.subcommand == 'enable':
            if not _validate_options(options):
                return False
            if config.add_threat_intel_downloader(vars(options)):
                return save_api_creds_info(config['global']['account']['region'])
        elif options.subcommand == 'update-auth':
            return save_api_creds_info(config['global']['account']['region'], overwrite=True)


def save_api_creds_info(region, overwrite=False):
    """Function to add API creds information to parameter store

    Args:
        info (dict): Required values needed to save the requested credentials
            information to AWS Parameter Store
    """
    # Get all of the required credentials from the user for API calls
    required_creds = {
        'api_user': {
            'description': ('API username to retrieve IOCs via API calls. '
                            'This should be an email address.'),
            'format':
            re.compile(r'^[a-zA-Z].*@.*')
        },
        'api_key': {
            'description': ('API key to retrieve IOCs via API calls. '
                            'This should be a string of 40 alphanumeric characters.'),
            'format':
            re.compile(r'^[a-zA-Z0-9]{40}$')
        }
    }

    creds_dict = {
        auth_key: user_input(info['description'], False, info['format'])
        for auth_key, info in required_creds.items()
    }

    description = ('Required credentials for the Threat Intel Downloader')

    # Save these to the parameter store
    saved = save_parameter(region, ThreatStream.CRED_PARAMETER_NAME, creds_dict, description,
                           overwrite)
    if saved:
        LOGGER.info('Threat Intel Downloader credentials were successfully '
                    'saved to parameter store.')
    else:
        LOGGER.error('Threat Intel Downloader credentials were not saved to '
                     'parameter store.')

    return saved

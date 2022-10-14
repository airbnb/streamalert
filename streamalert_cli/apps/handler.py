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
import string

from streamalert.apps import StreamAlertApp
from streamalert.shared.logger import get_logger
from streamalert_cli.apps.helpers import save_app_auth_info
from streamalert_cli.utils import (CLUSTERS, CLICommand, add_memory_arg,
                                   add_schedule_expression_arg,
                                   add_timeout_arg, generate_subparser,
                                   set_parser_epilog)

LOGGER = get_logger(__name__)


class AppCommand(CLICommand):
    description = 'Create, list, or update a StreamAlert app to poll logs from various services'

    @classmethod
    def setup_subparser(cls, subparser):
        """Add the app integration subparser: manage.py app [subcommand] [options]"""
        app_subparsers = subparser.add_subparsers(dest='app subcommand', required=True)

        cls._setup_app_list_subparser(app_subparsers)
        cls._setup_app_new_subparser(app_subparsers)
        cls._setup_app_update_auth_subparser(app_subparsers)

    @staticmethod
    def _setup_app_list_subparser(subparsers):
        """Add the app list subparser: manage.py app list"""
        generate_subparser(subparsers,
                           'list',
                           description='List all configured app functions, grouped by cluster',
                           subcommand=True)

    @classmethod
    def _setup_app_new_subparser(cls, subparsers):
        """Add the app new subparser: manage.py app new [options]"""
        app_new_parser = generate_subparser(
            subparsers,
            'new',
            description='Create a new StreamAlert app to poll logs from various services',
            subcommand=True)

        set_parser_epilog(app_new_parser,
                          epilog=('''\
                Example:

                    manage.py app new \\
                      duo_auth \\
                      --cluster prod \\
                      --name duo_prod_collector \\
                      --schedule-expression 'rate(2 hours)' \\
                      --timeout 60 \\
                      --memory 256
                '''))

        cls._add_default_app_args(app_new_parser)

        app_types = sorted(StreamAlertApp.get_all_apps())

        # App type options
        app_new_parser.add_argument('type',
                                    choices=app_types,
                                    metavar='APP_TYPE',
                                    help=f"Type of app being configured: {', '.join(app_types)}")

        # Function schedule expression (rate) arg
        add_schedule_expression_arg(app_new_parser)

        # Function timeout arg
        add_timeout_arg(app_new_parser)

        # Function memory arg
        add_memory_arg(app_new_parser)

    @classmethod
    def _setup_app_update_auth_subparser(cls, subparsers):
        """Add the app update-auth subparser: manage.py app update-auth [options]"""
        app_update_parser = generate_subparser(
            subparsers,
            'update-auth',
            description='Update the authentication information for an existing app',
            subcommand=True)

        set_parser_epilog(app_update_parser,
                          epilog=('''\
                Example:

                    manage.py app update-auth \\
                      --cluster prod \\
                      --name duo_prod_collector
                '''))

        cls._add_default_app_args(app_update_parser)

    @staticmethod
    def _add_default_app_args(app_parser):
        """Add the default arguments to the app integration parsers"""

        # App integration cluster options
        app_parser.add_argument('-c',
                                '--cluster',
                                choices=CLUSTERS,
                                required=True,
                                help='Cluster to perform this action against')

        # Validate the name being used to make sure it does not contain specific characters
        def _validate_name(val):
            """Validate acceptable inputs for the name of the function"""
            acceptable_chars = ''.join([string.digits, string.ascii_lowercase, '_-'])
            if not set(str(val)).issubset(acceptable_chars):
                raise app_parser.error('Name must contain only lowercase letters, numbers, '
                                       'hyphens, or underscores.')

            return val

        # App integration name to be used for this instance that must be unique per cluster
        app_parser.add_argument('-n',
                                '--name',
                                dest='app_name',
                                required=True,
                                help='Unique name for this app',
                                type=_validate_name)

    @classmethod
    def handler(cls, options, config):
        """Perform app related functions

        Args:
            options (argparse.Namespace): Parsed arguments with info to configure a new app
                or update an existing one
            config (CLIConfig): Loaded StreamAlert config

        Returns:
            bool: False if errors occurred, True otherwise
        """
        if not options:
            return False

        # List all of the available app integrations, broken down by cluster
        if options.subcommand == 'list':
            all_info = {
                cluster: cluster_config['modules'].get('streamalert_apps')
                for cluster, cluster_config in config['clusters'].items()
            }

            for cluster, info in all_info.items():
                print(f'\nCluster: {cluster}\n')
                if not info:
                    print('\tNo Apps configured\n')
                    continue

                for name, details in info.items():
                    print(f'\tName: {name}')
                    print('\n'.join([
                        '\t\t{key}:{padding_char:<{padding_count}}{value}'.format(key=key_name,
                                                                                  padding_char=' ',
                                                                                  padding_count=30 -
                                                                                  (len(key_name)),
                                                                                  value=value)
                        for key_name, value in details.items()
                    ] + ['\n']))
            return True

        # Convert the options to a dict
        app_info = vars(options)

        # Add the region and prefix for this StreamAlert instance to the app info
        app_info['region'] = str(config['global']['account']['region'])
        app_info['prefix'] = str(config['global']['account']['prefix'])

        # Create a new app integration function
        if options.subcommand == 'new':
            function_name = '_'.join([
                app_info['prefix'], app_info['cluster'], app_info['type'], app_info['app_name'],
                'app'
            ])

            return config.add_app(function_name, app_info)

        # Update the auth information for an existing app integration function
        if options.subcommand == 'update-auth':
            cluster_config = config['clusters'][app_info['cluster']]
            apps = cluster_config['modules'].get('streamalert_apps', {})
            if not apps:
                LOGGER.error('No apps configured for cluster \'%s\'', app_info['cluster'])
                return False

            func_name = next((function_name for function_name, app_config in apps.items()
                              if app_config.get('app_name') == app_info['app_name']), None)

            if not func_name:
                LOGGER.error('App with name \'%s\' does not exist for cluster \'%s\'',
                             app_info['app_name'], app_info['cluster'])
                return False

            # Get the type for this app integration from the current
            # config so we can update it properly
            app_info['type'] = cluster_config['modules']['streamalert_apps'][func_name]['type']

            app = StreamAlertApp.get_app(app_info['type'])

            return bool(save_app_auth_info(app, app_info, func_name, True))

"""
Copyright 2017-present, Airbnb Inc.

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
from stream_alert.apps import StreamAlertApp
from stream_alert.shared.logger import get_logger
from stream_alert_cli.apps.helpers import save_app_auth_info

LOGGER = get_logger(__name__)


def app_handler(options, config):
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
            cluster: cluster_config['modules'].get('stream_alert_apps')
            for cluster, cluster_config in config['clusters'].iteritems()
        }

        for cluster, info in all_info.iteritems():
            print '\nCluster: {}\n'.format(cluster)
            if not info:
                print '\tNo Apps configured\n'
                continue

            for name, details in info.iteritems():
                print '\tName: {}'.format(name)
                print '\n'.join([
                    '\t\t{key}:{padding_char:<{padding_count}}{value}'.format(
                        key=key_name,
                        padding_char=' ',
                        padding_count=30 - (len(key_name)),
                        value=value) for key_name, value in details.iteritems()
                ] + ['\n'])
        return True

    # Convert the options to a dict
    app_info = vars(options)

    # Add the region and prefix for this StreamAlert instance to the app info
    app_info['region'] = str(config['global']['account']['region'])
    app_info['prefix'] = str(config['global']['account']['prefix'])

    # Create a new app integration function
    if options.subcommand == 'new':
        function_name = '_'.join([
            app_info['prefix'],
            app_info['cluster'],
            app_info['type'],
            app_info['app_name'],
            'app'
        ])

        return config.add_app(function_name, app_info)

    # Update the auth information for an existing app integration function
    if options.subcommand == 'update-auth':
        cluster_config = config['clusters'][app_info['cluster']]
        apps = cluster_config['modules'].get('stream_alert_apps', {})
        if not apps:
            LOGGER.error('No apps configured for cluster \'%s\'', app_info['cluster'])
            return False

        # Find the appropriate function config for this app
        func_name = None
        for function_name, app_config in apps.iteritems():
            if app_config.get('app_name') == app_info['app_name']:
                func_name = function_name
                break

        if not func_name:
            LOGGER.error('App with name \'%s\' does not exist for cluster \'%s\'',
                         app_info['app_name'], app_info['cluster'])
            return False

        # Get the type for this app integration from the current
        # config so we can update it properly
        app_info['type'] = cluster_config['modules']['stream_alert_apps'][func_name]['type']

        app = StreamAlertApp.get_app(app_info['type'])

        if not save_app_auth_info(app, app_info, func_name, True):
            return False

        return True

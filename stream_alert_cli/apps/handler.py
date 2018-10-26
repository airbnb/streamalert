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
from stream_alert_cli.apps.helpers import save_app_auth_info
from stream_alert_cli.logger import LOGGER_CLI


def app_handler(options, config):
    """Perform app related functions

    Args:
        options (argparse.Namespace): Contains all of the necessary info for configuring
            a new app integration or updating an existing one
    """
    if not options:
        return

    # Convert the options to a dict
    app_info = vars(options)

    # Add the region and prefix for this StreamAlert instance to the app info
    app_info['region'] = str(config['global']['account']['region'])
    app_info['prefix'] = str(config['global']['account']['prefix'])

    # Function name follows the format: '<prefix>_<cluster>_<service>_<app_name>_app
    func_parts = ['prefix', 'cluster', 'type', 'app_name']

    # Create a new app integration function
    if options.subcommand == 'new':
        app_info['function_name'] = '_'.join([app_info.get(value)
                                              for value in func_parts] + ['app'])

        config.add_app(app_info)
        return

    # Update the auth information for an existing app integration function
    if options.subcommand == 'update-auth':
        cluster_config = config['clusters'][app_info['cluster']]
        if not app_info['app_name'] in cluster_config['modules'].get('stream_alert_apps', {}):
            LOGGER_CLI.error('App integration with name \'%s\' does not exist for cluster \'%s\'',
                             app_info['app_name'], app_info['cluster'])
            return

        # Get the type for this app integration from the current
        # config so we can update it properly
        app_info['type'] = cluster_config['modules']['stream_alert_apps'] \
                                         [app_info['app_name']]['type']

        app_info['function_name'] = '_'.join([app_info.get(value)
                                              for value in func_parts] + ['app'])

        app = StreamAlertApp.get_app(app_info['type'])

        if not save_app_auth_info(app, app_info, True):
            return

        return

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

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
from collections import OrderedDict
import json
import os
import re

from stream_alert.shared import metrics
from stream_alert_cli.helpers import continue_prompt
from stream_alert_cli.logger import LOGGER_CLI


class CLIConfigError(Exception):
    pass

class CLIConfig(object):
    """A class to load, modify, and display the StreamAlertCLI Config"""
    DEFAULT_CONFIG_PATH = 'conf'

    def __init__(self, **kwargs):
        self.config_path = kwargs.get('config_path', self.DEFAULT_CONFIG_PATH)
        self.config = {'clusters': {}}
        self.load()

    def __repr__(self):
        return str(self.config)

    def __getitem__(self, key):
        return self.config[key]

    def __setitem__(self, key, new_value):
        self.config.__setitem__(key, new_value)
        self.write()

    def get(self, key):
        """Lookup a value based on its key"""
        return self.config.get(key)

    def keys(self):
        """Config keys"""
        return self.config.keys()

    def clusters(self):
        """Return list of cluster configuration keys"""
        return self.config['clusters'].keys()

    def generate_athena(self):
        """Generate a base Athena config"""
        if 'athena_partition_refresh_config' in self.config['lambda']:
            LOGGER_CLI.warn('The Athena configuration already exists, skipping.')
            return

        athena_config_template = {
            'enabled': True,
            'enable_metrics': False,
            'current_version': '$LATEST',
            'refresh_type': {
                'add_hive_partition': {},
                'repair_hive_table': {}
            },
            'handler': 'stream_alert.athena_partition_refresh.main.handler',
            'timeout': '60',
            'memory': '128',
            'log_level': 'info',
            'source_bucket': 'PREFIX_GOES_HERE.streamalert.source',
            'source_current_hash': '<auto_generated>',
            'source_object_key': '<auto_generated>',
            'third_party_libraries': [
                'backoff'
            ]
        }

        # Check if the prefix has ever been set
        if self.config['global']['account']['prefix'] != 'PREFIX_GOES_HERE':
            athena_config_template['source_bucket'] = self.config['lambda'] \
                ['rule_processor_config']['source_bucket']

        self.config['lambda']['athena_partition_refresh_config'] = athena_config_template
        self.write()

        LOGGER_CLI.info('Athena configuration successfully created')

    def set_athena_lambda_enable(self):
        """Enable athena partition refreshes"""
        if 'athena_partition_refresh_config' not in self.config['lambda']:
            LOGGER_CLI.error('No configuration found for Athena Partition Refresh. '
                             'Please run: $ python manage.py athena init')
            return

        self.config['lambda']['athena_partition_refresh_config']['enabled'] = True
        self.write()

        LOGGER_CLI.info('Athena configuration successfully enabled')

    def set_prefix(self, prefix):
        """Set the Org Prefix in Global settings"""
        if not isinstance(prefix, (unicode, str)):
            LOGGER_CLI.error('Invalid prefix type, must be string')
            return

        self.config['global']['account']['prefix'] = prefix
        self.config['global']['terraform']['tfstate_bucket'] = self.config['global']['terraform'][
            'tfstate_bucket'].replace('PREFIX_GOES_HERE', prefix)

        self.config['lambda']['alert_processor_config']['source_bucket'] = self.config['lambda'][
            'alert_processor_config']['source_bucket'].replace('PREFIX_GOES_HERE', prefix)
        self.config['lambda']['rule_processor_config']['source_bucket'] = self.config['lambda'][
            'rule_processor_config']['source_bucket'].replace('PREFIX_GOES_HERE', prefix)
        self.write()

        LOGGER_CLI.info('Prefix successfully configured')

    def set_aws_account_id(self, aws_account_id):
        """Set the AWS Account ID in Global settings"""
        if not re.search(r'\A\d{12}\Z', aws_account_id):
            LOGGER_CLI.error('Invalid AWS Account ID, must be 12 digits long')
            return

        self.config['global']['account']['aws_account_id'] = aws_account_id
        self.write()

        LOGGER_CLI.info('AWS Account ID successfully configured')

    def toggle_metrics(self, enabled, clusters, lambda_functions):
        """Toggle CloudWatch metric logging and filter creation

        Args:
            enabled (bool): False if disabling metrics, true if enable_logging
            clusters (list): Clusters to enable or disable metrics on
            lambda_functions (list): Which lambda functions to enable or disable
                metrics on (rule, alert, or athena)
        """
        for function in lambda_functions:
            if function == metrics.ATHENA_PARTITION_REFRESH_NAME:
                if 'athena_partition_refresh_config' in self.config['lambda']:
                    self.config['lambda']['athena_partition_refresh_config'] \
                        ['enable_metrics'] = enabled
                else:
                    LOGGER_CLI.error('No Athena configuration found; please initialize first.')
                continue

            for cluster in clusters:
                self.config['clusters'][cluster]['modules']['stream_alert'] \
                    [function]['enable_metrics'] = enabled

        self.write()

    @staticmethod
    def _add_metric_alarm_config(alarm_info, current_alarms):
        """Helper function to add the metric alarm to the respective config

        Args:
            alarm_info (dict): All the necessary values needed to add a CloudWatch
                metric alarm
            current_alarms (dict): All of the current metric alarms from the config

        Returns:
            dict: The new metric alarms dictionary with the added metric alarm
        """
        # Some keys that come from the argparse options can be omitted
        omitted_keys = {'debug', 'alarm_name', 'command', 'clusters', 'metric_target'}

        current_alarms[alarm_info['alarm_name']] = {
            key: value for key, value in alarm_info.iteritems()
            if key not in omitted_keys
        }

        return current_alarms

    def _add_metric_alarm_per_cluster(self, alarm_info, function_name):
        """Add a metric alarm for individual clusters. This is for non-aggregate
        CloudWatch metric alarms.

        Args:
            alarm_info (dict): All the necessary values needed to add a CloudWatch
                metric alarm.
            function_name (str): The name of the lambda function this metric is
                related to.
        """
        # If no clusters have been specified by the user, we can assume this alarm
        # should be created for all available clusters, so fall back to that
        clusters = (alarm_info['clusters'] if alarm_info['clusters'] else
                    list(self.config['clusters']))

        # Go over each of the clusters and see if enable_metrics == True and prompt
        # the user to toggle metrics on if this is False
        for cluster in clusters:
            function_config = (self.config['clusters'][cluster]['modules']
                               ['stream_alert'][function_name])

            if not function_config.get('enable_metrics'):
                prompt = ('Metrics are not currently enabled for the \'{}\' function '
                          'within the \'{}\' cluster. Would you like to enable metrics '
                          'for this cluster?'.format(function_name, cluster))

                if continue_prompt(prompt):
                    self.toggle_metrics(True, [cluster], [function_name])

                elif not continue_prompt('Would you still like to add this alarm '
                                         'even though metrics are disabled?'):
                    continue

            metric_alarms = function_config.get('metric_alarms', {})

            # Format the metric name for the cluster based metric
            # Prepend a prefix for this function and append the cluster name
            alarm_settings = alarm_info.copy()
            alarm_settings['metric_name'] = '{}-{}-{}'.format(metrics.FUNC_PREFIXES[function_name],
                                                              alarm_settings['metric_name'],
                                                              cluster.upper())

            new_alarms = self._add_metric_alarm_config(alarm_settings, metric_alarms)
            if new_alarms != False:
                function_config['metric_alarms'] = new_alarms
                LOGGER_CLI.info('Successfully added \'%s\' metric alarm for the \'%s\' '
                                'function to \'conf/clusters/%s.json\'.',
                                alarm_settings['alarm_name'], function_name, cluster)

    def _alarm_exists(self, alarm_name):
        """Check if this alarm name is already used somewhere. CloudWatch alarm
        names must be unique to an AWS account

        Args:
            alarm_name (str): The name of the alarm being created

        Returns:
            bool: True if the the alarm name is already present in the config
        """
        message = ('CloudWatch metric alarm names must be unique '
                   'within each AWS account. Please remove this alarm '
                   'so it can be updated or choose another name.')
        funcs = {metrics.ALERT_PROCESSOR_NAME, metrics.RULE_PROCESSOR_NAME}
        for func in funcs:
            for cluster in self.config['clusters']:
                func_alarms = (self.config['clusters'][cluster]['modules']
                               ['stream_alert'][func].get('metric_alarms', {}))
                if alarm_name in func_alarms:
                    LOGGER_CLI.error('An alarm with name \'%s\' already exists in the '
                                     '\'conf/clusters/%s.json\' cluster. %s', alarm_name,
                                     cluster, message)
                    return True

        global_config = self.config['global']['infrastructure'].get('monitoring')
        if not global_config:
            return False

        metric_alarms = global_config.get('metric_alarms')
        if not metric_alarms:
            return False

        # Check for athena metric alarms also, which are save in the global config
        funcs.add(metrics.ATHENA_PARTITION_REFRESH_NAME)

        for func in funcs:
            global_func_alarms = global_config['metric_alarms'].get(func, {})
            if alarm_name in global_func_alarms:
                LOGGER_CLI.error('An alarm with name \'%s\' already exists in the '
                                 '\'conf/globals.json\'. %s', alarm_name, message)
                return True

        return False

    def add_metric_alarm(self, alarm_info):
        """Add a metric alarm that corresponds to a predefined metrics

        Args:
            alarm_info (dict): All the necessary values needed to add a CloudWatch
                metric alarm
        """
        # Check to see if an alarm with this name already exists
        if self._alarm_exists(alarm_info['alarm_name']):
            return

        # Get the current metrics for each function
        current_metrics = metrics.MetricLogger.get_available_metrics()

        # Extract the function name this metric is associated with
        metric_function = {metric: function for function in current_metrics
                           for metric in current_metrics[function]}[alarm_info['metric_name']]

        # Do not continue if the user is trying to apply a metric alarm for an athena
        # metric to a specific cluster (since the athena function operates on all clusters)
        if (alarm_info['metric_target'] != 'aggregate' and
                metric_function == metrics.ATHENA_PARTITION_REFRESH_NAME):
            LOGGER_CLI.error('Metrics for the athena function can only be applied '
                             'to an aggregate metric target, not on a per-cluster basis.')
            return

        # If the metric is related to either the rule processor or alert processor, we should
        # check to see if any cluster has metrics enabled for that function before continuing
        if (metric_function in {metrics.ALERT_PROCESSOR_NAME, metrics.RULE_PROCESSOR_NAME} and
                not any(self.config['clusters'][cluster]['modules']['stream_alert']
                        [metric_function].get('enable_metrics') for cluster in
                        self.config['clusters'])):
            prompt = ('Metrics are not currently enabled for the \'{}\' function '
                      'within any cluster. Creating an alarm will have no effect '
                      'until metrics are enabled for this function in at least one '
                      'cluster. Would you still like to continue?'.format(metric_function))
            if not continue_prompt(prompt):
                return

        elif metric_function == metrics.ATHENA_PARTITION_REFRESH_NAME:
            # If the user is attempting to add a metric for athena, make sure the athena
            # function is initialized first
            if 'athena_partition_refresh_config' not in self.config['lambda']:
                LOGGER_CLI.error('No configuration found for Athena Partition Refresh. '
                                 'Please run: `$ python manage.py athena init` first.')
                return

            # If the athena function is initialized, but metrics are not enabled, ask
            # the user if they would like to enable them now
            if not self.config['lambda']['athena_partition_refresh_config'].get('enable_metrics'):
                prompt = ('Metrics are not currently enabled for the \'athena\' function. '
                          'Would you like to enable metrics for athena?')

                if continue_prompt(prompt):
                    self.toggle_metrics(True, None, [metric_function])

                elif not continue_prompt('Would you still like to add this alarm '
                                         'even though metrics are disabled?'):
                    return

        # Add metric alarms for the aggregate metrics - these are added to the global config
        if (alarm_info['metric_target'] == 'aggregate' or
                metric_function == metrics.ATHENA_PARTITION_REFRESH_NAME):
            global_config = self.config['global']['infrastructure']['monitoring']

            metric_alarms = global_config.get('metric_alarms', {})
            if not metric_alarms:
                global_config['metric_alarms'] = {}

            metric_alarms = global_config['metric_alarms'].get(metric_function, {})
            if not metric_alarms:
                global_config['metric_alarms'][metric_function] = {}

            # Format the metric name for the aggregate metric
            alarm_settings = alarm_info.copy()
            alarm_settings['metric_name'] = '{}-{}'.format(metrics.FUNC_PREFIXES[metric_function],
                                                           alarm_info['metric_name'])

            new_alarms = self._add_metric_alarm_config(alarm_settings, metric_alarms)
            if new_alarms != False:
                global_config['metric_alarms'][metric_function] = new_alarms
                LOGGER_CLI.info('Successfully added \'%s\' metric alarm to '
                                '\'conf/global.json\'.', alarm_settings['alarm_name'])

        else:
            # Add metric alarms on a per-cluster basis - these are added to the cluster config
            self._add_metric_alarm_per_cluster(alarm_info, metric_function)

        # Save all of the alarm updates to disk
        self.write()

    def load(self):
        """Load the cluster, global, and lambda configuration files

        Args:
            key (str): The key in the config dictionary to place the loaded
                config file.
            file_path (str): The location on disk to load the config file.

        Keyword Arguments:
            cluster_file (bool): If the file to load is a cluster file.
        """
        # This accounts for non files passed in, such as a
        # directory from os.listdir()
        if not os.path.isfile(file_path):
            return

        with open(file_path) as data:
            try:
                if kwargs.get('cluster_file', False):
                    self.config['clusters'][key] = json.load(data)
                else:
                    # For certain log types (csv), the order of the schema
                    # must be retained.  By loading as an OrderedDict,
                    # the configuration is gauaranteed to keep its order.
                    if key == 'logs':
                        self.config[key] = json.load(data,
                                                     object_pairs_hook=OrderedDict)
                    else:
                        self.config[key] = json.load(data)
            except ValueError:
                raise CLIConfigError('[Config Error]: %s is not valid JSON', file_path)

    @staticmethod
    def _config_writer(config, path, **kwargs):
        with open(path, 'r+') as conf_file:
            conf_file.write(json.dumps(config,
                                       indent=2,
                                       separators=(',', ': '),
                                       sort_keys=kwargs.get('sort_keys', True)))
            conf_file.truncate()

    def load(self):
        """Load all files found under conf, including cluster configurations"""
        # Load configuration files
        config_files = [conf for conf in os.listdir(self.config_path) if conf.endswith('.json')]
        for config_file in config_files:
            config_key = os.path.splitext(config_file)[0]
            file_path = os.path.join(self.config_path, config_file)
            self._config_reader(config_key, file_path)

        # Load cluster files
        for cluster_file in os.listdir(os.path.join(self.config_path, 'clusters')):
            config_key = os.path.splitext(cluster_file)[0]
            file_path = os.path.join(self.config_path, 'clusters', cluster_file)
            self._config_reader(config_key, file_path, cluster_file=True)

    def write(self):
        """Write the current config in memory to disk"""
        # Write loaded configuration files
        for config_key in [key for key in self.config if key != 'clusters']:
            file_path = os.path.join(self.config_path,
                                     '{}.json'.format(config_key))
            if config_key == 'logs':
                self._config_writer(self.config[config_key],
                                    file_path,
                                    sort_keys=False)
            else:
                self._config_writer(self.config[config_key], file_path)

        # Write loaded cluster files
        for cluster_key in self.config['clusters']:
            file_path = os.path.join(self.config_path,
                                     'clusters',
                                     '{}.json'.format(cluster_key))
            self._config_writer(self.config['clusters'][cluster_key],
                                file_path)

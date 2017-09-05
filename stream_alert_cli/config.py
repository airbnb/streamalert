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
import sys

from stream_alert_cli.helpers import continue_prompt
from stream_alert_cli.logger import LOGGER_CLI


class CLIConfig(object):
    """Provide an object to load, modify, and display the StreamAlertCLI Config"""
    def __init__(self):
        self.config_files = OrderedDict([
            ('global', 'conf/global.json'),
            ('lambda', 'conf/lambda.json')
        ])
        self.config = self.load()

    def __repr__(self):
        return json.dumps(self.config)

    def __getitem__(self, key):
        return self.config[key]

    def __setitem__(self, key, new_value):
        self.config.__setitem__(key, new_value)
        print 'setting', key
        self.write()

    def get(self, key):
        """Lookup a value based on its key"""
        return self.config.get(key)

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

    def add_metric_alarm(self, alarm_info):
        """Add a metric alarm that corresponds to a predefined metrics"""
        metrics = self.config['global']['infrastructure'].get('metrics')
        if not metrics:
            self.config['global']['infrastructure']['metrics'] = {}

        # Check to see if metrics are enabled. If they are not, then alarms are useless.
        enable_metrics = self.config['global']['infrastructure']['metrics'].get('enabled', False)

        if not enable_metrics:
            prompt = ('Metrics are not currently enabled in \'conf/global.json\'. Creating a '
                      'metric alarm will have no effect until metrics are enabled. '
                      'Would you like to continue anyway?')
            if not continue_prompt(prompt):
                return

        current_alarms = self.config['global']['infrastructure']['metrics'].get('alarms', {})

        if alarm_info['alarm_name'] in current_alarms:
            prompt = ('Alarm name \'{}\' already defined. Would you '
                      'like to overwrite?').format(alarm_info['alarm_name'])
            if not continue_prompt(prompt):
                return

        omitted_keys = {'debug', 'alarm_name', 'command'}

        current_alarms[alarm_info['alarm_name']] = {
            key: value for key, value in alarm_info.iteritems()
            if key not in omitted_keys and value is not None
        }

        # Add the alarms to the config
        self.config['global']['infrastructure']['metrics']['alarms'] = current_alarms
        self.write()

    def load(self):
        """Load the cluster, global, and lambda configuration files

        Returns:
            dict: loaded config from all config files with the following keys:
                'clusters', 'global', and 'lambda'
        """
        config = {'clusters': {}}

        def _config_loader(key, filepath, cluster_file):
            if not os.path.isfile(filepath):
                LOGGER_CLI.error('[Config Error]: %s not found', filepath)
                sys.exit(1)

            with open(filepath) as data:
                try:
                    if cluster_file:
                        config['clusters'][key] = json.load(data)
                    else:
                        config[key] = json.load(data)
                except ValueError:
                    LOGGER_CLI.error('[Config Error]: %s is not valid JSON', filepath)
                    sys.exit(1)

        # Load individual files
        for key, path in self.config_files.iteritems():
            _config_loader(key, path, False)

        # Load cluster files
        for cluster_file in os.listdir('conf/clusters'):
            key = os.path.splitext(cluster_file)[0]
            _config_loader(key, 'conf/clusters/{}'.format(cluster_file), True)

        return config

    def write(self):
        """Write the current config in memory to disk"""
        def _config_writer(config, path):
            with open(path, 'r+') as varfile:
                varfile.write(json.dumps(
                    config,
                    indent=2,
                    separators=(',', ': '),
                    sort_keys=True
                ))
                varfile.truncate()

        for key, path in self.config_files.iteritems():
            _config_writer(self.config[key], path)

        for cluster_file in os.listdir('conf/clusters'):
            key = os.path.splitext(cluster_file)[0]
            _config_writer(
                self.config['clusters'][key],
                'conf/clusters/{}'.format(cluster_file))

'''
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
'''

import json
import os

from collections import defaultdict


class ConfigError(Exception):
    """Exception for a non existent config file"""
    pass


class CLIConfig(object):
    '''Provide an object to load, modify, and display the StreamAlertCLI Config'''
    filename = 'variables.json'

    v1_schema = {
        'account_id',
        'clusters',
        'firehose_s3_bucket_suffix',
        'flow_log_settings',
        'kinesis_settings',
        'kms_key_alias',
        'lambda_function_prod_versions',
        'lambda_handler',
        'lambda_settings',
        'lambda_source_bucket_name',
        'lambda_source_current_hash',
        'lambda_source_key',
        'output_lambda_current_hash',
        'output_lambda_source_key',
        'prefix',
        'region',
        'tfstate_s3_key',
        'tfvars',
        'third_party_libs'
    }

    v2_schema = {
        'account',
        'alert_processor_config',
        'alert_processor_lambda_config',
        'alert_processor_versions',
        'clusters',
        'firehose',
        'flow_log_config',
        'kinesis_streams_config',
        'rule_processor_config',
        'rule_processor_lambda_config',
        'rule_processor_versions',
        'terraform'
    }

    def __init__(self):
        self.config = self.load()
        self.version = self.detect_version()
        if self.version == 1:
            self.config = self._convert_schema()
            self.version = self.detect_version()

    def __getitem__(self, key):
        return self.config[key]

    def __setitem__(self, key, new_value):
        try:
            self.config[key] = new_value
        finally:
            self.write()

    def get(self, key):
        return self.config.get(key)

    def load(self):
        """Load the variables.json configuration file

        Returns:
            [dict] loaded config from variables.json
        """
        if not os.path.isfile(self.filename):
            raise ConfigError('StreamAlert variables.json file not found!')

        with open(self.filename) as data:
            try:
                config = json.load(data)
            except ValueError:
                raise ConfigError('StreamAlert variables.json file is not valid JSON!')
            return config

    def write(self):
        """Write the current config in memory to disk"""
        with open(self.filename, 'r+') as varfile:
            config_out = json.dumps(
                self.config,
                indent=4,
                separators=(',', ': '),
                sort_keys=True
            )
            varfile.seek(0)
            varfile.write(config_out)
            varfile.truncate()

    def detect_version(self):
        """Detect the config version

        Returns:
            [int] detected config version
        """
        config_keys = set(self.config.keys())

        if config_keys == self.v1_schema:
            return 1
        elif config_keys == self.v2_schema:
            return 2
        else:
            raise ConfigError('StreamAlert variables.json is missing keys!')

    def _convert_schema(self):
        """Upgrade the config from v1 to v2

        Returns:
            [dict] converted v2 config
        """
        new_config = defaultdict(dict)
        new_config['account'] = {
            'aws_account_id': self.config['account_id'],
            'prefix': self.config['prefix'],
            'kms_key_alias': self.config['kms_key_alias'],
            'region': self.config['region']
        }

        new_config['alert_processor_config'] = {
            'handler': 'stream_alert.alert_processor.main.handler',
            'third_party_libraries': [],
            'source_bucket': self.config['lambda_source_bucket_name'],
            'source_current_hash': self.config['output_lambda_current_hash'],
            'source_object_key': self.config['output_lambda_source_key'],
            'output_s3_bucket_arns': []
        }
        for cluster, _ in self.config['clusters'].iteritems():
            new_config['alert_processor_versions'][cluster] = '$LATEST'
            new_config['alert_processor_lambda_config'][cluster] = [10, 128]

        new_config['rule_processor_config'] = {
            'handler': self.config['lambda_handler'],
            'third_party_libraries': self.config['third_party_libs'],
            'source_bucket': self.config['lambda_source_bucket_name'],
            'source_current_hash': self.config['lambda_source_current_hash'],
            'source_object_key': self.config['lambda_source_key'],
        }
        new_config['rule_processor_versions'] = self.config['lambda_function_prod_versions']
        new_config['rule_processor_lambda_config'] = self.config['lambda_settings']

        new_config['clusters'] = self.config['clusters']
        new_config['firehose']['s3_bucket_suffix'] = self.config['firehose_s3_bucket_suffix']
        new_config['flow_log_config'] = {
            'vpcs': [],
            'subnets': [],
            'emis': []
        }
        new_config['kinesis_streams_config'] = self.config['kinesis_settings']
        new_config['terraform'] = {
            'tfstate_s3_key': self.config['tfstate_s3_key'],
            'tfvars': self.config['tfvars']
        }

        return new_config

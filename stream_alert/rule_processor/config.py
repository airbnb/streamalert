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

from collections import OrderedDict


class ConfigError(Exception):
    """Exception class for config file errors"""


def load_config(conf_dir='conf/'):
    """Load the configuration for StreamAlert.

    All configuration files live in the `conf` directory in JSON format.
    `sources` define a colleciton of AWS services (S3, Kinesis) supported as
    inputs to StreamAlert, specific entities (S3 buckets, Kinesis streams),
    and log types emitted from them.

    `logs` declare the schema for the listed log types in `sources`.  Each
    key denotes the name of the log type, and includes 'keys' used to match
    rules to log fields.
    """
    conf_files = {'sources', 'logs'}
    config = dict()
    for base_name in conf_files:
        path = '{}.json'.format(os.path.join(conf_dir, base_name))
        with open(path) as data:
            try:
                config[base_name] = json.load(data, object_pairs_hook=OrderedDict)
            except ValueError:
                raise ConfigError('Invalid JSON format for {}.json'.format(base_name))

    # Validate the config. This will raise an exception on any errors, which bubbles up
    _validate_config(config)

    return config


def _validate_config(config):
    """Validate the StreamAlert configuration contains a valid structure.

    Checks for `logs.json`:
        - each log has a schema and parser declared
    Checks for `sources.json`
        - the sources contains either kinesis or s3 keys
        - each sources has a list of logs declared
    """
    # Check the log declarations
    for log, attrs in config['logs'].iteritems():
        if 'schema' not in attrs:
            raise ConfigError('The \'schema\' is missing for {}'.format(log))

        if 'parser' not in attrs:
            raise ConfigError('The \'parser\' is missing for {}'.format(log))

    # check sources attributes
    if not set(config['sources']).issubset({'kinesis', 's3', 'sns'}):
        missing_sources = {'kinesis', 's3', 'sns'} - set(config['sources'])
        raise ConfigError(
            'Sources contains invalid key(s): %s',
            ', '.join('\'{}\''.format(key) for key in missing_sources))

    # check sources attributes
    for attrs in config['sources'].values():
        for entity, entity_attrs in attrs.iteritems():
            if 'logs' not in entity_attrs:
                raise ConfigError('Missing \'logs\' key for entity: {}'.format(entity))

            if not entity_attrs['logs']:
                raise ConfigError(
                    'List of \'logs\' is empty for entity: {}'.format(entity))


def load_env(context):
    """Get the current environment for the running Lambda function.

    Parses the invoked_function_arn from the given context object to get
    the name of the currently running alias (either production or staging)
    and the name of the function.

    Example:
        arn:aws:lambda:aws-region:acct-id:function:stream_alert:production

    Args:
        context: The AWS Lambda context object.

    Returns:
        [dict] including the following items:
            {
                'lambda_region': 'region_name',
                'account_id': 'account_id',
                'lambda_function_name': 'function_name',
                'lambda_alias': 'qualifier'
            }
    """
    arn = context.invoked_function_arn.split(':')
    return {
        'lambda_region': arn[3],
        'account_id': arn[4],
        'lambda_function_name': arn[6],
        'lambda_alias': arn[7]
    }

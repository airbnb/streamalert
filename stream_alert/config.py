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
    pass

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
    conf_files = {
        'sources': 'sources.json',
        'logs': 'logs.json'
    }
    config = {}
    for desc, filename in conf_files.iteritems():
        with open(os.path.join(conf_dir, filename)) as data:
            try:
                config[desc] = json.load(data, object_pairs_hook=OrderedDict)
            except ValueError:
                raise ConfigError('Invalid JSON format for {}.json'.format(desc))

    if validate_config(config):
        return config

def validate_config(config):
    """Validate the StreamAlert configuration contains a valid structure.

    Checks for `logs.json`:
        - each log has a schema and parser declared
    Checks for `sources.json`
        - the sources contains either kinesis or s3 keys
        - each sources has a list of logs declared
    """
    for config_key, settings in config.iteritems():
        # check log declarations
        if config_key == 'logs':
            for log, attrs in settings.iteritems():
                if not {'schema', 'parser'}.issubset(set(attrs.keys())):
                    raise ConfigError('Schema or parser missing for {}'.format(log))

        # check sources attributes
        elif config_key == 'sources':
            if not set(settings.keys()).issubset(set(['kinesis', 's3'])):
                raise ConfigError('Sources missing kinesis or s3 keys')
            for log, attrs in settings.iteritems():
                for entity, entity_attrs in attrs.iteritems():
                    if 'logs' not in set(entity_attrs.keys()):
                        raise ConfigError('Logs are not declared for {}'.format(entity))
                    if len(entity_attrs['logs']) == 0:
                        raise ConfigError('Log list is empty for {}'.format(entity))

    return True

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
        {'lambda_function_name': 'function_name',
         'lambda_alias': 'staging|development|production'}
    """
    env = {}
    if context:
        arn = context.invoked_function_arn.split(':')
        env['lambda_region'] = arn[3]
        env['account_id'] = arn[4]
        env['lambda_function_name'] = arn[6]
        env['lambda_alias'] = arn[7]
    else:
        env['lambda_alias'] = 'development'
    return env

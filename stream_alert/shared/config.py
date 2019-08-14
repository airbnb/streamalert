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
from collections import defaultdict, OrderedDict
import json
import os


class TopLevelConfigKeys(object):
    """Define the available top level keys in the loaded config"""
    CLUSTERS = 'clusters'
    GLOBAL = 'global'
    LAMBDA = 'lambda'
    LOGS = 'logs'
    NORMALIZED_TYPES = 'normalized_types'
    OUTPUTS = 'outputs'
    SOURCES = 'sources'
    THREAT_INTEL = 'threat_intel'
    LOOKUP_TABLES = 'lookup_tables'


class ConfigError(Exception):
    """Exception class for config file errors"""


def parse_lambda_arn(function_arn):
    """Extract info on the current environment from the lambda function ARN

    Parses the invoked_function_arn from the given context object to get
    the name of the currently running alias (either production or development)
    and the name of the function.

    Example:
        arn:aws:lambda:aws-region:acct-id:function:stream_alert:production

    Args:
        function_arn (str): The AWS Lambda function ARN

    Returns:
        dict:
            {
                'region': 'region_name',
                'account_id': 'account_id',
                'function_name': 'function_name',
                'qualifier': 'qualifier'
            }
    """
    split_arn = function_arn.split(':')
    return {
        'region': split_arn[3],
        'account_id': split_arn[4],
        'function_name': split_arn[6],
        'qualifier': split_arn[7] if len(split_arn) == 8 else None  # optional qualifier
    }


def load_config(conf_dir='conf/', exclude=None, include=None, validate=True):
    """Load the configuration for StreamAlert.

    All configuration files live in the `conf` directory in JSON format.
    `sources` define a colleciton of AWS services (S3, Kinesis) supported as
    inputs to StreamAlert, specific entities (S3 buckets, Kinesis streams),
    and log types emitted from them.

    `logs` declare the schema for the listed log types in `sources`.  Each
    key denotes the name of the log type, and includes 'keys' used to match
    rules to log fields.

    Args:
        conf_dir (str): [optional] Path from which to load the config
        exclude (set): [optional] Names of config files or folders that should not be loaded
        include (set): [optional] Names of specific config files to only load
        validate (bool): [optional] Validate aspects of the config to check for user error

    Raises:
        ConfigError: Raised if errors occur with configuration file loading

    Returns:
        dict: Loaded configuration in dictionary form. Example:
            {
                'clusters': {
                    'prod': <prod.json contents>
                },
                'global': <global.json contents>,
                'lambda': <lambda.json contents>,
                'logs': <logs.json contents>,
                'outputs': <outputs.json contents>,
                'sources': <sources.json contents>
            }
    """
    default_files = {file for file in os.listdir(conf_dir) if file.endswith('.json')}
    conf_files = (include or default_files).copy()
    include_clusters = TopLevelConfigKeys.CLUSTERS in conf_files

    conf_files.intersection_update(default_files)
    exclusions = exclude or set()
    conf_files = conf_files.difference(exclusions)

    if not (conf_files or include_clusters):
        available_files = ', '.join("'{}'".format(name) for name in sorted(default_files))
        raise ConfigError('No config files to load. This is likely due the misuse of '
                          'the \'include\' or \'exclude\' keyword arguments. Available '
                          'files are: {}, and clusters'.format(available_files))

    config = defaultdict(dict)
    for name in conf_files:
        path = os.path.join(conf_dir, name)
        # we use object_pairs_hook=OrderdDict to preserve schema order for CSV/KV log types
        config[os.path.splitext(name)[0]] = _load_json_file(path, name == 'logs.json')

    # Load the configs for clusters if it is not excluded
    if TopLevelConfigKeys.CLUSTERS not in exclusions and not include or include_clusters:
        clusters = {file for file in os.listdir(os.path.join(conf_dir, 'clusters'))
                    if file.endswith('.json')}
        for cluster in clusters:
            cluster_path = os.path.join(conf_dir, TopLevelConfigKeys.CLUSTERS, cluster)
            config[TopLevelConfigKeys.CLUSTERS][os.path.splitext(cluster)[0]] = (
                _load_json_file(cluster_path)
            )

    if validate:
        _validate_config(config)

    return config


def _load_json_file(path, ordered=False):
    """Helper to return the loaded json from a given path

    Args:
        path (str): Relative path to config file being loaded
        ordered (bool): [optional] Boolean that indicates if the loaded JSON
            file should have its order maintained an object_pairs_hook=OrderdDict

    Returns:
        dict: The loaded contents of the JSON file specified by path

    Raises:
        ConfigError: Raised if any ValueErrors occur during json.load(...)
    """
    kwargs = {'object_pairs_hook': OrderedDict if ordered else None}
    with open(path) as data:
        try:
            return json.load(data, **kwargs)
        except ValueError:
            raise ConfigError('Invalid JSON format for {}'.format(path))


def _validate_config(config):
    """Validate the StreamAlert configuration contains a valid structure.

    Checks for `logs.json`:
        - each log has a schema and parser declared
    Checks for `sources.json`
        - the sources contains either kinesis or s3 keys
        - each sources has a list of logs declared

    Args:
        config (dict): The loaded configuration dictionary

    Raises:
        ConfigError: Raised if any config validation errors occur
    """
    # Check the log declarations
    if TopLevelConfigKeys.LOGS in config:
        for log, attrs in config[TopLevelConfigKeys.LOGS].iteritems():
            if 'schema' not in attrs:
                raise ConfigError('The \'schema\' is missing for {}'.format(log))

            if 'parser' not in attrs:
                raise ConfigError('The \'parser\' is missing for {}'.format(log))

    # Check if the defined sources are supported and report any invalid entries
    if TopLevelConfigKeys.SOURCES in config:
        supported_sources = {'kinesis', 's3', 'sns', 'stream_alert_app'}
        if not set(config[TopLevelConfigKeys.SOURCES]).issubset(supported_sources):
            missing_sources = supported_sources - set(config[TopLevelConfigKeys.SOURCES])
            raise ConfigError(
                'The \'sources.json\' file contains invalid source entries: {}. '
                'The following sources are supported: {}'.format(
                    ', '.join('\'{}\''.format(source) for source in missing_sources),
                    ', '.join('\'{}\''.format(source) for source in supported_sources)
                )
            )

        # Iterate over each defined source and make sure the required subkeys exist
        for attrs in config[TopLevelConfigKeys.SOURCES].values():
            for entity, entity_attrs in attrs.iteritems():
                if TopLevelConfigKeys.LOGS not in entity_attrs:
                    raise ConfigError('Missing \'logs\' key for entity: {}'.format(entity))

                if not entity_attrs[TopLevelConfigKeys.LOGS]:
                    raise ConfigError('List of \'logs\' is empty for entity: {}'.format(entity))

    if TopLevelConfigKeys.THREAT_INTEL in config:
        if TopLevelConfigKeys.NORMALIZED_TYPES not in config:
            raise ConfigError('Normalized types must also be loaded with IOC types')

        if 'normalized_ioc_types' not in config[TopLevelConfigKeys.THREAT_INTEL]:
            raise ConfigError('Normalized IOC types must be defined for threat intelligence')

        normalized_ioc_types = config[TopLevelConfigKeys.THREAT_INTEL]['normalized_ioc_types']

        for ioc_type, normalized_keys in normalized_ioc_types.iteritems():
            for normalized_key in normalized_keys:
                if not any(normalized_key in set(log_keys)
                           for log_keys in config[TopLevelConfigKeys.NORMALIZED_TYPES].values()):
                    raise ConfigError(
                        'IOC key \'{}\' within IOC type \'{}\' must be defined for at least '
                        'one log type in normalized types'.format(normalized_key, ioc_type)
                    )

    # FIXME (derek.wang) write a configuration validator for lookuptables (new one)

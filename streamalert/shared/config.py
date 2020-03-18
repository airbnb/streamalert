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
from collections import defaultdict, OrderedDict
import json
import os
import re

from streamalert.shared import CLUSTERED_FUNCTIONS
from streamalert.shared.exceptions import ConfigError
from streamalert.shared.logger import get_logger

LOGGER = get_logger(__name__)

SUPPORTED_SOURCES = {'kinesis', 's3', 'sns', 'streamalert_app'}

# Used to detect special characters in log names. Log names can not contain special
# characters except "_" (underscore) because the log names will be referenced when
# create Athena tables and Firehose.
SPECIAL_CHAR_REGEX = re.compile(r'\W')
SPECIAL_CHAR_SUB = '_'


class TopLevelConfigKeys:
    """Define the available top level keys in the loaded config"""
    CLUSTERS = 'clusters'
    GLOBAL = 'global'
    LAMBDA = 'lambda'
    LOGS = 'logs'
    NORMALIZED_TYPES = 'normalized_types'
    OUTPUTS = 'outputs'
    SCHEMAS = 'schemas'
    THREAT_INTEL = 'threat_intel'
    LOOKUP_TABLES = 'lookup_tables'


class SchemaSorter:
    """Statefully sort schema by priority where 0 is the highest priority
    and the lowest priority is any positive numeric value.
    In the event that no priority is specified for a schema,
    it will be placed at the end after all schema with a priority defined.
    If no priority or equal priority is specified for multiple schema, they will
    be sorted in the order they were encountered. The intent of the statefulness
    of this function is that there is no arbitrarily enforced upper bound for priority."""

    def __init__(self):
        # Set a default index to -1
        self.max_index = -1

    def sort_key(self, key_and_value_tuple):
        """Key function for pythons sort function.
        Return each schemas priority or the max encountered priority if none was specified.
        """
        dict_value = key_and_value_tuple[1]
        value = int(dict_value.get('configuration', {}).get('priority', -1))

        # Update the index to the max of the current index or cached one
        self.max_index = max(self.max_index, value)

        # If the index is -1 (or unset), use the current "max_index"
        # Otherwise, return the actual priority value
        return self.max_index if value == -1 else value


def firehose_data_bucket(config):
    """Get the bucket name to be used for historical data retention

    Args:
        config (dict): The loaded config from the 'conf/' directory

    Returns:
        string|bool: The bucket name to be used for historical data retention. Returns
            False if firehose is not configured
    """
    # The default name is <prefix>-streamalert-data but can be overridden
    firehose_config = config['global']['infrastructure'].get('firehose')
    if not firehose_config:
        return False

    if not firehose_config.get('enabled'):
        return False

    return firehose_config.get(
        'bucket_name',
        '{}-streamalert-data'.format(config['global']['account']['prefix'])
    )


def firehose_alerts_bucket(config):
    """Get the bucket name to be used for historical alert retention

    Args:
        config (dict): The loaded config from the 'conf/' directory

    Returns:
        string: The bucket name to be used for historical alert retention
    """
    # The default name is <prefix>-streamalerts but can be overridden
    # The alerts firehose is not optional, so this should always return a value
    return config['global']['infrastructure'].get('alerts_firehose', {}).get(
        'bucket_name',
        '{}-streamalerts'.format(config['global']['account']['prefix'])
    )


def parse_lambda_arn(function_arn):
    """Extract info on the current environment from the lambda function ARN

    Parses the invoked_function_arn from the given context object to get
    the name of the currently running alias (either production or development)
    and the name of the function.

    Example:
        arn:aws:lambda:aws-region:acct-id:function:streamalert:production

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
                'outputs': <outputs.json contents>
            }
    """
    default_files = {file for file in os.listdir(conf_dir) if file.endswith('.json')}
    conf_files = (include or default_files).copy()
    include_clusters = TopLevelConfigKeys.CLUSTERS in conf_files

    conf_files.intersection_update(default_files)
    exclusions = exclude or set()
    conf_files = conf_files.difference(exclusions)

    schemas_dir = os.path.join(conf_dir, TopLevelConfigKeys.SCHEMAS)
    schema_files = []

    if (os.path.exists(schemas_dir) and TopLevelConfigKeys.SCHEMAS not in exclusions
            and (not include or TopLevelConfigKeys.SCHEMAS in include)):
        schema_files = [
            schema_file for schema_file in os.listdir(schemas_dir) if schema_file.endswith('.json')
        ]

    if not (conf_files or include_clusters or schema_files):
        available_files = ', '.join("'{}'".format(name) for name in sorted(default_files))
        raise ConfigError('No config files to load. This is likely due the misuse of '
                          'the \'include\' or \'exclude\' keyword arguments. Available '
                          'files are: {}, clusters, and schemas.'.format(available_files))

    config = defaultdict(dict)
    for name in conf_files:
        path = os.path.join(conf_dir, name)
        # we use object_pairs_hook=OrderdDict to preserve schema order for CSV/KV log types
        config[os.path.splitext(name)[0]] = _load_json_file(path, name == 'logs.json')

    # Load split logs.json configuration
    if ('logs.json' not in default_files and schema_files):
        config[TopLevelConfigKeys.LOGS] = _load_schemas(schemas_dir, schema_files)

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


def _load_schemas(schemas_dir, schema_files):
    """Helper to load all schemas from the schemas directory into one ordered dictionary.

    Args:
        conf_dir (str):  The relative path of the configuration directory
        schemas_dir (bool): The realtive path of the schemas directory

    Returns:
        OrderedDict: The sorted schema dictionary.
    """
    schemas = dict()
    for schema in schema_files:
        schemas_from_file = _load_json_file(os.path.join(schemas_dir, schema), True)
        dup_schema = set(schemas).intersection(schemas_from_file)
        if dup_schema:
            LOGGER.warning('Duplicate schema detected %s. This may result in undefined behavior.',
                           ', '.join(dup_schema))
        schemas.update(schemas_from_file)
    return OrderedDict(sorted(schemas.items(), key=SchemaSorter().sort_key))


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
    Checks for `cluster.json` data_sources:
        - the sources contains either kinesis or s3 keys
        - each sources has a list of logs declared

    Args:
        config (dict): The loaded configuration dictionary

    Raises:
        ConfigError: Raised if any config validation errors occur
    """
    # Check the log declarations
    if TopLevelConfigKeys.LOGS in config:
        for log, attrs in config[TopLevelConfigKeys.LOGS].items():
            if 'schema' not in attrs:
                raise ConfigError("The 'schema' is missing for {}".format(log))

            if 'parser' not in attrs:
                raise ConfigError("The 'parser' is missing for {}".format(log))

    # Check if the defined sources are supported and report any invalid entries
    if TopLevelConfigKeys.CLUSTERS in config:
        # Used to track duplicate sources in separate cluster config files
        existing_sources = set()
        for cluster_name, cluster_attrs in config[TopLevelConfigKeys.CLUSTERS].items():
            if 'data_sources' not in cluster_attrs:
                raise ConfigError("'data_sources' missing for cluster {}".format(cluster_name))
            _validate_sources(cluster_name, cluster_attrs['data_sources'], existing_sources)

            for func in CLUSTERED_FUNCTIONS:
                config_name = '{}_config'.format(func)
                if config_name in cluster_attrs:
                    continue

                error = "'{}' is missing in the '{}' cluster".format(config_name, cluster_name)

                modules = cluster_attrs.get('modules', {})
                old_format = None
                for key in {'streamalert', 'stream_alert'}:
                    if key in modules:
                        old_format = key

                if old_format:
                    error += (
                        ". The usage of the '{}' within 'modules' has been deprecated and '{}'"
                        "should be included as a top level key"
                    ).format(old_format, config_name)

                raise ConfigError(error)

    if TopLevelConfigKeys.THREAT_INTEL in config:
        if TopLevelConfigKeys.NORMALIZED_TYPES not in config:
            raise ConfigError('Normalized types must also be loaded with IOC types')

        if 'normalized_ioc_types' not in config[TopLevelConfigKeys.THREAT_INTEL]:
            raise ConfigError('Normalized IOC types must be defined for threat intelligence')

        normalized_ioc_types = config[TopLevelConfigKeys.THREAT_INTEL]['normalized_ioc_types']

        for ioc_type, normalized_keys in normalized_ioc_types.items():
            for normalized_key in normalized_keys:
                if not any(normalized_key in set(log_keys)
                           for log_keys in
                           list(config[TopLevelConfigKeys.NORMALIZED_TYPES].values())):
                    raise ConfigError(
                        "IOC key '{}' within IOC type '{}' must be defined for at least "
                        "one log type in normalized types".format(normalized_key, ioc_type)
                    )


def _validate_sources(cluster_name, data_sources, existing_sources):
    """Validates the sources for a cluster
    Args:
        cluster_name (str): The name of the cluster we are validating sources for
        data_sources (dict): The sources to validate
        existing_sources(set): Aleady defined sources
    Raises:
        ConfigError: If the validation fails
    """
    # Iterate over each defined source and make sure the required subkeys exist
    if not set(data_sources).issubset(SUPPORTED_SOURCES):
        invalid_sources = set(data_sources) - SUPPORTED_SOURCES
        raise ConfigError(
            'The data sources for cluster {} contain invalid source entries: {}. '
            'The following sources are supported: {}'.format(
                cluster_name,
                ', '.join("'{}'".format(source) for source in invalid_sources),
                ', '.join("'{}'".format(source) for source in SUPPORTED_SOURCES)
            )
        )
    for attrs in data_sources.values():
        for source, logs in attrs.items():

            if not logs:
                raise ConfigError("List of logs is empty for source: {}".format(source))

            if source in existing_sources:
                raise ConfigError(
                    "Duplicate data_source in cluster configuration {} "
                    "for cluster {}".format(source, cluster_name)
                )
            existing_sources.add(source)

# FIXME (derek.wang) write a configuration validator for lookuptables (new one)

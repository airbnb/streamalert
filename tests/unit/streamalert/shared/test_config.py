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
import collections
import json
from unittest.mock import Mock

import pytest
from pyfakefs import fake_filesystem_unittest

from streamalert.shared.config import (ConfigError, _validate_config,
                                       artifact_extractor_enabled, load_config,
                                       parse_lambda_arn)
from tests.unit.helpers.config import basic_streamalert_config


def get_mock_lambda_context(func_name, milliseconds=100):
    """Helper function to create a fake context object using Mock"""
    arn = 'arn:aws:lambda:us-east-1:123456789012:function:{}:development'
    return Mock(invoked_function_arn=(arn.format(func_name)),
                function_name=func_name,
                function_version='production',
                get_remaining_time_in_millis=Mock(return_value=milliseconds))


class TestConfigLoading(fake_filesystem_unittest.TestCase):
    """Test config loading logic with a mocked filesystem."""

    # pylint: disable=protected-access

    def setUp(self):
        self.setUpPyfakefs()

        config_data = basic_streamalert_config()

        mock_cluster_contents = '{"data_sources": {}, "classifier_config": {"foo": "bar"}}'

        # Add config files which should be loaded
        self.fs.create_file('conf/clusters/prod.json', contents=mock_cluster_contents)
        self.fs.create_file('conf/clusters/dev.json', contents=mock_cluster_contents)
        self.fs.create_file('conf/global.json', contents='{}')
        self.fs.create_file('conf/lambda.json', contents='{}')
        self.fs.create_file('conf/logs.json', contents='{}')
        self.fs.create_file('conf/outputs.json', contents='{}')
        self.fs.create_file('conf/threat_intel.json',
                            contents=json.dumps(config_data['threat_intel']))
        self.fs.create_file('conf/normalized_types.json',
                            contents=json.dumps(config_data['normalized_types']))
        self.fs.create_file(
            'conf/schemas/csv.json',
            contents='{"csv_log2": {"schema": {"data": "string","uid": "integer"},"parser": "csv"}}'
        )

        # Create similar structure but with schemas folder instead of logs.json and 2 clusters.
        self.fs.create_file('conf_schemas/clusters/prod.json', contents=mock_cluster_contents)
        self.fs.create_file('conf_schemas/clusters/dev.json', contents=mock_cluster_contents)
        self.fs.create_file('conf_schemas/global.json', contents='{}')
        self.fs.create_file('conf_schemas/lambda.json', contents='{}')
        self.fs.create_file('conf_schemas/outputs.json', contents='{}')
        self.fs.create_file(
            'conf_schemas/schemas/csv.json',
            contents='{"csv_log": {"schema": {"data": "string","uid": "integer"},"parser": "csv"}}')
        self.fs.create_file(
            'conf_schemas/schemas/json.json',
            contents='{"json_log": {"schema": {"name": "string"},"parser": "json"}}')
        self.fs.create_file(
            'conf_schemas/schemas/json_log_with_dots.json',
            contents='{"json:log.with.dots": {"schema": {"name": "string"},"parser": "json"}}')

    def test_load_invalid_file(self):
        """Shared - Config Loading - Bad JSON"""
        self.fs.create_file('conf/clusters/bad.json', contents='test string')
        pytest.raises(ConfigError, load_config)

    @staticmethod
    def test_load_invalid_path():
        """Shared - Config Loading - Bad JSON"""
        pytest.raises(ConfigError, load_config, include={'foobar.json'})

    @staticmethod
    def test_load_all():
        """Shared - Config Loading - All"""
        config = load_config()
        expected_keys = {
            'clusters', 'global', 'lambda', 'logs', 'outputs', 'threat_intel', 'normalized_types'
        }
        assert set(config) == expected_keys

    @staticmethod
    def test_load_exclude():
        """Shared - Config Loading - Exclude"""
        config = load_config(exclude={'global.json', 'logs.json'})
        expected_keys = {'clusters', 'lambda', 'outputs', 'threat_intel', 'normalized_types'}
        assert set(config) == expected_keys

    @staticmethod
    def test_load_exclude_clusters():
        """Shared - Config Loading - Exclude Clusters"""
        config = load_config(exclude={'clusters'})
        expected_keys = {'global', 'lambda', 'logs', 'outputs', 'threat_intel', 'normalized_types'}
        assert set(config) == expected_keys

    @staticmethod
    def test_load_exclude_schemas():
        """Shared - Config Loading - Exclude Clusters"""
        config = load_config(conf_dir='conf_schemas', exclude={'schemas'})
        expected_keys = {
            'clusters',
            'global',
            'lambda',
            'outputs',
        }
        assert set(config) == expected_keys

    @staticmethod
    def test_load_include():
        """Shared - Config Loading - Include"""
        config = load_config(include={'clusters', 'logs.json'})
        expected_keys = ['clusters', 'logs']
        expected_clusters_keys = ['prod', 'dev']
        assert collections.Counter(list(config.keys())) == collections.Counter(expected_keys)
        assert collections.Counter(
            list(config['clusters'].keys())) == collections.Counter(expected_clusters_keys)

    @staticmethod
    def test_load_schemas():
        """Shared - Config Loading - Schemas"""
        # Load from separate dir where logs.json doesn't exist
        config = load_config(conf_dir='conf_schemas')
        basic_config = basic_streamalert_config()
        assert config['logs'] == basic_config['logs']

    @staticmethod
    def test_load_schemas_logs():
        """Shared - Config Loading - Schemas and Logs.json Exist"""
        # Check if data was loaded from conf/logs.json or the schemas dir if both exist
        config = load_config(conf_dir='conf')
        # Logs.json is preferred over schemas for backwards compatibility.
        assert config['logs'] == {}


class TestConfigValidation:
    """Test config validation"""

    def test_config_no_schema(self):
        """Shared - Config Validator - No Schema in Log"""
        # Load a valid config
        config = basic_streamalert_config()

        # Remove the 'schema' keys from the config
        config['logs']['json_log'].pop('schema')
        config['logs']['csv_log'].pop('schema')

        pytest.raises(ConfigError, _validate_config, config)

    def test_config_no_parsers(self):
        """Shared - Config Validator - No Parser in Log"""
        # Load a valid config
        config = basic_streamalert_config()

        # Remove the 'parser' keys from the config
        config['logs']['json_log'].pop('parser')
        config['logs']['csv_log'].pop('parser')

        pytest.raises(ConfigError, _validate_config, config)

    def test_config_no_logs_key(self):
        """Shared - Config Validator - No Logs Key in Source"""
        # Load a valid config
        config = basic_streamalert_config()

        # Remove everything from the sources entry
        config['clusters']['prod']['data_sources']['kinesis']['stream_1'] = {}

        pytest.raises(ConfigError, _validate_config, config)

    def test_config_empty_logs_list(self):
        """Shared - Config Validator - Empty Logs List in Source"""
        # Load a valid config
        config = basic_streamalert_config()

        # Set the logs key to an empty list
        config['clusters']['prod']['data_sources']['kinesis']['stream_1'] = []

        pytest.raises(ConfigError, _validate_config, config)

    def test_config_invalid_datasources(self):
        """Shared - Config Validator - Invalid Datasources"""
        # Load a valid config
        config = basic_streamalert_config()

        # Set the sources value to contain an invalid data source ('sqs')
        config['clusters']['prod']['data_sources'] = {'sqs': {'queue_1': {}}}

        pytest.raises(ConfigError, _validate_config, config)

    def test_parse_lambda_arn(self):
        """Shared - Config - Parse Lambda ARN"""
        func_name = 'corp-prefix_prod_streamalert_classifer'
        context = get_mock_lambda_context(func_name)

        env = parse_lambda_arn(context.invoked_function_arn)
        assert env['region'] == 'us-east-1'
        assert env['account_id'] == '123456789012'
        assert env['function_name'] == func_name
        assert env['qualifier'] == 'development'

    def test_missing_streamalert_module(self):
        """Shared - Config Validator, Missing streamalert Module"""
        config = basic_streamalert_config()
        del config['clusters']['prod']['classifier_config']
        pytest.raises(ConfigError, _validate_config, config)

    def test_config_invalid_ioc_types(self):
        """Shared - Config Validator - IOC Types, Invalid"""
        # Load a valid config
        config = basic_streamalert_config()

        # Set the sources value to contain an invalid data source ('sqs')
        config['threat_intel'] = {'normalized_ioc_types': {'ip': ['foobar']}}

        config['normalized_types'] = {'log_type': {'sourceAddress': ['ip_address']}}

        pytest.raises(ConfigError, _validate_config, config)

    def test_config_ioc_types_no_normalized_types(self):
        """Shared - Config Validator - IOC Types, Without Normalized Types"""
        # Load a valid config
        config = basic_streamalert_config()

        # Set the sources value to contain an invalid data source ('sqs')
        config['threat_intel'] = {'normalized_ioc_types': {'ip': ['foobar']}}
        if 'normalized_types' in config:
            del config['normalized_types']

        pytest.raises(ConfigError, _validate_config, config)

    def test_config_duplicate_sources(self):
        """Shared - Config Validator - Duplicate Data Sources in Cluster Configs"""
        config = basic_streamalert_config()
        config['clusters']['dev'] = config['clusters']['prod']
        pytest.raises(ConfigError, _validate_config, config)


class TestConfigArtifactExtractor():
    """Shared - Test Artifact Extractor configuration with mocked config files"""

    def __init__(self):
        self.default_conf_data = {}

    def setup(self):
        self.default_conf_data = {
            'global': {
                'infrastructure': {
                    'firehose': {
                        'enabled': False,
                        'enabled_logs': {}
                    },
                    'artifact_extractor': {
                        'enabled': False
                    }
                }
            },
            'logs': {
                'test_log:type_1': {
                    'schema': {},
                    'configuration': {
                        'normalization': {}
                    }
                },
                'test_log:type_2': {
                    'schema': {},
                }
            }
        }

    def test_artifact_extractor_disabled_by_default(self):
        """Shared - artifact extractor is disabled with default config"""
        assert not artifact_extractor_enabled(self.default_conf_data)

    def test_artifact_extractor(self):
        """Shared - test artifact_extractor_enabled helper"""
        self.default_conf_data['global']['infrastructure']['artifact_extractor']['enabled'] = True
        assert not artifact_extractor_enabled(self.default_conf_data)

        self.default_conf_data['global']['infrastructure']['firehose']['enabled'] = True
        assert artifact_extractor_enabled(self.default_conf_data)

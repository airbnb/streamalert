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
from nose.tools import assert_equal, assert_items_equal, assert_raises
from pyfakefs import fake_filesystem_unittest

from stream_alert.shared.config import (
    _validate_config,
    load_config,
    parse_lambda_arn,
    ConfigError,
)

from tests.unit.stream_alert_rule_processor.test_helpers import get_mock_context, get_valid_config

class TestConfigLoading(fake_filesystem_unittest.TestCase):
    """Test config loading logic with a mocked filesystem."""
    # pylint: disable=protected-access

    def setUp(self):
        self.setUpPyfakefs()

        # Add config files which should be loaded
        self.fs.create_file('conf/clusters/prod.json', contents='{}')
        self.fs.create_file('conf/clusters/dev.json', contents='{}')
        self.fs.create_file('conf/global.json', contents='{}')
        self.fs.create_file('conf/lambda.json', contents='{}')
        self.fs.create_file('conf/logs.json', contents='{}')
        self.fs.create_file('conf/outputs.json', contents='{}')
        self.fs.create_file('conf/sources.json', contents='{}')
        self.fs.create_file('conf/types.json', contents='{}')

    def test_load_invalid_file(self):
        """Shared - Config Loading - Bad JSON"""
        self.fs.create_file('conf/clusters/bad.json', contents='test string')
        assert_raises(ConfigError, load_config)

    @staticmethod
    def test_load_invalid_path():
        """Shared - Config Loading - Bad JSON"""
        assert_raises(ConfigError, load_config, include={'foobar.json'})

    @staticmethod
    def test_load_all():
        """Shared - Config Loading - All"""
        config = load_config()
        expected_keys = ['clusters', 'global', 'lambda', 'logs', 'outputs', 'sources', 'types']
        assert_items_equal(config.keys(), expected_keys)

    @staticmethod
    def test_load_exclude():
        """Shared - Config Loading - Exclude"""
        config = load_config(exclude={'global.json', 'logs.json'})
        expected_keys = ['clusters', 'lambda', 'outputs', 'sources', 'types']
        assert_items_equal(config.keys(), expected_keys)

    @staticmethod
    def test_load_exclude_clusters():
        """Shared - Config Loading - Exclude Clusters"""
        config = load_config(exclude={'clusters'})
        expected_keys = ['global', 'lambda', 'logs', 'outputs', 'sources', 'types']
        assert_items_equal(config.keys(), expected_keys)

    @staticmethod
    def test_load_include():
        """Shared - Config Loading - Include"""
        config = load_config(include={'clusters', 'logs.json'})
        expected_keys = ['clusters', 'logs']
        expected_clusters_keys = ['prod', 'dev']
        assert_items_equal(config.keys(), expected_keys)
        assert_items_equal(config['clusters'].keys(), expected_clusters_keys)


class TestConfigValidation(object):
    """Test config validation"""
    # pylint: disable=no-self-use

    def test_config_no_schema(self):
        """Shared - Config Validator - No Schema in Log"""
        # Load a valid config
        config = get_valid_config()

        # Remove the 'schema' keys from the config
        config['logs']['json_log'].pop('schema')
        config['logs']['csv_log'].pop('schema')

        assert_raises(ConfigError, _validate_config, config)

    def test_config_no_parsers(self):
        """Shared - Config Validator - No Parser in Log"""
        # Load a valid config
        config = get_valid_config()

        # Remove the 'parser' keys from the config
        config['logs']['json_log'].pop('parser')
        config['logs']['csv_log'].pop('parser')

        assert_raises(ConfigError, _validate_config, config)

    def test_config_no_logs_key(self):
        """Shared - Config Validator - No Logs Key in Source"""
        # Load a valid config
        config = get_valid_config()

        # Remove everything from the sources entry
        config['sources']['kinesis']['stream_1'] = {}

        assert_raises(ConfigError, _validate_config, config)

    def test_config_empty_logs_list(self):
        """Shared - Config Validator - Empty Logs List in Source"""
        # Load a valid config
        config = get_valid_config()

        # Set the logs key to an empty list
        config['sources']['kinesis']['stream_1']['logs'] = []

        assert_raises(ConfigError, _validate_config, config)

    def test_config_invalid_datasources(self):
        """Shared - Config Validator - Invalid Datasources"""
        # Load a valid config
        config = get_valid_config()

        # Set the sources value to contain an invalid data source ('sqs')
        config['sources'] = {'sqs': {'queue_1': {}}}

        assert_raises(ConfigError, _validate_config, config)

    def test_parse_lambda_arn(self):
        """Shared - Config - Parse Lambda ARN"""
        context = get_mock_context()

        env = parse_lambda_arn(context.invoked_function_arn)
        assert_equal(env['region'], 'us-east-1')
        assert_equal(env['account_id'], '123456789012')
        assert_equal(env['function_name'], 'corp-prefix_prod_streamalert_rule_processor')
        assert_equal(env['qualifier'], 'development')

    def test_config_invalid_ioc_types(self):
        """Shared - Config Validator - IOC Types, Invalid"""
        # Load a valid config
        config = get_valid_config()

        # Set the sources value to contain an invalid data source ('sqs')
        config['ioc_types'] = {'ip': ['foobar']}
        config['normalized_types'] = {'log_type': {'sourceAddress': ['ip_address']}}

        assert_raises(ConfigError, _validate_config, config)

    def test_config_ioc_types_no_normalized_types(self):
        """Shared - Config Validator - IOC Types, Without Normalized Types"""
        # Load a valid config
        config = get_valid_config()

        # Set the sources value to contain an invalid data source ('sqs')
        config['ioc_types'] = {'ip': ['foobar']}
        if 'normalized_types' in config:
            del config['normalized_types']

        assert_raises(ConfigError, _validate_config, config)

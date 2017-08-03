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

# command: nosetests -v -s test/unit/
# specific test: nosetests -v -s test/unit/file.py:TestStreamPayload.test_name
from datetime import datetime

import json

from collections import namedtuple
from mock import patch, MagicMock

from nose.tools import assert_equal, raises, nottest, assert_true, assert_false

from stream_alert.athena_partition_refresh.main import StreamAlertAthenaClient, ConfigError
from unit.helpers.base import mock_open
from unit.helpers.aws_mocks import MockAthenaClient

GLOBAL_FILE = 'conf/global.json'
LAMBDA_FILE = 'conf/lambda.json'


class TestStreamAlertAthenaClient(object):
    """Test class for StreamAlertAthenaClient"""

    def __init__(self):
        self.config_data = {
            'global': {
                'account': {
                    'aws_account_id': '111111111111',
                    'kms_key_alias': 'stream_alert_secrets',
                    'prefix': 'unit-testing',
                    'region': 'us-east-2'
                },
                'terraform': {
                    'tfstate_bucket': 'unit-testing.streamalert.terraform.state',
                    'tfstate_s3_key': 'stream_alert_state/terraform.tfstate',
                    'tfvars': 'terraform.tfvars'
                },
                'infrastructure': {
                    'monitoring': {
                        'create_sns_topic': True
                    }
                }
            },
            'lambda': {
                'alert_processor_config': {
                    'handler': 'stream_alert.alert_processor.main.handler',
                    'source_bucket': 'unit-testing.streamalert.source',
                    'source_current_hash': '<auto_generated>',
                    'source_object_key': '<auto_generated>',
                    'third_party_libraries': []
                },
                'rule_processor_config': {
                    'handler': 'stream_alert.rule_processor.main.handler',
                    'source_bucket': 'unit-testing.streamalert.source',
                    'source_current_hash': '<auto_generated>',
                    'source_object_key': '<auto_generated>',
                    'third_party_libraries': [
                        'jsonpath_rw',
                        'netaddr'
                    ]
                },
                'athena_partition_refresh_config': {
                    "enabled": True,
                    "refresh_type": {
                        "repair_hive_table": {
                            "unit-testing.streamalerts": "alerts"
                        },
                        "add_hive_partition": {}
                    },
                    "handler": "main.handler",
                    "timeout": "60",
                    "memory": "128",
                    "source_bucket": "unit-testing.streamalert.source",
                    "source_current_hash": "<auto_generated>",
                    "source_object_key": "<auto_generated",
                    "third_party_libraries": [
                        "backoff"
                    ]
                }
            }
        }

    def setup(self):
        self.client = StreamAlertAthenaClient(config=self.config_data,
                                              results_key_prefix='unit-testing')

    @raises(ConfigError)
    def test_invalid_json_config(self):
        """Athena - Load Invalid Config"""
        invalid_config_data = 'This is not JSON!!!'
        with mock_open(LAMBDA_FILE, invalid_config_data):
            with mock_open(GLOBAL_FILE, invalid_config_data):
                client = StreamAlertAthenaClient()

    @raises(ConfigError)
    def test_invalid_missing_config(self):
        """Athena - Load Missing Config File"""
        invalid_config_data = 'test'
        with mock_open(LAMBDA_FILE, invalid_config_data):
            with mock_open(GLOBAL_FILE, invalid_config_data):
                with patch('os.path.exists') as mock_exists:
                    mock_exists.return_value = False
                    client = StreamAlertAthenaClient()

    def test_load_valid_config(self):
        """Athena - Load Config"""
        global_contents = json.dumps(self.config_data['global'], indent=4)
        lambda_contents = json.dumps(self.config_data['lambda'], indent=4)

        with mock_open(GLOBAL_FILE, global_contents):
            with mock_open(LAMBDA_FILE, lambda_contents):
                client = StreamAlertAthenaClient()

                assert_equal(type(client.config), dict)
                assert_equal(set(client.config.keys()), {'global', 'lambda'})

    @patch('stream_alert.athena_partition_refresh.main.LOGGER')
    @raises(NotImplementedError)
    def test_firehose_partition_refresh(self, mock_logging):
        """Athena - Test Firehose Parition Refresh"""
        self.client.firehose_partition_refresh(None)

        assert_true(mock_logging.error.called)

    @patch('stream_alert.athena_partition_refresh.main.LOGGER')
    def test_backoff_and_success_handlers(self, mock_logging):
        """Athena - Test Backoff Handlers"""
        self.client._backoff_handler({'wait': 1.0, 'tries': 3, 'target': 'backoff'})
        assert_true(mock_logging.debug.called)

        self.client._success_handler({'tries': 3, 'target': 'backoff'})
        assert_true(mock_logging.debug.called)

    def test_check_table_exists(self):
        """Athena - Check Table Exists"""
        query_result = [{'alerts': True}]
        self.client.athena_client = MockAthenaClient(results=query_result)

        result = self.client.check_table_exists('unit-test')
        assert_true(result)

        generated_results_key = 'unit-testing/{}'.format(
            datetime.now().strftime('%Y/%m/%d'))
        assert_equal(self.client.athena_results_key, generated_results_key)

    @patch('stream_alert.athena_partition_refresh.main.LOGGER')
    def test_check_table_exists_invalid(self, mock_logging):
        """Athena - Check Table Exists - Does Not Exist"""
        query_result = None
        self.client.athena_client = MockAthenaClient(results=query_result)

        result = self.client.check_table_exists('unit-test')
        assert_false(result)
        assert_true(mock_logging.info.called)

    def test_check_database_exists_invalid(self):
        """Athena - Check Database Exists - Does Not Exist"""
        query_result = None
        self.client.athena_client = MockAthenaClient(results=query_result)

        assert_false(self.client.check_database_exists())

    def test_check_database_exists(self):
        """Athena - Check Database Exists"""
        query_result = [{'streamalert': True}]
        self.client.athena_client = MockAthenaClient(results=query_result)

        assert_true(self.client.check_database_exists())

    @patch('stream_alert.athena_partition_refresh.main.LOGGER')
    def test_run_athena_query_empty(self, mock_logging):
        """Athena - Run Athena Query"""
        query_result = None
        self.client.athena_client = MockAthenaClient(results=query_result)

        query_success, query_results = self.client.run_athena_query(
            query='SHOW DATABASES;'
        )

        assert_true(query_success)
        assert_equal(query_results['ResultSet']['Rows'], [])
        assert_true(mock_logging.debug.called)

    @patch('stream_alert.athena_partition_refresh.main.LOGGER')
    def test_run_athena_query_error(self, mock_logging):
        """Athena - Run Athena Query"""
        self.client.athena_client = MockAthenaClient(results=None, result_state='FAILED')

        query_success, query_results = self.client.run_athena_query(
            query='SHOW DATABASES;'
        )

        assert_true(mock_logging.error.called)
        assert_false(query_success)
        assert_equal(query_results, {})

    @patch('stream_alert.athena_partition_refresh.main.LOGGER')
    def test_repair_hive_table(self, mock_logging):
        """Athena - Repair Hive Table"""
        query_result = [{'Status': 'Success'}]
        self.client.athena_client = MockAthenaClient(results=query_result)

        self.client.repair_hive_table()
        assert_true(mock_logging.info.called)

    def test_run_athena_query(self):
        """Athena - Run Athena Query"""
        self.client.athena_client = MockAthenaClient()

        query_success, query_results = self.client.run_athena_query(
            query='SHOW DATABASES;'
        )

        assert_true(query_success)
        assert_equal(query_results['ResultSet']['Rows'], [{'Data': [{'test': 'test'}]}])

    @patch('stream_alert.athena_partition_refresh.main.LOGGER.error')
    @patch('stream_alert.athena_partition_refresh.main.StreamAlertAthenaClient.run_athena_query')
    def test_repair_hive_table_fail(self, mock_run_athena, mock_logging):
        """Athena - Repair Hive Table, Failure"""
        mock_run_athena.return_value = (False, None)
        self.client.athena_client = MockAthenaClient()

        self.client.repair_hive_table()
        assert_true(mock_logging.called)

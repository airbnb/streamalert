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

import json

from collections import namedtuple
from mock import patch, MagicMock

from nose.tools import assert_equal, raises, nottest, assert_true, assert_false

from stream_alert.athena_partition_refresh import main
from unit.helpers.base import mock_open
from unit.helpers.aws_mocks import MockAthenaClient

GLOBAL_FILE = 'conf/global.json'
LAMBDA_FILE = 'conf/lambda.json'

@nottest
def test_handler(mock_logging):
    """Athena - Main"""
    main.handler(None, None)


@patch('stream_alert.athena_partition_refresh.main.LOGGER')
def test_invalid_json_config(mock_logging):
    """Athena - Load Invalid Config"""
    invalid_config_data = 'This is not JSON!!!'
    with mock_open(LAMBDA_FILE, invalid_config_data):
        config = main._load_config()
        assert_true(mock_logging.error.called)


def test_load_valid_config():
    """Athena - Load Config"""
    config_data = {
        'global': {
            'account': {
                'aws_account_id': 'AWS_ACCOUNT_ID_GOES_HERE',
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
                "partitioning": {
                  "normal": {
                    "unit-testing.streamalerts": "alerts"
                  },
                  "firehose": {}
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
    global_contents = json.dumps(config_data['global'], indent=4)
    lambda_contents = json.dumps(config_data['lambda'], indent=4)

    with mock_open(GLOBAL_FILE, global_contents):
        with mock_open(LAMBDA_FILE, lambda_contents):
            config = main._load_config()

            assert_equal(type(config), dict)
            assert_equal(set(config.keys()), {'global', 'lambda'})


@patch('stream_alert.athena_partition_refresh.main.LOGGER')
@raises(NotImplementedError)
def test_firehose_partition_refresh(mock_logging):
    """Athena - Test Firehose Parition Refresh"""
    main.firehose_partition_refresh(None)

    assert_true(mock_logging.error.called)


@patch('stream_alert.athena_partition_refresh.main.LOGGER')
def test_backoff_handler(mock_logging):
    """Athena - Test Backoff Handler"""
    main._backoff_handler({'wait': 1.0, 'tries': 3, 'target': 'backoff'})

    assert_true(mock_logging.debug.called)


@patch('stream_alert.athena_partition_refresh.main.LOGGER')
def test_success_handler(mock_logging):
    """Athena - Test Success Handler"""
    main._success_handler({'tries': 3, 'target': 'backoff'})

    assert_true(mock_logging.debug.called)


@patch('stream_alert.athena_partition_refresh.main.ATHENA_CLIENT', MockAthenaClient(results=[{'alerts': True}]))
def test_check_table_exists():
    """Athena - Check Table Exists"""
    result = main.check_table_exists('s3://unit-test-results', '/athena', 'unit-test')

    assert_true(result)


@patch('stream_alert.athena_partition_refresh.main.ATHENA_CLIENT', MockAthenaClient(results=None))
def test_check_table_exists_invalid():
    """Athena - Check Table Exists - Does Not Exist"""
    result = main.check_table_exists('s3://unit-test-results', '/athena', 'unit-test')

    assert_false(result)


@patch('stream_alert.athena_partition_refresh.main.ATHENA_CLIENT', MockAthenaClient(results=None))
def test_check_database_exists_invalid():
    """Athena - Check Database Exists - Does Not Exist"""
    result = main.check_database_exists('s3://unit-test-results', '/athena')

    assert_false(result)


@patch('stream_alert.athena_partition_refresh.main.ATHENA_CLIENT', MockAthenaClient(results=[{'streamalert': True}]))
def test_check_database_exists():
    """Athena - Check Database Exists"""
    result = main.check_database_exists('s3://unit-test-results', '/athena')

    assert_true(result)


@patch('stream_alert.athena_partition_refresh.main.LOGGER')
def test_check_query_status(mock_logging):
    """Athena - Check Query Status"""
    pass


@patch('stream_alert.athena_partition_refresh.main.LOGGER')
@patch('stream_alert.athena_partition_refresh.main.ATHENA_CLIENT', MockAthenaClient(results=None))
def test_run_athena_query_empty(mock_logging):
    """Athena - Run Athena Query"""
    query_results = main.run_athena_query(
        query='SHOW DATABASES;',
        results_bucket='s3://unit-test-results',
        results_path='/athena'
    )

    assert_equal(query_results['ResultSet']['Rows'], [])
    assert_true(mock_logging.debug.called)


@patch('stream_alert.athena_partition_refresh.main.LOGGER')
@patch('stream_alert.athena_partition_refresh.main.ATHENA_CLIENT', MockAthenaClient(results=None, result_state='FAILED'))
def test_run_athena_query_error(mock_logging):
    """Athena - Run Athena Query"""
    query_results = main.run_athena_query(
        query='SHOW DATABASES;',
        results_bucket='s3://unit-test-results',
        results_path='/athena'
    )

    assert_true(mock_logging.error.called)
    assert_false(query_results)


@patch('stream_alert.athena_partition_refresh.main.LOGGER')
@patch('stream_alert.athena_partition_refresh.main.ATHENA_CLIENT', MockAthenaClient(results=[{'Status': 'Success'}]))
def test_normal_partition_refresh(mock_logging):
    """Athena - Normal Parition Refresh"""
    config = {
        'lambda': {
            'athena_partition_refresh_config': {
                'partitioning': {
                    'normal': {
                        'my-bucket.name': 'my-athena-table-name'
                    }
                }
            }
        }
    }
    main.normal_partition_refresh(config, 's3://unit-test-results', '/athena') 
    assert_true(mock_logging.info.called)


@patch('stream_alert.athena_partition_refresh.main.ATHENA_CLIENT', MockAthenaClient())
def test_run_athena_query():
    """Athena - Run Athena Query"""
    query_results = main.run_athena_query(
        query='SHOW DATABASES;',
        results_bucket='s3://unit-test-results',
        results_path='/athena'
    )

    assert_equal(query_results['ResultSet']['Rows'], [{'Data': [{'test':'test'}]}])

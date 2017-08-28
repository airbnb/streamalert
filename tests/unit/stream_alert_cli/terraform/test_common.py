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
from nose.tools import assert_equal

from stream_alert_cli.config import CLIConfig
from stream_alert_cli.terraform import _common

CONFIG = CLIConfig(config_path='tests/unit/conf')

def test_enabled_firehose_logs():
    """CLI - Terraform Common - Expected Firehose Logs """
    firehose_logs = set(_common.enabled_firehose_logs(CONFIG))

    expected_logs = {
        'test_log_type_csv',
        'test_log_type_csv_nested',
        'test_log_type_json_nested',
        'test_log_type_json_nested_with_data',
        'test_log_type_json',
        'test_log_type_kv_auditd',
        'test_multiple_schemas_01',
        'test_multiple_schemas_02',
        'test_log_type_json_2',
        'test_log_type_json_nested_osquery',
        'test_log_type_syslog',
        'test_cloudtrail',
        'unit_test_simple_log'
    }

    assert_equal(firehose_logs, expected_logs)

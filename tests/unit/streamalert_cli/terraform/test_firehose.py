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

from streamalert_cli.config import CLIConfig
from streamalert_cli.terraform import common, firehose

class TestFirehoseGenerate:
    """Class for testing firehose generation code"""
    #pylint: disable=attribute-defined-outside-init

    def setup(self):
        """Setup before each method"""
        self._logging_bucket_name = 'logging-bucket-name'
        self.config = CLIConfig(config_path='tests/unit/conf')

    def _default_firehose_config(self):
        return {
            'source': './modules/tf_kinesis_firehose_setup',
            'account_id': "12345678910",
            'prefix': 'unit-test',
            'region': 'us-west-1',
            's3_logging_bucket': self._logging_bucket_name,
            's3_bucket_name': 'unit-test.streamalert.data',
            'kms_key_id': '${aws_kms_key.server_side_encryption.key_id}'
        }

    def test_firehose_defaults(self):
        """CLI - Terraform Generate Kinesis Firehose, Defaults"""
        cluster_dict = common.infinitedict()
        firehose.generate_firehose(self._logging_bucket_name, cluster_dict, self.config)

        expected_result = {
            'module': {
                'kinesis_firehose_setup': self._default_firehose_config(),
            }
        }

        assert_equal(cluster_dict, expected_result)

    def test_firehose_enabled_log(self):
        """CLI - Terraform Generate Kinesis Firehose, Enabled Log"""
        cluster_dict = common.infinitedict()

        # Add an enabled log, with no alarm configuration (aka: alarms disabled)
        self.config['global']['infrastructure']['firehose']['enabled_logs'] = {
            'json:embedded': {}
        }

        firehose.generate_firehose(self._logging_bucket_name, cluster_dict, self.config)

        expected_result = {
            'module': {
                'kinesis_firehose_setup': self._default_firehose_config(),
                'kinesis_firehose_json_embedded': {
                    'source': './modules/tf_kinesis_firehose_delivery_stream',
                    'buffer_size': 128,
                    'buffer_interval': 900,
                    'compression_format': 'GZIP',
                    'use_prefix': True,
                    'prefix': 'unit-test',
                    'log_name': 'json_embedded',
                    'role_arn': '${module.kinesis_firehose_setup.firehose_role_arn}',
                    's3_bucket_name': 'unit-test.streamalert.data',
                    'kms_key_arn': '${aws_kms_key.server_side_encryption.arn}'
                }
            }
        }

        assert_equal(cluster_dict, expected_result)

    def test_firehose_enabled_log_alarm_defaults(self):
        """CLI - Terraform Generate Kinesis Firehose, Enabled Alarm - Default Settings"""
        cluster_dict = common.infinitedict()

        # Add an enabled log, with alarms on (will use terraform default settings)
        self.config['global']['infrastructure']['firehose']['enabled_logs'] = {
            'json:embedded': {
                'enable_alarm': True
            }
        }

        firehose.generate_firehose(self._logging_bucket_name, cluster_dict, self.config)

        expected_result = {
            'module': {
                'kinesis_firehose_setup': self._default_firehose_config(),
                'kinesis_firehose_json_embedded': {
                    'source': './modules/tf_kinesis_firehose_delivery_stream',
                    'buffer_size': 128,
                    'buffer_interval': 900,
                    'compression_format': 'GZIP',
                    'use_prefix': True,
                    'prefix': 'unit-test',
                    'log_name': 'json_embedded',
                    'role_arn': '${module.kinesis_firehose_setup.firehose_role_arn}',
                    's3_bucket_name': 'unit-test.streamalert.data',
                    'kms_key_arn': '${aws_kms_key.server_side_encryption.arn}',
                    'enable_alarm': True,
                    'alarm_actions': [
                        'arn:aws:sns:us-west-1:12345678910:unit-test_streamalert_monitoring'
                    ]
                }
            }
        }

        assert_equal(cluster_dict, expected_result)

    def test_firehose_enabled_log_alarm_custom(self):
        """CLI - Terraform Generate Kinesis Firehose, Enabled Alarm - Custom Settings"""
        cluster_dict = common.infinitedict()

        # Add an enabled log, with alarms on with custom settings
        self.config['global']['infrastructure']['firehose']['enabled_logs'] = {
            'json:embedded': {
                'enable_alarm': True,
                'evaluation_periods': 10,
                'period_seconds': 3600,
                'log_min_count_threshold': 100000
            }
        }

        firehose.generate_firehose(self._logging_bucket_name, cluster_dict, self.config)

        expected_result = {
            'module': {
                'kinesis_firehose_setup': self._default_firehose_config(),
                'kinesis_firehose_json_embedded': {
                    'source': './modules/tf_kinesis_firehose_delivery_stream',
                    'buffer_size': 128,
                    'buffer_interval': 900,
                    'compression_format': 'GZIP',
                    'use_prefix': True,
                    'prefix': 'unit-test',
                    'log_name': 'json_embedded',
                    'role_arn': '${module.kinesis_firehose_setup.firehose_role_arn}',
                    's3_bucket_name': 'unit-test.streamalert.data',
                    'kms_key_arn': '${aws_kms_key.server_side_encryption.arn}',
                    'enable_alarm': True,
                    'evaluation_periods': 10,
                    'period_seconds': 3600,
                    'alarm_threshold': 100000,
                    'alarm_actions': [
                        'arn:aws:sns:us-west-1:12345678910:unit-test_streamalert_monitoring'
                    ]
                }
            }
        }

        assert_equal(cluster_dict, expected_result)

    def test_firehose_enabled_log_alarm_custom_sns(self):
        """CLI - Terraform Generate Kinesis Firehose, Enabled Alarm - Custom SNS"""
        cluster_dict = common.infinitedict()

        # Add an enabled log, with alarms on with custom alarm actions
        self.config['global']['infrastructure']['firehose']['enabled_logs'] = {
            'json:embedded': {
                'enable_alarm': True,
                'alarm_actions': 'do something crazy'
            }
        }

        firehose.generate_firehose(self._logging_bucket_name, cluster_dict, self.config)

        expected_result = {
            'module': {
                'kinesis_firehose_setup': self._default_firehose_config(),
                'kinesis_firehose_json_embedded': {
                    'source': './modules/tf_kinesis_firehose_delivery_stream',
                    'buffer_size': 128,
                    'buffer_interval': 900,
                    'compression_format': 'GZIP',
                    'use_prefix': True,
                    'prefix': 'unit-test',
                    'log_name': 'json_embedded',
                    'role_arn': '${module.kinesis_firehose_setup.firehose_role_arn}',
                    's3_bucket_name': 'unit-test.streamalert.data',
                    'kms_key_arn': '${aws_kms_key.server_side_encryption.arn}',
                    'enable_alarm': True,
                    'alarm_actions': ['do something crazy']
                }
            }
        }

        assert_equal(cluster_dict, expected_result)

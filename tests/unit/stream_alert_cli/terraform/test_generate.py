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
from stream_alert_cli.config import CLIConfig
from stream_alert_cli.terraform import (
    common,
    cloudtrail,
    cloudwatch,
    flow_logs,
    generate,
    streamalert
)

from mock import ANY, patch
from nose.tools import assert_equal, assert_false, assert_true


class TestTerraformGenerate(object):
    """Test class for the Terraform Cluster Generating"""
    # pylint: disable=no-self-use,attribute-defined-outside-init

    def setup(self):
        """Setup before each method"""
        self.cluster_dict = common.infinitedict()
        self.config = CLIConfig(config_path='tests/unit/conf')

    @staticmethod
    def test_generate_s3_bucket():
        """CLI - Terraform Generate S3 Bucket """
        bucket = generate.generate_s3_bucket(
            bucket='unit.test.bucket',
            logging='my.s3-logging.bucket',
            force_destroy=True
        )

        required_keys = {
            'bucket',
            'acl',
            'force_destroy',
            'versioning',
            'logging',
            'server_side_encryption_configuration'
        }

        assert_equal(type(bucket), dict)
        assert_equal(bucket['bucket'], 'unit.test.bucket')
        assert_equal(set(bucket.keys()), required_keys)

    @staticmethod
    def test_generate_s3_bucket_lifecycle():
        """CLI - Terraform Generate S3 Bucket with Lifecycle"""
        bucket = generate.generate_s3_bucket(
            bucket='unit.test.bucket',
            logging='my.s3-logging.bucket',
            force_destroy=False,
            lifecycle_rule={
                'prefix': 'logs/',
                'enabled': True,
                'transition': {'days': 30, 'storage_class': 'GLACIER'}
            }
        )

        assert_equal(bucket['lifecycle_rule']['prefix'], 'logs/')
        assert_equal(bucket['force_destroy'], False)
        assert_equal(type(bucket['lifecycle_rule']), dict)
        assert_equal(type(bucket['versioning']), dict)

    def test_generate_main(self):
        """CLI - Terraform Generate Main"""
        tf_main = generate.generate_main(config=self.config, init=False)

        tf_main_expected = {
            'provider': {
                'aws': {
                    'version': generate.TERRAFORM_VERSIONS['provider']['aws']
                }
            },
            'terraform': {
                'required_version': generate.TERRAFORM_VERSIONS['application'],
                'backend': {
                    's3': {
                        'bucket': 'unit-testing.streamalert.terraform.state',
                        'key': 'stream_alert_state/terraform.tfstate',
                        'region': 'us-west-1',
                        'encrypt': True,
                        'acl': 'private',
                        'kms_key_id': 'alias/unit-testing'
                    }
                }
            },
            'resource': {
                'aws_kms_key': {
                    'server_side_encryption': {
                        'enable_key_rotation': True,
                        'description': 'StreamAlert S3 Server-Side Encryption',
                        'policy': ANY
                    },
                    'stream_alert_secrets': {
                        'enable_key_rotation': True,
                        'description': 'StreamAlert secret management'
                    }
                },
                'aws_kms_alias': {
                    'server_side_encryption': {
                        'name': 'alias/unit-testing_server-side-encryption',
                        'target_key_id': '${aws_kms_key.server_side_encryption.key_id}'
                    },
                    'stream_alert_secrets': {
                        'name': 'alias/unit-testing',
                        'target_key_id': '${aws_kms_key.stream_alert_secrets.key_id}'
                    }
                },
                'aws_s3_bucket': {
                    'stream_alert_secrets': {
                        'bucket': 'unit-testing.streamalert.secrets',
                        'acl': 'private',
                        'force_destroy': True,
                        'versioning': {
                            'enabled': True
                        },
                        'logging': {
                            'target_bucket': 'unit-testing.streamalert.s3-logging',
                            'target_prefix': 'unit-testing.streamalert.secrets/'
                        },
                        'server_side_encryption_configuration': {
                            'rule': {
                                'apply_server_side_encryption_by_default': {
                                    'sse_algorithm': 'aws:kms',
                                    'kms_master_key_id': (
                                        '${aws_kms_key.server_side_encryption.key_id}')
                                }
                            }
                        }
                    },
                    'terraform_remote_state': {
                        'bucket': 'unit-testing.streamalert.terraform.state',
                        'acl': 'private',
                        'force_destroy': True,
                        'versioning': {
                            'enabled': True
                        },
                        'logging': {
                            'target_bucket': 'unit-testing.streamalert.s3-logging',
                            'target_prefix': 'unit-testing.streamalert.terraform.state/'
                        },
                        'server_side_encryption_configuration': {
                            'rule': {
                                'apply_server_side_encryption_by_default': {
                                    'sse_algorithm': 'aws:kms',
                                    'kms_master_key_id': (
                                        '${aws_kms_key.server_side_encryption.key_id}')
                                }
                            }
                        }
                    },
                    'logging_bucket': {
                        'bucket': 'unit-testing.streamalert.s3-logging',
                        'acl': 'log-delivery-write',
                        'force_destroy': True,
                        'versioning': {
                            'enabled': True
                        },
                        'logging': {
                            'target_bucket': 'unit-testing.streamalert.s3-logging',
                            'target_prefix': 'unit-testing.streamalert.s3-logging/'
                        },
                        'lifecycle_rule': {
                            'prefix': '/',
                            'enabled': True,
                            'transition': {
                                'days': 365,
                                'storage_class': 'GLACIER'
                            }
                        },
                        'server_side_encryption_configuration': {
                            'rule': {
                                'apply_server_side_encryption_by_default': {
                                    'sse_algorithm': 'AES256'
                                }
                            }
                        }
                    },
                    'streamalerts': {
                        'bucket': 'unit-testing.streamalerts',
                        'acl': 'private',
                        'force_destroy': True,
                        'versioning': {
                            'enabled': True
                        },
                        'logging': {
                            'target_bucket': 'unit-testing.streamalert.s3-logging',
                            'target_prefix': 'unit-testing.streamalerts/'
                        },
                        'server_side_encryption_configuration': {
                            'rule': {
                                'apply_server_side_encryption_by_default': {
                                    'sse_algorithm': 'aws:kms',
                                    'kms_master_key_id': (
                                        '${aws_kms_key.server_side_encryption.key_id}')
                                }
                            }
                        }
                    }
                },
                'aws_sns_topic': {
                    'stream_alert_monitoring': {
                        'name': 'stream_alert_monitoring'
                    }
                }
            }
        }

        assert_equal(tf_main['provider'], tf_main_expected['provider'])
        assert_equal(tf_main['terraform'], tf_main_expected['terraform'])
        assert_equal(tf_main['resource'], tf_main_expected['resource'])

    def test_generate_main_with_firehose(self):
        """CLI - Terraform Generate Main with Firehose Enabled"""
        self.config['global']['infrastructure']['firehose'] = {
            'enabled': True,
            's3_bucket_suffix': 'my-data',
            'buffer_size': 10,
            'buffer_interval': 650,
            'enabled_logs': {
                'cloudwatch': {
                    'enable_alarm': False
                }
            }
        }
        tf_main = generate.generate_main(config=self.config, init=False)

        generated_modules = tf_main['module']
        expected_kinesis_modules = {
            'kinesis_firehose_setup',
            'kinesis_firehose_cloudwatch_test_match_types',
            'kinesis_firehose_cloudwatch_test_match_types_2'
        }

        assert_true(all([expected_module in generated_modules
                         for expected_module
                         in expected_kinesis_modules]))

        assert_equal(generated_modules['kinesis_firehose_cloudwatch_test_match_types']\
                                      ['s3_bucket_name'], 'unit-testing.my-data')
        assert_equal(generated_modules['kinesis_firehose_cloudwatch_test_match_types']\
                                      ['buffer_size'], 10)
        assert_equal(generated_modules['kinesis_firehose_cloudwatch_test_match_types']\
                                      ['buffer_interval'], 650)

    def test_generate_stream_alert_test(self):
        """CLI - Terraform Generate StreamAlert - Test Cluster"""
        streamalert.generate_stream_alert(
            'test',
            self.cluster_dict,
            self.config
        )

        expected_test_cluster = {
            'module': {
                'stream_alert_test': {
                    'source': 'modules/tf_stream_alert',
                    'account_id': '12345678910',
                    'region': 'us-west-1',
                    'prefix': 'unit-testing',
                    'cluster': 'test',
                    'dynamodb_ioc_table': 'test_table_name',
                    'lambda_handler': 'stream_alert.rule_processor.main.handler',
                    'threat_intel_enabled': False,
                    'rule_processor_enable_metrics': True,
                    'rule_processor_log_level': 'info',
                    'rule_processor_memory': 128,
                    'rule_processor_timeout': 25,
                    'rules_table_arn': '${module.globals.rules_table_arn}',
                }
            }
        }

        assert_equal(self.cluster_dict['module']['stream_alert_test'],
                     expected_test_cluster['module']['stream_alert_test'])

    def test_generate_stream_alert_advanced(self):
        """CLI - Terraform Generate StreamAlert - Advanced Cluster"""
        streamalert.generate_stream_alert(
            'advanced',
            self.cluster_dict,
            self.config
        )

        expected_advanced_cluster = {
            'module': {
                'stream_alert_advanced': {
                    'source': 'modules/tf_stream_alert',
                    'account_id': '12345678910',
                    'region': 'us-west-1',
                    'prefix': 'unit-testing',
                    'cluster': 'advanced',
                    'dynamodb_ioc_table': 'test_table_name',
                    'lambda_handler': 'stream_alert.rule_processor.main.handler',
                    'threat_intel_enabled': False,
                    'rule_processor_enable_metrics': True,
                    'rule_processor_log_level': 'info',
                    'rule_processor_memory': 128,
                    'rule_processor_timeout': 25,
                    'rules_table_arn': '${module.globals.rules_table_arn}',
                    'input_sns_topics': ['my-sns-topic-name'],
                }
            }
        }

        assert_equal(self.cluster_dict['module']['stream_alert_advanced'],
                     expected_advanced_cluster['module']['stream_alert_advanced'])

    def test_generate_flow_logs(self):
        """CLI - Terraform Generate Flow Logs"""
        cluster_name = 'advanced'
        flow_logs.generate_flow_logs(
            cluster_name,
            self.cluster_dict,
            self.config
        )

        flow_log_config = self.cluster_dict['module']['flow_logs_advanced']
        assert_equal(flow_log_config['flow_log_group_name'], 'unit-test-advanced')
        assert_equal(flow_log_config['vpcs'], ['vpc-id-1', 'vpc-id-2'])

    def test_generate_cloudtrail_basic(self):
        """CLI - Terraform Generate Cloudtrail Module - Legacy"""
        cluster_name = 'advanced'
        self.config['clusters']['advanced']['modules']['cloudtrail'] = {
            'enabled': True
        }
        result = cloudtrail.generate_cloudtrail(cluster_name, self.cluster_dict, self.config)

        assert_true(result)
        assert_equal(set(self.config['clusters']['advanced']['modules']['cloudtrail'].keys()),
                     {'enable_logging', 'enable_kinesis'})
        assert_equal(self.cluster_dict['module']['cloudtrail_advanced'], {
            'account_ids': ['12345678910'],
            'primary_account_id': '12345678910',
            'cluster': 'advanced',
            'kinesis_arn': '${module.kinesis_advanced.arn}',
            'prefix': 'unit-testing',
            'enable_logging': True,
            'enable_kinesis': True,
            'source': 'modules/tf_stream_alert_cloudtrail',
            's3_logging_bucket': 'unit-testing.streamalert.s3-logging',
            'existing_trail': False,
            'is_global_trail': True,
            'region': 'us-west-1',
            'exclude_home_region_events': False,
            'send_to_cloudwatch': False,
            'event_pattern': '{"account": ["12345678910"]}'
        })

    def test_generate_cloudtrail_all_options(self):
        """CLI - Terraform Generate Cloudtrail Module - All Options"""
        cluster_name = 'advanced'
        self.config['clusters']['advanced']['modules']['cloudtrail'] = {
            'enable_logging': True,
            'enable_kinesis': True,
            'existing_trail': False,
            'is_global_trail': False,
            'event_pattern': {
                'source': ['aws.ec2'],
                'account': '12345678910',
                'detail': {
                    'state': ['running']
                }
            }
        }
        cloudtrail.generate_cloudtrail(
            cluster_name,
            self.cluster_dict,
            self.config
        )

        assert_equal('cloudtrail_advanced' in self.cluster_dict['module'], True)
        assert_equal(self.cluster_dict['module']['cloudtrail_advanced'], {
            'account_ids': ['12345678910'],
            'primary_account_id': '12345678910',
            'cluster': 'advanced',
            'existing_trail': False,
            'is_global_trail': False,
            'kinesis_arn': '${module.kinesis_advanced.arn}',
            'prefix': 'unit-testing',
            'enable_logging': True,
            'enable_kinesis': True,
            'region': 'us-west-1',
            'exclude_home_region_events': False,
            'send_to_cloudwatch': False,
            'source': 'modules/tf_stream_alert_cloudtrail',
            's3_logging_bucket': 'unit-testing.streamalert.s3-logging',
            'event_pattern': '{"source": ["aws.ec2"], "account": "12345678910",'
                             ' "detail": {"state": ["running"]}}'
        })

    @patch('stream_alert_cli.terraform.cloudtrail.LOGGER_CLI')
    def test_generate_cloudtrail_invalid_event_pattern(self, mock_logging):
        """CLI - Terraform Generate Cloudtrail Module - Invalid Event Pattern"""
        cluster_name = 'advanced'
        self.config['clusters']['advanced']['modules']['cloudtrail'] = {
            'enable_logging': True,
            'enable_kinesis': True,
            'existing_trail': False,
            'is_global_trail': False,
            'event_pattern': {
                'invalid': ['aws.ec2']
            }
        }
        result = cloudtrail.generate_cloudtrail(cluster_name, self.cluster_dict, self.config)
        assert_false(result)
        assert_true(mock_logging.error.called)

    def test_generate_cloudwatch(self):
        """CLI - Terraform Generate CloudWatch"""
        cloudwatch.generate_cloudwatch(
            'advanced',
            self.cluster_dict,
            self.config
        )

        # Count the modules for each region - there should be 14 since 1 is excluded
        count = sum(1 for name in self.cluster_dict['module']
                    if name.startswith('cloudwatch_advanced'))
        assert_equal(count, 14)

        expected_config = {
            'cluster': 'advanced',
            'source': 'modules/tf_stream_alert_cloudwatch',
            'region': 'eu-west-1',
            'kinesis_stream_arn': '${module.kinesis_advanced.arn}',
            'cross_account_ids': ['123456789012', '12345678910']
        }

        eu_west_config = self.cluster_dict['module']['cloudwatch_advanced_eu-west-1']
        assert_equal(expected_config, eu_west_config)

    def test_generate_cluster_test(self):
        """CLI - Terraform Generate Test Cluster"""

        tf_cluster = generate.generate_cluster(
            config=self.config,
            cluster_name='test'
        )

        cluster_keys = {'module', 'output'}

        test_modules = {
            'stream_alert_test',
            'cloudwatch_monitoring_test',
            'kinesis_test',
            'kinesis_events_test',
            's3_events_unit-testing_test_0'
        }

        assert_equal(set(tf_cluster['module'].keys()), test_modules)
        assert_equal(set(tf_cluster.keys()), cluster_keys)

    def test_generate_cluster_advanced(self):
        """CLI - Terraform Generate Advanced Cluster"""

        tf_cluster = generate.generate_cluster(
            config=self.config,
            cluster_name='advanced'
        )

        cluster_keys = {
            'module',
            'output'
        }

        advanced_modules = {
            'stream_alert_advanced',
            'cloudwatch_advanced_eu-west-1',
            'cloudwatch_advanced_eu-west-2',
            'cloudwatch_advanced_eu-west-3',
            'cloudwatch_advanced_us-west-2',
            'cloudwatch_advanced_sa-east-1',
            'cloudwatch_advanced_eu-central-1',
            'cloudwatch_advanced_ap-northeast-2',
            'cloudwatch_advanced_ap-northeast-1',
            'cloudwatch_advanced_ap-southeast-1',
            'cloudwatch_advanced_ca-central-1',
            'cloudwatch_advanced_ap-southeast-2',
            'cloudwatch_advanced_us-east-1',
            'cloudwatch_advanced_us-east-2',
            'cloudwatch_advanced_ap-south-1',
            'cloudwatch_monitoring_advanced',
            'kinesis_advanced',
            'kinesis_events_advanced',
            'flow_logs_advanced',
            'cloudtrail_advanced',
            's3_events_unit-testing_advanced_1',
            's3_events_unit-testing_advanced_0'
        }

        assert_equal(set(tf_cluster['module'].keys()), advanced_modules)
        assert_equal(set(tf_cluster.keys()), cluster_keys)

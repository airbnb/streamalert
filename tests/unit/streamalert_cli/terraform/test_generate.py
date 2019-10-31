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
from mock import ANY, patch

from nose.tools import assert_equal, assert_dict_equal, assert_false, assert_true

from streamalert_cli.config import CLIConfig
from streamalert_cli.terraform import (
    common,
    cloudtrail,
    cloudwatch,
    flow_logs,
    generate
)


class TestTerraformGenerate:
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
            'server_side_encryption_configuration',
            'policy'
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
                    'version': '~> 2.28.1',  # Changes to this should require unit test update
                    'region': 'us-west-1'
                }
            },
            'terraform': {
                'required_version': '~> 0.12.9', # Changes to this should require unit test update
                'backend': {
                    's3': {
                        'bucket': 'unit-test.streamalert.terraform.state',
                        'key': 'stream_alert_state/terraform.tfstate',
                        'region': 'us-west-1',
                        'encrypt': True,
                        'acl': 'private',
                        'kms_key_id': 'alias/unit-test'
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
                        'name': 'alias/unit-test_server-side-encryption',
                        'target_key_id': '${aws_kms_key.server_side_encryption.key_id}'
                    },
                    'stream_alert_secrets': {
                        'name': 'alias/unit-test',
                        'target_key_id': '${aws_kms_key.stream_alert_secrets.key_id}'
                    }
                },
                'aws_s3_bucket': {
                    'stream_alert_secrets': {
                        'bucket': 'unit-test.streamalert.secrets',
                        'acl': 'private',
                        'force_destroy': True,
                        'versioning': {
                            'enabled': True
                        },
                        'logging': {
                            'target_bucket': 'unit-test.streamalert.s3-logging',
                            'target_prefix': 'unit-test.streamalert.secrets/'
                        },
                        'server_side_encryption_configuration': {
                            'rule': {
                                'apply_server_side_encryption_by_default': {
                                    'sse_algorithm': 'aws:kms',
                                    'kms_master_key_id': (
                                        '${aws_kms_key.server_side_encryption.key_id}')
                                }
                            }
                        },
                        'policy': ANY
                    },
                    'terraform_remote_state': {
                        'bucket': 'unit-test.streamalert.terraform.state',
                        'acl': 'private',
                        'force_destroy': True,
                        'versioning': {
                            'enabled': True
                        },
                        'logging': {
                            'target_bucket': 'unit-test.streamalert.s3-logging',
                            'target_prefix': 'unit-test.streamalert.terraform.state/'
                        },
                        'server_side_encryption_configuration': {
                            'rule': {
                                'apply_server_side_encryption_by_default': {
                                    'sse_algorithm': 'aws:kms',
                                    'kms_master_key_id': (
                                        '${aws_kms_key.server_side_encryption.key_id}')
                                }
                            }
                        },
                        'policy': ANY
                    },
                    'logging_bucket': {
                        'bucket': 'unit-test.streamalert.s3-logging',
                        'acl': 'log-delivery-write',
                        'force_destroy': True,
                        'versioning': {
                            'enabled': True
                        },
                        'logging': {
                            'target_bucket': 'unit-test.streamalert.s3-logging',
                            'target_prefix': 'unit-test.streamalert.s3-logging/'
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
                        },
                        'policy': ANY
                    },
                    'streamalerts': {
                        'bucket': 'unit-test.streamalerts',
                        'acl': 'private',
                        'force_destroy': True,
                        'versioning': {
                            'enabled': True
                        },
                        'logging': {
                            'target_bucket': 'unit-test.streamalert.s3-logging',
                            'target_prefix': 'unit-test.streamalerts/'
                        },
                        'server_side_encryption_configuration': {
                            'rule': {
                                'apply_server_side_encryption_by_default': {
                                    'sse_algorithm': 'aws:kms',
                                    'kms_master_key_id': (
                                        '${aws_kms_key.server_side_encryption.key_id}')
                                }
                            }
                        },
                        'policy': ANY
                    }
                },
                'aws_sns_topic': {
                    'monitoring': {
                        'name': 'unit-test_streamalert_monitoring'
                    }
                }
            }
        }

        assert_dict_equal(tf_main['provider'], tf_main_expected['provider'])
        assert_dict_equal(tf_main['terraform'], tf_main_expected['terraform'])
        assert_dict_equal(tf_main['resource'], tf_main_expected['resource'])

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

        assert_true(
            all([
                expected_module in generated_modules
                for expected_module in expected_kinesis_modules
            ])
        )

        assert_equal(
            generated_modules['kinesis_firehose_cloudwatch_test_match_types']['s3_bucket_name'],
            'unit-test.my-data'
        )
        assert_equal(
            generated_modules['kinesis_firehose_cloudwatch_test_match_types']['buffer_size'],
            10
        )
        assert_equal(
            generated_modules['kinesis_firehose_cloudwatch_test_match_types']['buffer_interval'],
            650
        )

    def test_generate_flow_logs(self):
        """CLI - Terraform Generate Flow Logs"""
        cluster_name = 'advanced'
        flow_logs.generate_flow_logs(
            cluster_name,
            self.cluster_dict,
            self.config
        )

        expected = {
            'module': {
                'flow_logs_advanced': {
                    'source': './modules/tf_flow_logs',
                    'prefix': 'unit-test',
                    'cluster': 'advanced',
                    'cloudwatch_logs_destination_arn': (
                        '${module.cloudwatch_logs_destination_advanced_us-west-1.'
                        'cloudwatch_logs_destination_arn}'
                    ),
                    'vpcs': ['vpc-id-1', 'vpc-id-2'],
                },
                'cloudwatch_logs_destination_advanced': {
                    'source': './modules/tf_cloudwatch_logs_destination',
                    'prefix': 'unit-test',
                    'cluster': 'advanced',
                    'regions': [
                        'us-west-1'
                    ],
                    'destination_kinesis_stream_arn': '${module.kinesis_advanced.arn}'
                },
                'cloudwatch_logs_destination_advanced_us-west-1': {
                    'source': './modules/tf_cloudwatch_logs_destination/modules/destination',
                    'prefix': 'unit-test',
                    'cluster': 'advanced',
                    'account_ids': [
                        '12345678910'
                    ],
                    'destination_kinesis_stream_arn': '${module.kinesis_advanced.arn}',
                    'cloudwatch_logs_subscription_role_arn': (
                        '${module.cloudwatch_logs_destination_advanced.'
                        'cloudwatch_logs_subscription_role_arn}'
                    ),
                    'providers': {
                        'aws': 'aws.us-west-1'
                    }
                }
            }
        }

        assert_equal(self.cluster_dict, expected)

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
            'prefix': 'unit-test',
            'enable_logging': True,
            'enable_kinesis': True,
            'region': 'us-west-1',
            'exclude_home_region_events': False,
            'send_to_cloudwatch': False,
            'source': './modules/tf_cloudtrail',
            's3_logging_bucket': 'unit-test.streamalert.s3-logging',
            'event_pattern': '{"source": ["aws.ec2"], "account": "12345678910",'
                             ' "detail": {"state": ["running"]}}'
        })

    @patch('streamalert_cli.terraform.cloudtrail.LOGGER')
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
        """CLI - Terraform Generate CloudWatch Destinations"""
        cloudwatch.generate_cloudwatch_destinations(
            'advanced',
            self.cluster_dict,
            self.config
        )

        expected = {
            'cloudwatch_logs_destination_advanced': {
                'source': './modules/tf_cloudwatch_logs_destination',
                'prefix': 'unit-test',
                'cluster': 'advanced',
                'regions': [
                    'us-east-2',
                    'us-west-2'
                ],
                'destination_kinesis_stream_arn': '${module.kinesis_advanced.arn}'
            },
            'cloudwatch_logs_destination_advanced_us-east-2': {
                'source': './modules/tf_cloudwatch_logs_destination/modules/destination',
                'prefix': 'unit-test',
                'cluster': 'advanced',
                'account_ids': [
                    '123456789012'
                ],
                'destination_kinesis_stream_arn': '${module.kinesis_advanced.arn}',
                'cloudwatch_logs_subscription_role_arn': (
                    '${module.cloudwatch_logs_destination_advanced.'
                    'cloudwatch_logs_subscription_role_arn}'
                ),
                'providers': {
                    'aws': 'aws.us-east-2'
                }
            },
            'cloudwatch_logs_destination_advanced_us-west-2': {
                'source': './modules/tf_cloudwatch_logs_destination/modules/destination',
                'prefix': 'unit-test',
                'cluster': 'advanced',
                'account_ids': [
                    '123456789012'
                ],
                'destination_kinesis_stream_arn': '${module.kinesis_advanced.arn}',
                'cloudwatch_logs_subscription_role_arn': (
                    '${module.cloudwatch_logs_destination_advanced.'
                    'cloudwatch_logs_subscription_role_arn}'
                ),
                'providers': {
                    'aws': 'aws.us-west-2'
                }
            }
        }

        assert_equal(expected, self.cluster_dict['module'])

    def test_generate_cluster_test(self):
        """CLI - Terraform Generate Test Cluster"""

        tf_cluster = generate.generate_cluster(
            config=self.config,
            cluster_name='test'
        )

        cluster_keys = {'module', 'output'}

        test_modules = {
            'classifier_test_lambda',
            'classifier_test_iam',
            'cloudwatch_monitoring_test',
            'kinesis_test',
            'kinesis_events_test',
            's3_events_unit-test_test_0'
        }

        assert_equal(set(tf_cluster['module']), test_modules)
        assert_equal(set(tf_cluster), cluster_keys)

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
            'classifier_advanced_lambda',
            'classifier_advanced_iam',
            'cloudwatch_logs_destination_advanced',
            # us-west-1 because of the flow logs module in the default (us-west-1) region
            'cloudwatch_logs_destination_advanced_us-west-1',
            # us-east-2 and us-west-2 because of the explicit cloudwatch_destinations
            # in these regions
            'cloudwatch_logs_destination_advanced_us-east-2',
            'cloudwatch_logs_destination_advanced_us-west-2',
            'cloudwatch_monitoring_advanced',
            'kinesis_advanced',
            'kinesis_events_advanced',
            'flow_logs_advanced',
            'cloudtrail_advanced',
            's3_events_unit-test_advanced_1',
            's3_events_unit-test_advanced_0'
        }

        assert_equal(set(tf_cluster['module'].keys()), advanced_modules)
        assert_equal(set(tf_cluster.keys()), cluster_keys)

    def test_generate_main_with_sqs_url_unspecified(self):
        """CLI - Terraform Generate Main with unspecified classifier_sqs.use_prefix"""
        del self.config['global']['infrastructure']['classifier_sqs']['use_prefix']

        result = generate.generate_main(config=self.config, init=False)

        assert_equal(result['module']['globals']['source'], './modules/tf_globals')
        assert_true(result['module']['globals']['sqs_use_prefix'])

    def test_generate_main_with_sqs_url_true(self):
        """CLI - Terraform Generate Main with classifier_sqs.use_prefix = True"""
        self.config['global']['infrastructure']['classifier_sqs']['use_prefix'] = True

        result = generate.generate_main(config=self.config, init=False)

        assert_equal(result['module']['globals']['source'], './modules/tf_globals')
        assert_true(result['module']['globals']['sqs_use_prefix'])

    def test_generate_main_with_sqs_url_false(self):
        """CLI - Terraform Generate Main with classifier_sqs.use_prefix = False"""
        self.config['global']['infrastructure']['classifier_sqs']['use_prefix'] = False

        result = generate.generate_main(config=self.config, init=False)

        assert_equal(result['module']['globals']['source'], './modules/tf_globals')
        assert_false(result['module']['globals']['sqs_use_prefix'])

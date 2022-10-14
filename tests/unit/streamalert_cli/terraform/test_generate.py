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
from unittest.mock import ANY, Mock, patch

import pytest

from streamalert.shared.exceptions import ConfigError
from streamalert_cli.config import CLIConfig
from streamalert_cli.terraform import (cloudtrail, cloudwatch_destinations,
                                       cloudwatch_events, common, flow_logs,
                                       generate)


@patch('streamalert_cli.terraform.generate.write_vars', Mock())
class TestTerraformGenerate:
    """Test class for the Terraform Cluster Generating"""
    # pylint: disable=no-self-use,attribute-defined-outside-init

    def setup(self):
        """Setup before each method"""
        self.cluster_dict = common.infinitedict()
        self.config = CLIConfig(config_path='tests/unit/conf')

    def test_generate_s3_bucket(self):
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

        assert isinstance(bucket, dict)
        assert bucket['bucket'] == 'unit.test.bucket'
        assert set(bucket.keys()) == required_keys

    def test_generate_s3_bucket_lifecycle(self):
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

        assert bucket['lifecycle_rule']['prefix'] == 'logs/'
        assert bucket['force_destroy'] == False
        assert isinstance(bucket['lifecycle_rule'], dict)
        assert isinstance(bucket['versioning'], dict)

    def test_generate_main(self):
        """CLI - Terraform Generate Main"""
        tf_main = generate.generate_main(config=self.config, init=False)

        tf_main_expected = {
            'terraform': {
                'backend': {
                    's3': {
                        'bucket': 'unit-test-streamalert-terraform-state',
                        'key': 'streamalert_state/terraform.tfstate',
                        'region': 'us-west-1',
                        'dynamodb_table': 'unit-test_streamalert_terraform_state_lock',
                        'encrypt': True,
                        'acl': 'private',
                        'kms_key_id': 'alias/alternate-alias'
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
                    'streamalert_secrets': {
                        'enable_key_rotation': True,
                        'description': 'StreamAlert secret management'
                    }
                },
                'aws_kms_alias': {
                    'server_side_encryption': {
                        'name': 'alias/unit-test_server-side-encryption',
                        'target_key_id': '${aws_kms_key.server_side_encryption.key_id}'
                    },
                    'streamalert_secrets': {
                        'name': 'alias/alternate-alias',
                        'target_key_id': '${aws_kms_key.streamalert_secrets.key_id}'
                    }
                },
                'aws_dynamodb_table': {
                    'terraform_remote_state_lock': {
                        'name': 'unit-test_streamalert_terraform_state_lock',
                        'billing_mode': 'PAY_PER_REQUEST',
                        'hash_key': 'LockID',
                        'attribute': {
                            'name': 'LockID',
                            'type': 'S'
                        },
                        'tags': {
                            'Name': 'StreamAlert'
                        }
                    }
                },
                'aws_s3_bucket': {
                    'terraform_remote_state': {
                        'bucket': 'unit-test-streamalert-terraform-state',
                        'acl': 'private',
                        'force_destroy': True,
                        'versioning': {
                            'enabled': True
                        },
                        'logging': {
                            'target_bucket': 'unit-test-streamalert-s3-logging',
                            'target_prefix': 'unit-test-streamalert-terraform-state/'
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
                        'bucket': 'unit-test-streamalert-s3-logging',
                        'acl': 'log-delivery-write',
                        'force_destroy': True,
                        'versioning': {
                            'enabled': True
                        },
                        'logging': {
                            'target_bucket': 'unit-test-streamalert-s3-logging',
                            'target_prefix': 'unit-test-streamalert-s3-logging/'
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
                        'bucket': 'unit-test-streamalerts',
                        'acl': 'private',
                        'force_destroy': True,
                        'versioning': {
                            'enabled': True
                        },
                        'logging': {
                            'target_bucket': 'unit-test-streamalert-s3-logging',
                            'target_prefix': 'unit-test-streamalerts/'
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

        assert tf_main['terraform'] == tf_main_expected['terraform']
        assert tf_main['resource'] == tf_main_expected['resource']

    def test_generate_main_s3_access_logging(self):
        """CLI - Terraform Generate Main with Alternate S3 Access Logging Bucket"""
        alt_bucket_name = 'alternative-bucket-name'
        self.config['global']['infrastructure']['s3_access_logging'] = {
            'bucket_name': alt_bucket_name
        }
        tf_main = generate.generate_main(config=self.config, init=False)

        # Should not "create" the logging bucket
        assert 'logging_bucket' not in tf_main['resource']['aws_s3_bucket']

    def test_generate_main_with_firehose(self):
        """CLI - Terraform Generate Main with Firehose Enabled"""
        self.config['global']['infrastructure']['firehose'] = {
            'enabled': True,
            'bucket_name': 'my-data',
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

        assert all(expected_module in generated_modules for expected_module in expected_kinesis_modules)

        assert (
            generated_modules['kinesis_firehose_cloudwatch_test_match_types']['s3_bucket_name'] ==
            'my-data')
        assert (
            generated_modules['kinesis_firehose_cloudwatch_test_match_types']['buffer_size'] ==
            10)
        assert (
            generated_modules['kinesis_firehose_cloudwatch_test_match_types']['buffer_interval'] ==
            650)

    def test_generate_main_alerts_firehose(self):
        """CLI - Terraform Generate Main with Alerts Firehose Config"""
        self.config['global']['infrastructure']['alerts_firehose'] = {
            'bucket_name': 'test-bucket-name',
            'buffer_interval': 600
        }
        tf_main = generate.generate_main(config=self.config, init=False)

        assert (
            tf_main['module']['globals']['alerts_firehose_bucket_name'] ==
            'test-bucket-name')
        assert (
            tf_main['module']['globals']['alerts_firehose_buffer_interval'] ==
            600)

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

        assert self.cluster_dict == expected

    def test_generate_cloudtrail_minimal(self):
        """CLI - Terraform Generate CloudTrail Module, Minimal Settings"""
        cluster_name = 'advanced'
        self.config['clusters']['advanced']['modules']['cloudtrail'] = {
            's3_settings': {
                'cross_account_ids': ['456789012345'],
                'enable_events': False,
            },
            'send_to_cloudwatch': False,
        }
        cloudtrail.generate_cloudtrail(
            cluster_name,
            self.cluster_dict,
            self.config
        )

        expected = {
            'cloudtrail_advanced': {
                'source': './modules/tf_cloudtrail',
                's3_cross_account_ids': ['12345678910', '456789012345'],
                'primary_account_id': '12345678910',
                'cluster': 'advanced',
                'prefix': 'unit-test',
                'region': 'us-west-1',
                's3_bucket_name': 'unit-test-advanced-streamalert-cloudtrail',
                's3_logging_bucket': 'unit-test-streamalert-s3-logging',
            }
        }

        assert expected == self.cluster_dict['module']

    def test_generate_cloudtrail_with_s3_events(self):
        """CLI - Terraform Generate CloudTrail Module, With S3 Events"""
        cluster_name = 'advanced'
        self.config['clusters']['advanced']['modules']['cloudtrail'] = {
            's3_settings': {
                'bucket_name': 'unit-test-bucket',
                'cross_account_ids': ['456789012345'],
                'enable_events': True,
            },
            'send_to_cloudwatch': False,
        }
        cloudtrail.generate_cloudtrail(
            cluster_name,
            self.cluster_dict,
            self.config
        )

        expected = {
            'cloudtrail_advanced': {
                'source': './modules/tf_cloudtrail',
                's3_cross_account_ids': ['12345678910', '456789012345'],
                'primary_account_id': '12345678910',
                'cluster': 'advanced',
                'prefix': 'unit-test',
                'region': 'us-west-1',
                's3_bucket_name': 'unit-test-bucket',
                's3_logging_bucket': 'unit-test-streamalert-s3-logging',
            },
            'cloudtrail_s3_events_unit-test_advanced_unit-test-bucket': {
                'source': './modules/tf_s3_events',
                'lambda_role_id': '${module.classifier_advanced_lambda.role_id}',
                'lambda_function_alias': '${module.classifier_advanced_lambda.function_alias}',
                'lambda_function_alias_arn': (
                    '${module.classifier_advanced_lambda.function_alias_arn}'
                ),
                'lambda_function_name': '${module.classifier_advanced_lambda.function_name}',
                'bucket_name': 'unit-test-bucket',
                'filters': [
                    {
                        'filter_prefix': 'AWSLogs/12345678910/CloudTrail/'
                    },
                    {
                        'filter_prefix': 'AWSLogs/456789012345/CloudTrail/'
                    }
                ]
            }
        }

        assert expected == self.cluster_dict['module']

    def test_generate_cloudtrail_with_cloudwatch_logs(self):
        """CLI - Terraform Generate CloudTrail Module, With CloudWatch Logs"""
        cluster_name = 'advanced'
        self.config['clusters']['advanced']['modules']['cloudtrail'] = {
            's3_settings': {
                'enable_events': False,
            },
            'send_to_cloudwatch': True,
        }
        cloudtrail.generate_cloudtrail(
            cluster_name,
            self.cluster_dict,
            self.config
        )

        expected = {
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
            },
            'cloudtrail_cloudwatch_advanced': {
                'source': './modules/tf_cloudtrail/modules/tf_cloudtrail_cloudwatch',
                'cluster': 'advanced',
                'prefix': 'unit-test',
                'region': 'us-west-1',
                'cloudwatch_destination_arn': (
                    '${module.cloudwatch_logs_destination_advanced_us-west-1.'
                    'cloudwatch_logs_destination_arn}'
                ),
            },
            'cloudtrail_advanced': {
                'source': './modules/tf_cloudtrail',
                's3_cross_account_ids': ['12345678910'],
                'primary_account_id': '12345678910',
                'cluster': 'advanced',
                'prefix': 'unit-test',
                'region': 'us-west-1',
                's3_bucket_name': 'unit-test-advanced-streamalert-cloudtrail',
                's3_logging_bucket': 'unit-test-streamalert-s3-logging',
                'cloudwatch_logs_role_arn': (
                    '${module.cloudtrail_cloudwatch_advanced.cloudtrail_to_cloudwatch_logs_role}'
                ),
                'cloudwatch_logs_group_arn': (
                    '${module.cloudtrail_cloudwatch_advanced.cloudwatch_logs_group_arn}'
                ),
            },
        }

        assert expected == self.cluster_dict['module']

    def test_generate_cloudtrail_cloudwatch_logs_and_s3(self):
        """CLI - Terraform Generate CloudTrail Module, With S3 and CloudWatch Logs"""
        cluster_name = 'advanced'
        self.config['clusters']['advanced']['modules']['cloudtrail'] = {
            's3_settings': {
                'cross_account_ids': ['456789012345'],
                'enable_events': True,
            },
            'send_to_cloudwatch': True,
        }
        cloudtrail.generate_cloudtrail(
            cluster_name,
            self.cluster_dict,
            self.config
        )

        expected = {
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
            },
            'cloudtrail_cloudwatch_advanced': {
                'source': './modules/tf_cloudtrail/modules/tf_cloudtrail_cloudwatch',
                'cluster': 'advanced',
                'prefix': 'unit-test',
                'region': 'us-west-1',
                'cloudwatch_destination_arn': (
                    '${module.cloudwatch_logs_destination_advanced_us-west-1.'
                    'cloudwatch_logs_destination_arn}'
                ),
            },
            'cloudtrail_advanced': {
                'source': './modules/tf_cloudtrail',
                's3_cross_account_ids': ['12345678910', '456789012345'],
                'primary_account_id': '12345678910',
                'cluster': 'advanced',
                'prefix': 'unit-test',
                'region': 'us-west-1',
                's3_bucket_name': 'unit-test-advanced-streamalert-cloudtrail',
                's3_logging_bucket': 'unit-test-streamalert-s3-logging',
                'cloudwatch_logs_role_arn': (
                    '${module.cloudtrail_cloudwatch_advanced.cloudtrail_to_cloudwatch_logs_role}'
                ),
                'cloudwatch_logs_group_arn': (
                    '${module.cloudtrail_cloudwatch_advanced.cloudwatch_logs_group_arn}'
                ),
            },
            'cloudtrail_s3_events_unit-test_advanced_unit-test-advanced-streamalert-cloudtrail': {
                'source': './modules/tf_s3_events',
                'lambda_role_id': '${module.classifier_advanced_lambda.role_id}',
                'lambda_function_alias': '${module.classifier_advanced_lambda.function_alias}',
                'lambda_function_alias_arn': (
                    '${module.classifier_advanced_lambda.function_alias_arn}'
                ),
                'lambda_function_name': '${module.classifier_advanced_lambda.function_name}',
                'bucket_name': 'unit-test-advanced-streamalert-cloudtrail',
                'filters': [
                    {
                        'filter_prefix': 'AWSLogs/456789012345/CloudTrail/'
                    }
                ]
            },
        }

        assert expected == self.cluster_dict['module']

    def test_generate_cloudwatch_destinations(self):
        """CLI - Terraform Generate CloudWatch Destinations"""
        cloudwatch_destinations.generate_cloudwatch_destinations(
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

        assert expected == self.cluster_dict['module']

    def test_generate_cloudwatch_events(self):
        """CLI - Terraform Generate CloudWatch Events"""
        cloudwatch_events.generate_cloudwatch_events(
            'advanced',
            self.cluster_dict,
            self.config
        )

        expected = {
            'cloudwatch_events_advanced': {
                'source': './modules/tf_cloudwatch_events',
                'prefix': 'unit-test',
                'cluster': 'advanced',
                'kinesis_arn': '${module.kinesis_advanced.arn}',
                'event_pattern': '{"account": ["12345678910"]}',
            },
        }

        assert expected == self.cluster_dict['module']

    def test_generate_cloudwatch_events_no_pattern(self):
        """CLI - Terraform Generate CloudWatch Events, No Pattern"""
        self.config['clusters']['advanced']['modules']['cloudwatch_events']['event_pattern'] = None

        cloudwatch_events.generate_cloudwatch_events(
            'advanced',
            self.cluster_dict,
            self.config
        )

        expected = {
            'cloudwatch_events_advanced': {
                'source': './modules/tf_cloudwatch_events',
                'prefix': 'unit-test',
                'cluster': 'advanced',
                'kinesis_arn': '${module.kinesis_advanced.arn}',
                'event_pattern': None,
            },
        }

        assert expected == self.cluster_dict['module']

    @patch('streamalert_cli.terraform.cloudwatch_events.LOGGER.error')
    def test_generate_cloudwatch_events_invalid_pattern(self, log_mock):
        """CLI - Terraform Generate CloudWatch Events, Invalid Pattern"""
        self.config['clusters']['advanced']['modules']['cloudwatch_events']['event_pattern'] = {
            'invalid': ['aws.ec2']
        }

        cloudwatch_events.generate_cloudwatch_events(
            'advanced',
            self.cluster_dict,
            self.config
        )

        assert log_mock.called

    def test_generate_cwe_cross_acct_map_regions(self):
        """CLI - Terraform Generate CloudWatch Events Cross Account Region Map"""
        # pylint: disable=protected-access
        settings = {
            'accounts': {
                '123456789012': ['us-east-1'],
                '234567890123': ['us-east-1']
            },
            'organizations': {
                'o-aabbccddee': ['us-west-1']
            }
        }

        result = cloudwatch_events._map_regions(settings)

        expected = {
            'us-east-1': {
                'accounts': ['123456789012', '234567890123'],
            },
            'us-west-1': {
                'organizations': ['o-aabbccddee']
            }
        }

        assert expected == result

    def test_generate_cloudwatch_events_cross_account(self):
        """CLI - Terraform Generate CloudWatch Events Cross Account"""
        self.config['clusters']['advanced']['modules']['cloudwatch_events']['cross_account'] = {
            'accounts': {
                '123456789012': ['us-east-1'],
                '234567890123': ['us-east-1']
            },
            'organizations': {
                'o-aabbccddee': ['us-west-1']
            }
        }
        cloudwatch_events.generate_cloudwatch_events(
            'advanced',
            self.cluster_dict,
            self.config
        )

        expected = {
            'cloudwatch_events_advanced': {
                'source': './modules/tf_cloudwatch_events',
                'prefix': 'unit-test',
                'cluster': 'advanced',
                'kinesis_arn': '${module.kinesis_advanced.arn}',
                'event_pattern': '{"account": ["12345678910"]}',
            },
            'cloudwatch_events_cross_account_advanced_us-east-1': {
                'source': './modules/tf_cloudwatch_events/cross_account',
                'region': 'us-east-1',
                'accounts': ['123456789012', '234567890123'],
                'organizations': [],
                'providers': {
                    'aws': 'aws.us-east-1'
                }
            },
            'cloudwatch_events_cross_account_advanced_us-west-1': {
                'source': './modules/tf_cloudwatch_events/cross_account',
                'region': 'us-west-1',
                'accounts': [],
                'organizations': ['o-aabbccddee'],
                'providers': {
                    'aws': 'aws.us-west-1'
                }
            },
        }

        assert expected == self.cluster_dict['module']

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
            's3_events_unit-test_test_unit-test-bucket'
        }

        assert set(tf_cluster['module']) == test_modules
        assert set(tf_cluster) == cluster_keys

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
            'cloudwatch_events_advanced',
            's3_events_unit-test_advanced_unit-test-bucket_data',
            's3_events_unit-test_advanced_unit-test_cloudtrail_data'
        }

        assert set(tf_cluster['module'].keys()) == advanced_modules
        assert set(tf_cluster.keys()) == cluster_keys

    def test_generate_main_with_sqs_url_unspecified(self):
        """CLI - Terraform Generate Main with unspecified classifier_sqs.use_prefix"""
        del self.config['global']['infrastructure']['classifier_sqs']['use_prefix']

        result = generate.generate_main(config=self.config, init=False)

        assert result['module']['globals']['source'] == './modules/tf_globals'
        assert result['module']['globals']['sqs_use_prefix']

    def test_generate_main_with_sqs_url_true(self):
        """CLI - Terraform Generate Main with classifier_sqs.use_prefix = True"""
        self.config['global']['infrastructure']['classifier_sqs']['use_prefix'] = True

        result = generate.generate_main(config=self.config, init=False)

        assert result['module']['globals']['source'] == './modules/tf_globals'
        assert result['module']['globals']['sqs_use_prefix']

    def test_generate_main_with_sqs_url_false(self):
        """CLI - Terraform Generate Main with classifier_sqs.use_prefix = False"""
        self.config['global']['infrastructure']['classifier_sqs']['use_prefix'] = False

        result = generate.generate_main(config=self.config, init=False)

        assert result['module']['globals']['source'] == './modules/tf_globals'
        assert not result['module']['globals']['sqs_use_prefix']

    def test_generate_required_lambda_invalid_config(self):
        "CLI - Terraform Generate Global Lambda Settings, Invalid Config"

        pytest.raises(
            ConfigError,
            generate.generate_global_lambda_settings,
            config=self.config,
            conf_name='athena_partition_refresh_config',
            generate_func='test_func',
            tf_tmp_file_name='test_tf_tmp_file_path',
        )

    @patch('logging.Logger.warning')
    def test_generate_optional_lambda_not_in_config(self, log_mock):
        "CLI - Terraform Generate Global Lambda Settings, Optional Missing in Config"
        fake_opt_conf_name = 'fake_optional_conf_name'
        generate.generate_global_lambda_settings(
            config=self.config,
            conf_name=fake_opt_conf_name,
            generate_func='test_func',
            tf_tmp_file_name='test_tf_tmp_file_path',
            required=False,
        )

        log_mock.assert_called_with(
            'Optional configuration missing in lambda.json, skipping: %s', fake_opt_conf_name
        )

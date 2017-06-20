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

import base64
import json

from nose.tools import assert_equal

from stream_alert_cli import terraform_generate


class TestTerraformGenerate(object):
    """Test class for the Terraform Cluster Generating"""

    def setup(self):
        """Setup before each method"""
        self.cluster_dict = terraform_generate.infinitedict()
        self.config = {
            'global': {
                'account': {
                    'prefix': 'unit-testing',
                    'kms_key_alias': 'unit-testing',
                    'region': 'us-west-1',
                    'aws_account_id': '12345678910'
                },
                'terraform': {
                    'tfstate_bucket': 'unit-testing.terraform.tfstate'
                }
            },
            'lambda': {
                'rule_processor_config': {
                    'source_bucket': 'unit.testing.source.bucket'
                }
            },
            'clusters': {
                'test': {
                    'id': 'test',
                    'modules': {
                        'cloudwatch_monitoring': {
                          'enabled': True
                        },
                        'kinesis': {
                            'firehose': {
                                'enabled': True,
                                's3_bucket_suffix': 'streamalert.results'
                            },
                            'streams': {
                                'retention': 24,
                                'shards': 1
                            }
                        },
                        'kinesis_events': {
                            'enabled': True
                        },
                        'stream_alert': {
                            'alert_processor': {
                                'current_version': '$LATEST',
                                'memory': 128,
                                'timeout': 25
                            },
                            'rule_processor': {
                                'current_version': '$LATEST',
                                'memory': 128,
                                'timeout': 25
                            }
                        }
                    },
                    'outputs': {
                        'kinesis': [
                            'username',
                            'access_key_id',
                            'secret_key'
                        ]
                    },
                    'region': 'us-west-1'
                },
                'advanced': {
                    'id': 'advanced',
                    'modules': {
                        'cloudwatch_monitoring': {
                          'enabled': True
                        },
                        'kinesis': {
                            'firehose': {
                                'enabled': True,
                                's3_bucket_suffix': 'streamalert.results'
                            },
                            'streams': {
                                'retention': 24,
                                'shards': 1
                            }
                        },
                        'kinesis_events': {
                            'enabled': True
                        },
                        'stream_alert': {
                            'alert_processor': {
                                'current_version': '$LATEST',
                                'memory': 128,
                                'timeout': 25,
                                'vpc_config': {
                                    'subnet_ids': [
                                        'subnet-id-1'
                                    ],
                                    'security_group_ids': [
                                        'sg-id-1'
                                    ]
                                }
                            },
                            'rule_processor': {
                                'current_version': '$LATEST',
                                'memory': 128,
                                'timeout': 25
                            }
                        },
                        'cloudtrail': {
                            'enabled': True
                        },
                        'flow_logs': {
                            'enabled': True,
                            'vpcs': [
                                'vpc-id-1',
                                'vpc-id-2'
                            ],
                            'log_group_name': 'unit-test-advanced'
                        }
                    },
                    'outputs': {
                        'kinesis': [
                            'username',
                            'access_key_id',
                            'secret_key'
                        ]
                    },
                    'region': 'us-west-1'
                }
            }
        }

    def teardown(self):
        """Teardown after each method"""

    def test_generate_s3_bucket(self):
        """CLI - Terraform Generate S3 Bucket """
        bucket = terraform_generate.generate_s3_bucket(
            bucket='unit.test.bucket',
            logging='my.s3-logging.bucket',
            force_destroy=True
        )

        required_keys = {
            'bucket',
            'acl',
            'force_destroy',
            'versioning',
            'logging'
        }

        assert_equal(type(bucket), dict)
        assert_equal(bucket['bucket'], 'unit.test.bucket')
        assert_equal(set(bucket.keys()), required_keys)

    def test_generate_s3_bucket_lifecycle(self):
        """CLI - Terraform Generate S3 Bucket with Lifecycle"""
        bucket = terraform_generate.generate_s3_bucket(
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
        init = False

        tf_main = terraform_generate.generate_main(
            config=self.config,
            init=init
        )

        tf_main_expected = {
            'provider': {
                'aws': {}
            },
            'terraform': {
                'required_version': '> 0.9.4',
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
                    'stream_alert_secrets': {
                        'enable_key_rotation': True,
                        'description': 'StreamAlert secret management'
                    }
                },
                'aws_kms_alias': {
                    'stream_alert_secrets': {
                        'name': 'alias/unit-testing',
                        'target_key_id': '${aws_kms_key.stream_alert_secrets.key_id}'
                    }
                },
                'aws_s3_bucket': {
                    'lambda_source': {
                        'bucket': 'unit.testing.source.bucket',
                        'acl': 'private',
                        'force_destroy': False,
                        'versioning': {
                            'enabled': True
                        },
                        'logging': {
                            'target_bucket': 'unit-testing.streamalert.s3-logging',
                            'target_prefix': 'unit.testing.source.bucket/'
                        }
                    },
                    'stream_alert_secrets': {
                        'bucket': 'unit-testing.streamalert.secrets',
                        'acl': 'private',
                        'force_destroy': False,
                        'versioning': {
                            'enabled': True
                        },
                        'logging': {
                            'target_bucket': 'unit-testing.streamalert.s3-logging',
                            'target_prefix': 'unit-testing.streamalert.secrets/'
                        }
                    },
                    'terraform_remote_state': {
                        'bucket': 'unit-testing.terraform.tfstate',
                        'acl': 'private',
                        'force_destroy': False,
                        'versioning': {
                            'enabled': True
                        },
                        'logging': {
                            'target_bucket': 'unit-testing.streamalert.s3-logging',
                            'target_prefix': 'unit-testing.terraform.tfstate/'
                        }
                    },
                    'logging_bucket': {
                        'bucket': 'unit-testing.streamalert.s3-logging',
                        'acl': 'log-delivery-write',
                        'force_destroy': False,
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
                                'days': 30,
                                'storage_class': 'GLACIER'
                            }
                        }
                    }
                }
            }
        }

        assert_equal(tf_main['provider'], tf_main_expected['provider'])
        assert_equal(tf_main['terraform'], tf_main_expected['terraform'])
        assert_equal(tf_main['resource'], tf_main_expected['resource'])

    def test_generate_stream_alert(self):
        """CLI - Terraform Generate stream_alert Module"""
        #TODO(jacknagz): Write this test
        pass

    def test_generate_cloudwatch_monitoring(self):
        """CLI - Terraform Generate cloudwatch_monitoring Module"""
        cluster_name = 'test'
        terraform_generate.generate_cloudwatch_monitoring(
            cluster_name,
            self.cluster_dict,
            self.config
        )

        expected_cloudwatch_tf = {
            'source': 'modules/tf_stream_alert_monitoring',
            'sns_topic_arn': '${module.stream_alert_test.sns_topic_arn}',
            'lambda_functions': [
                'unit-testing_test_streamalert_rule_processor',
                'unit-testing_test_streamalert_alert_processor'
            ],
            'kinesis_stream': 'unit-testing_test_stream_alert_kinesis'
        }

        assert_equal(
            self.cluster_dict['module']['cloudwatch_monitoring_test'],
            expected_cloudwatch_tf)

    def test_generate_cluster_test(self):
        """CLI - Terraform Generate 'Test' Cluster"""

        tf_cluster = terraform_generate.generate_cluster(
            config=self.config,
            cluster_name='test'
        )

        cluster_keys = {
            'module',
            'output'
        }

        test_modules = {
            'stream_alert_test',
            'cloudwatch_monitoring_test',
            'kinesis_test',
            'kinesis_events_test'
        }

        assert_equal(set(tf_cluster['module'].keys()), test_modules)
        assert_equal(set(tf_cluster.keys()), cluster_keys)

    def test_generate_cluster_advanced(self):
        """CLI - Terraform Generate 'Advanced' Cluster"""

        tf_cluster = terraform_generate.generate_cluster(
            config=self.config,
            cluster_name='advanced'
        )

        cluster_keys = {
            'module',
            'output'
        }

        advanced_modules = {
            'stream_alert_advanced',
            'cloudwatch_monitoring_advanced',
            'kinesis_advanced',
            'kinesis_events_advanced',
            'flow_logs_advanced',
            'cloudtrail_advanced'
        }

        assert_equal(set(tf_cluster['module'].keys()), advanced_modules)
        assert_equal(set(tf_cluster.keys()), cluster_keys)

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
import json


class MockCLIConfig:
    """Fake CLI Config Class"""

    def __init__(self, config):
        self.config = config
        self.build_directory = 'streamalert_terraform_unit_test'

    def __repr__(self):
        return json.dumps(self.config)

    def __getitem__(self, key):
        return self.config[key]

    def __setitem__(self, key, new_value):
        self.config.__setitem__(key, new_value)

    def clusters(self):
        return list(self.config['clusters'].keys())

    def get(self, key):
        return self.config.get(key)

    def write(self):
        pass


def basic_streamalert_config():
    """Generate basic StreamAlert configuration dictionary."""
    return {
        'global': {
            'account': {
                'aws_account_id': '123456789123',
                'prefix': 'unit-test',
                'region': 'us-west-2'
            },
            'general': {
                'terraform_files': [
                    '/test/terraform/file.tf'
                ]
            },
            'infrastructure': {
                'monitoring': {},
                's3_access_logging': {
                    'bucket_name': 'unit-test-streamalert-s3-logging'
                }
            }
        },
        'scheduled_queries': {},
        'threat_intel': {
            'dynamodb_table_name': 'table_name',
            'enabled': False,
            'excluded_iocs': {},
            'normalized_ioc_types': {
                'ip': [
                    'sourceAddress',
                    'destinationAddress'
                ]
            }
        },
        'normalized_types': {
            'test_cloudtrail': {
                'sourceAddress': [
                    'sourceIPAddress'
                ]
            },
            'test_cloudwatch': {
                'destinationAddress': [
                    'destination'
                ]
            }
        },
        'logs': {
            'json_log': {
                'schema': {
                    'name': 'string'
                },
                'parser': 'json'
            },
            'json:log.with.dots': {
                'schema': {
                    'name': 'string'
                },
                'parser': 'json'
            },
            'csv_log': {
                'schema': {
                    'data': 'string',
                    'uid': 'integer'
                },
                'parser': 'csv'
            }
        },
        'lambda': {
            'alert_merger_config': {
                'memory': 128,
                'timeout': 10
            },
            'alert_processor_config': {
                'memory': 128,
                'timeout': 10
            },
            'athena_partitioner_config': {
                'enable_custom_metrics': False,
                'memory': 128,
                'timeout': 60
            },
            'rules_engine_config': {
                'custom_metric_alarms': {
                    'Aggregate Unit Testing Failed Parses Alarm': {
                        'alarm_description': '',
                        'comparison_operator': 'GreaterThanOrEqualToThreshold',
                        'evaluation_periods': 1,
                        'metric_name': 'RulesEngine-FailedParses',
                        'period': 300,
                        'statistic': 'Sum',
                        'threshold': 1.0
                    }
                }
            },
            'threat_intel_downloader_config': {
                'autoscale': True,
                'enabled': True,
                'interval': 'rate(1 day)',
                'ioc_filters': [],
                'ioc_keys': [],
                'ioc_types': [],
                'log_level': 'info',
                'max_read_capacity': 1000,
                'memory': 128,
                'min_read_capacity': 100,
                'table_rcu': 1000,
                'table_wcu': 200,
                'target_utilization': 70,
                'timeout': 120
            }
        },
        'clusters': {
            'prod': {
                'id': 'prod',
                'classifier_config': {
                    'enable_custom_metrics': True,
                    'log_level': 'info',
                    'memory': 128,
                    'custom_metric_alarms': {
                        'Prod Unit Testing Failed Parses Alarm': {
                            'alarm_description': '',
                            'comparison_operator': 'GreaterThanOrEqualToThreshold',
                            'evaluation_periods': 1,
                            'metric_name': 'Classifier-FailedParses-PROD',
                            'period': 300,
                            'statistic': 'Sum',
                            'threshold': 1.0
                        }
                    },
                    'timeout': 10
                },
                'data_sources': {
                    'kinesis': {
                        'stream_1': [
                            'json_log',
                            'csv_log'
                        ]
                    }
                },
                'modules': {
                    'cloudwatch_monitoring': {
                        'enabled': True
                    },
                    'kinesis': {
                        'streams': {
                            'retention': 24,
                            'shards': 1
                        }
                    },
                    'kinesis_events': {
                        'enabled': True
                    }
                },
                'outputs': {
                    'kinesis': [
                        'username',
                        'access_key_id',
                        'secret_key'
                    ]
                },
                'region': 'us-east-1'
            },
            'corp': {
                'id': 'corp',
                'classifier_config': {
                    'enable_custom_metrics': True,
                    'log_level': 'info',
                    'memory': 128,
                    'custom_metric_alarms': {
                        'Prod Unit Testing Failed Parses Alarm': {
                            'alarm_description': '',
                            'comparison_operator': 'GreaterThanOrEqualToThreshold',
                            'evaluation_periods': 1,
                            'metric_name': 'Classifier-FailedParses-PROD',
                            'period': 300,
                            'statistic': 'Sum',
                            'threshold': 1.0
                        }
                    },
                    'timeout': 10
                },
                'modules': {
                    'streamalert_apps': {
                        'unit-test_corp_box_admin_events_box_collector_app': {
                            'app_name': 'box_collector',
                            'concurrency_limit': 2,
                            'log_level': 'info',
                            'log_retention_days': 14,
                            'memory': 128,
                            'metric_alarms': {
                                'errors': {
                                    'enabled': True,
                                    'evaluation_periods': 1,
                                    'period_secs': 120
                                }
                            },
                            'schedule_expression': 'rate(5 minutes)',
                            'timeout': 60,
                            'type': 'box_admin_events'
                        },
                        'unit-test_corp_duo_admin_duo_admin_collector_app': {
                            'app_name': 'duo_admin_collector',
                            'concurrency_limit': 2,
                            'log_level': 'info',
                            'log_retention_days': 14,
                            'memory': 128,
                            'metric_alarms': {
                                'errors': {
                                    'enabled': True,
                                    'evaluation_periods': 1,
                                    'period_secs': 120
                                }
                            },
                            'schedule_expression': 'rate(30 minutes)',
                            'timeout': 40,
                            'type': 'duo_admin'
                        }
                    }
                },
                'region': 'us-east-1'
            }
        }
    }


def athena_cli_basic_config():
    return {
        'global': {
            'account': {
                'aws_account_id': '123456789123',
                'prefix': 'unit-test',
                'region': 'us-west-2'
            },
            'infrastructure': {
                'firehose': {
                    'enabled': True,
                    'enabled_logs': {
                        'unit': {}
                    },
                }
            }
        },
        'logs': {
            'unit:my_test': {
                'schema': {
                    'name': 'string'
                },
                'parser': 'json'
            }
        },
        'lambda': {
            'athena_partitioner_config': {}
        }
    }

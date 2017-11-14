"""Basic helper methods available to all tests."""
from contextlib import contextmanager
import io
import json

import mock


class NotMocked(Exception):
    """Borrowed from http://bit.ly/2uyWD9X"""
    def __init__(self, filename):
        super(NotMocked, self).__init__(
            "The file %s was opened, but not mocked." % filename)
        self.filename = filename


@contextmanager
def mock_open(filename, contents=None, complain=True):  # pylint: disable=unused-argument
    """Mock the open() builtin function on a specific filename.

    Let execution pass through to open() on files different than
    `filename`. Return a StringIO with `contents` if the file was
    matched. If the `contents` parameter is not given or if it is None,
    a StringIO instance simulating an empty file is returned.

    If `complain` is True (default), will raise an AssertionError if
    `filename` was not opened in the enclosed block. A NotMocked
    exception will be raised if open() was called with a file that was
    not mocked by mock_open.
    """
    open_files = set()

    def mock_file(*args):
        """Mock file object."""
        if args[0] == filename:
            f = io.StringIO(contents.decode('utf-8'))
            f.name = filename
        else:
            mocked_file.stop()
            f = open(*args)
            mocked_file.start()
        open_files.add(f.name)
        return f

    mocked_file = mock.patch('__builtin__.open', mock_file)
    mocked_file.start()

    try:
        yield
    except NotMocked as e:
        if e.filename != filename:
            raise

    mocked_file.stop()


class MockCLIConfig(object):
    """Fake CLI Config Class"""

    def __init__(self, **kwargs):
        self.config = kwargs['config']

    def __repr__(self):
        return json.dumps(self.config)

    def __getitem__(self, key):
        return self.config[key]

    def __setitem__(self, key, new_value):
        self.config.__setitem__(key, new_value)
        self.write()

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
                'kms_key_alias': 'stream_alert_secrets',
                'prefix': 'unit-testing',
                'region': 'us-west-2'
            },
            'terraform': {
                'tfstate_bucket': 'unit-testing.streamalert.terraform.state',
                'tfstate_s3_key': 'stream_alert_state/terraform.tfstate',
                'tfvars': 'terraform.tfvars'
            },
            'infrastructure': {
                'monitoring': {
                    'create_sns_topic': True,
                    'metric_alarms': {
                        'rule_processor': {
                            'Aggregate Unit Testing Failed Parses Alarm': {
                                'alarm_description': '',
                                'comparison_operator': 'GreaterThanOrEqualToThreshold',
                                'evaluation_periods': 1,
                                'metric_name': 'RuleProcessor-FailedParses',
                                'period': 300,
                                'statistic': 'Sum',
                                'threshold': 1.0
                            }
                        }
                    }
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
                'current_version': '$LATEST',
                'enable_metrics': False,
                'enabled': True,
                'handler': 'main.handler',
                'memory': 128,
                'partitioning': {
                    'firehose': {},
                    'normal': {
                        'unit-testing.streamalerts': 'alerts'
                    }
                },
                'source_bucket': 'unit-testing.streamalert.source',
                'source_current_hash': '<auto_generated>',
                'source_object_key': '<auto_generated>',
                'third_party_libraries': [],
                'timeout': 60
            },
        },
        'clusters': {
            'prod': {
                'id': 'prod',
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
                            'timeout': 10
                        },
                        'rule_processor': {
                            'current_version': '$LATEST',
                            "enable_metrics": True,
                            'memory': 128,
                            'metric_alarms': {
                                'Prod Unit Testing Failed Parses Alarm': {
                                    'alarm_description': '',
                                    'comparison_operator': 'GreaterThanOrEqualToThreshold',
                                    'evaluation_periods': 1,
                                    'metric_name': 'RuleProcessor-FailedParses-PROD',
                                    'period': 300,
                                    'statistic': 'Sum',
                                    'threshold': 1.0
                                }
                            },
                            'timeout': 10
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
                'region': 'us-east-1'
            }
        }
    }

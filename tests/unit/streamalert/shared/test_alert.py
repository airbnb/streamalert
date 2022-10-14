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
import copy
import json
from datetime import datetime, timedelta

import pytest

from streamalert.shared.alert import Alert, AlertCreationError


class TestAlert:
    """Test shared Alert class."""
    # pylint: disable=no-self-use,protected-access,too-many-public-methods

    @staticmethod
    def _basic_alert():
        return Alert('test_rule', {'abc': 123}, {'aws-firehose:alerts', 'aws-sns:test-output'})

    @staticmethod
    def _customized_alert():
        return Alert(
            'test_rule',
            {'abc': 123},
            {'aws-firehose:alerts', 'aws-sns:test-output', 'aws-s3:other-output'},
            alert_id='abc-123',
            attempts=1,
            cluster='',
            context={'rule': 'context'},
            created=datetime.utcnow(),
            dispatched=datetime.utcnow(),
            log_source='source',
            log_type='csv',
            merge_by_keys=['abc'],
            merge_window=timedelta(minutes=5),
            outputs_sent={'aws-sns:test-output'},
            rule_description='A Test Rule',
            source_entity='entity',
            source_service='s3',
            staged=True
        )

    def test_alert_encoder_invalid_json(self):
        """Alert Class - Alert Encoder - Invalid JSON raises parent exception"""
        pytest.raises(TypeError, json.dumps, RuntimeWarning, default=list)

    def test_init_invalid_kwargs(self):
        """Alert Class - Init With Invalid Kwargs"""
        pytest.raises(AlertCreationError, Alert, '', {}, set(), cluster='test', invalid='nonsense')

    def test_ordering(self):
        """Alert Class - Alerts Are Sorted By Creation"""
        alerts = [self._basic_alert() for _ in range(5)]
        assert alerts == sorted([alerts[0], alerts[3], alerts[1], alerts[4], alerts[2]])

    def test_repr(self):
        """Alert Class - Complete Alert Representation"""
        assert isinstance(repr(self._basic_alert()), str)
        assert isinstance(repr(self._customized_alert()), str)

    def test_str(self):
        """Alert Class - To String"""
        alert = self._customized_alert()
        assert '<Alert abc-123 triggered from test_rule>' == str(alert)

    def test_dynamo_key(self):
        """Alert Class - Dynamo Key"""
        alert = self._customized_alert()
        assert {'RuleName': 'test_rule', 'AlertID': 'abc-123'} == alert.dynamo_key

    def test_remaining_outputs_merge_disabled(self):
        """Alert Class - Remaining Outputs - No Merge Information"""
        alert = self._basic_alert()
        assert alert.outputs == alert.remaining_outputs

        # One output sent successfully
        alert.outputs_sent = {'aws-sns:test-output'}
        assert {'aws-firehose:alerts'} == alert.remaining_outputs

        # All outputs sent successfully
        alert.outputs_sent = {'aws-firehose:alerts', 'aws-sns:test-output'}
        assert set() == alert.remaining_outputs

    def test_remaining_outputs_merge_enabled(self):
        """Alert Class - Remaining Outputs - With Merge Config"""
        # Only the required firehose output shows as remaining
        assert {'aws-firehose:alerts'} == self._customized_alert().remaining_outputs

    def test_dynamo_record(self):
        """Alert Class - Dynamo Record"""
        # Make sure there are no empty strings nor sets (not allowed in Dynamo)
        alert = Alert(
            'test_rule', {}, {'aws-sns:test-output'},
            cluster='',
            created='',
            log_source='',
            log_type='',
            outputs_sent=set(),
            rule_description='',
            source_entity='',
            source_service=''
        )
        record = alert.dynamo_record()
        assert '' not in list(record.values())
        assert set() not in list(record.values())

    def test_create_from_dynamo_record(self):
        """Alert Class - Create Alert from Dynamo Record"""
        alert = self._customized_alert()
        # Converting to a Dynamo record and back again should result in the exact same alert
        record = alert.dynamo_record()
        new_alert = Alert.create_from_dynamo_record(record)
        assert alert.dynamo_record() == new_alert.dynamo_record()

    def test_create_from_dynamo_record_invalid(self):
        """Alert Class - AlertCreationError raised for an invalid Dynamo Record"""
        pytest.raises(AlertCreationError, Alert.create_from_dynamo_record, {})

    def test_output_dict(self):
        """Alert Class - Output Dict"""
        alert = self._basic_alert()
        result = alert.output_dict()
        # Ensure result is JSON-serializable (no sets)
        assert isinstance(json.dumps(result), str)
        # Ensure result is Athena compatible (no None values)
        assert None not in list(result.values())

    def test_can_merge_no_config(self):
        """Alert Class - Can Merge - False if Either Alert Does Not Have Merge Config"""
        assert not self._basic_alert().can_merge(self._customized_alert())
        assert not self._customized_alert().can_merge(self._basic_alert())

    def test_can_merge_too_far_apart(self):
        """Alert Class - Can Merge - False if Outside Merge Window"""
        alert1 = Alert(
            '', {'key': True}, set(),
            created=datetime(year=2000, month=1, day=1, minute=0),
            merge_by_keys=['key'],
            merge_window=timedelta(minutes=10)
        )
        alert2 = Alert(
            '', {'key': True}, set(),
            created=datetime(year=2000, month=1, day=1, minute=11),
            merge_by_keys=['key'],
            merge_window=timedelta(minutes=10)
        )
        assert not alert1.can_merge(alert2)
        assert not alert2.can_merge(alert1)

    def test_can_merge_different_merge_keys(self):
        """Alert Class - Can Merge - False if Different Merge Keys Defined"""
        alert1 = Alert(
            '', {'key': True}, set(),
            merge_by_keys=['key'],
            merge_window=timedelta(minutes=10)
        )
        alert2 = Alert(
            '', {'key': True}, set(),
            merge_by_keys=['other'],
            merge_window=timedelta(minutes=10)
        )
        assert not alert1.can_merge(alert2)
        assert not alert2.can_merge(alert1)

    def test_can_merge_key_not_common(self):
        """Alert Class - Can Merge - False if Merge Key Not Present in Both Records"""
        alert1 = Alert(
            '', {'key': True}, set(),
            merge_by_keys=['key'],
            merge_window=timedelta(minutes=10)
        )
        alert2 = Alert(
            '', {'other': True}, set(),
            merge_by_keys=['key'],
            merge_window=timedelta(minutes=10)
        )
        assert not alert1.can_merge(alert2)
        assert not alert2.can_merge(alert1)

    def test_can_merge_different_values(self):
        """Alert Class - Can Merge - False if Merge Key has Different Values"""
        alert1 = Alert(
            '', {'key': True}, set(),
            merge_by_keys=['key'],
            merge_window=timedelta(minutes=10)
        )
        alert2 = Alert(
            '', {'key': False}, set(),
            merge_by_keys=['key'],
            merge_window=timedelta(minutes=10)
        )
        assert not alert1.can_merge(alert2)
        assert not alert2.can_merge(alert1)

    def test_can_merge_merge_keys_absent(self):
        """Alert Class - Can Merge - True if Merge Keys Do Not Exist in Either Record"""
        alert1 = Alert('', {}, set(), merge_by_keys=['key'], merge_window=timedelta(minutes=10))
        alert2 = Alert('', {}, set(), merge_by_keys=['key'], merge_window=timedelta(minutes=10))
        assert alert1.can_merge(alert2)
        assert alert2.can_merge(alert1)

    def test_can_merge_true(self):
        """Alert Class - Can Merge - True Result"""
        alert1 = Alert(
            '', {'key': True}, set(),
            created=datetime(year=2000, month=1, day=1, minute=0),
            merge_by_keys=['key'],
            merge_window=timedelta(minutes=10)
        )
        alert2 = Alert(
            '', {'key': True, 'other': True}, set(),
            created=datetime(year=2000, month=1, day=1, minute=10),
            merge_by_keys=['key'],
            merge_window=timedelta(minutes=10)
        )
        assert alert1.can_merge(alert2)
        assert alert2.can_merge(alert1)

    def test_compute_common_empty_record(self):
        """Alert Class - Compute Common - Empty Record List"""
        assert {} == Alert._compute_common([])

    def test_compute_common_single_record(self):
        """Alert Class - Compute Common - Single Record"""
        # The greatest common subset of a single record is itself
        record = {'a': 1, 'b': 2, 'c': {'d': {'e': 3}}}
        assert record == Alert._compute_common([record])

    def test_compute_common_top_level(self):
        """Alert Class - Compute Common - No Nested Dictionaries"""
        record1 = {'a': 1, 'b': 2, 'c': 3}
        record2 = {'b': 2, 'c': 3, 'd': 4}
        record3 = {'c': 3, 'd': 4, 'e': 5}
        assert {'c': 3} == Alert._compute_common([record1, record2, record3])

    def test_compute_common_no_similarities(self):
        """Alert Class - Compute Common - Empty Common Set"""
        record1 = {'a': -1, 'b': -2, 'c': -3, 'd': {'e': 0}}
        record2 = {'a': 1, 'b': 2, 'c': 3}
        assert {} == Alert._compute_common([record1, record2])

    def test_compute_common_partial_nested(self):
        """Alert Class - Compute Common - Some Common Features in Nested Dictionary"""
        # This is the example given in the docstring
        record1 = {'abc': 123, 'nested': {'A': 1, 'B': 2}}
        record2 = {'abc': 123, 'def': 456, 'nested': {'A': 1}}
        assert {'abc': 123, 'nested': {'A': 1}} == Alert._compute_common([record1, record2])

    def test_compute_common_different_types(self):
        """Alert Class - Compute Common - Same Keys, Different Types"""
        record1 = {'a': 1, 'b': None, 'c': {'d': {'e': 5}, 'f': {'g': 6}}}
        record2 = {'a': '1', 'b': 0, 'c': []}
        assert {} == Alert._compute_common([record1, record2])

    def test_compute_common_many_nested(self):
        """Alert Class - Compute Common - Multiple Levels of Nesting"""
        record1 = {
            'a': {
                'b': {
                    'c': 3,
                    'd': 4
                },
                'e': {
                    'h': {
                        'i': 9
                    }
                },
                'j': {}
            }
        }
        record2 = {
            'a': {
                'b': {
                    'c': 3,
                },
                'e': {
                    'f': {
                        'g': 8
                    },
                    'h': {}
                },
                'j': {}
            }
        }
        expected = {
            'a': {
                'b': {
                    'c': 3
                },
                'j': {}
            }
        }
        assert expected == Alert._compute_common([record1, record2])

    def test_compute_common_all_identical(self):
        """Alert Class - Compute Common - Identical Records"""
        record = {'a': 1, 'b': 2, 'c': {'d': {'e': 3}}}
        assert record == Alert._compute_common([record] * 4)

    def test_compute_diff_no_common(self):
        """Alert Class - Compute Diff - No Common Set"""
        record = {'a': 1, 'b': 2, 'c': {'d': {'e': 3}}}
        assert record == Alert._compute_diff({}, record)

    def test_compute_diff_no_diff(self):
        """Alert Class - Compute Diff - Record Identical to Common"""
        record = {'a': 1, 'b': 2, 'c': {'d': {'e': 3}}}
        common = record
        assert {} == Alert._compute_diff(common, common)

    def test_compute_diff_top_level(self):
        """Alert Class - Compute Diff - Top Level Keys"""
        common = {'c': 3}
        record = {'a': 1, 'b': 2, 'c': 3}
        assert {'a': 1, 'b': 2} == Alert._compute_diff(common, record)

    def test_compute_diff_different_types(self):
        """Alert Class - Compute Diff - Type Mismatch Short-Circuits Recursion"""
        common = {'b': 2}
        record = {'a': 1, 'b': {'nested': 'stuff'}}
        assert record == Alert._compute_diff(common, record)

    def test_compute_diff_nested(self):
        """Alert Class - Compute Diff - Difference in Nested Dictionary"""
        # This is the example given in the docstring
        common = {'abc': 123, 'nested': {'A': 1}}
        record = {'abc': 123, 'nested': {'A': 1, 'B': 2}}
        assert {'nested': {'B': 2}} == Alert._compute_diff(common, record)

    def test_compute_diff_many_nested(self):
        """Alert Class - Compute Diff - Multiple Levels of Nesting"""
        # These values are the same as those from test_compute_common_many_nested
        record1 = {
            'a': {
                'b': {
                    'c': 3,
                    'd': 4
                },
                'e': {
                    'h': {
                        'i': 9
                    }
                },
                'j': {}
            }
        }
        record2 = {
            'a': {
                'b': {
                    'c': 3,
                },
                'e': {
                    'f': {
                        'g': 8
                    },
                    'h': {}
                },
                'j': {}
            }
        }
        common = {
            'a': {
                'b': {
                    'c': 3
                },
                'j': {}
            }
        }

        expected_diff1 = {
            'a': {
                'b': {
                    'd': 4
                },
                'e': {
                    'h': {
                        'i': 9
                    }
                }
            }
        }
        assert expected_diff1 == Alert._compute_diff(common, record1)

        expected_diff2 = {
            'a': {
                'e': {
                    'f': {
                        'g': 8
                    },
                    'h': {}
                }
            }
        }
        assert expected_diff2 == Alert._compute_diff(common, record2)

    def test_merge(self):
        """Alert Class - Merge - Create Merged Alert"""
        # Example based on a CarbonBlack log
        record1 = {
            'alliance_data_virustotal': [],
            'alliance_link_virustotal': '',
            'alliance_score_virustotal': 0,
            'cmdline': 'whoami',
            'comms_ip': '1.2.3.4',
            'hostname': 'my-computer-name',
            'path': '/usr/bin/whoami',
            'streamalert:ioc': {
                'hello': 'world'
            },
            'timestamp': 1234.5678,
            'username': 'user'
        }
        alert1 = Alert(
            'RuleName', record1, {'aws-sns:topic'},
            created=datetime(year=2000, month=1, day=1),
            merge_by_keys=['hostname', 'username'],
            merge_window=timedelta(minutes=5)
        )

        # Second alert has slightly different record and different outputs
        record2 = copy.deepcopy(record1)
        record2['streamalert:ioc'] = {'goodbye': 'world'}
        record2['timestamp'] = 9999
        alert2 = Alert(
            'RuleName', record2, {'slack:channel'},
            created=datetime(year=2000, month=1, day=2),
            merge_by_keys=['hostname', 'username'],
            merge_window=timedelta(minutes=5)
        )

        merged = Alert.merge([alert1, alert2])
        assert isinstance(merged, Alert)
        assert {'slack:channel'} == merged.outputs  # Most recent outputs were used

        expected_record = {
            'AlertCount': 2,
            'AlertTimeFirst': '2000-01-01T00:00:00.000000Z',
            'AlertTimeLast': '2000-01-02T00:00:00.000000Z',
            'MergedBy': {
                'hostname': 'my-computer-name',
                'username': 'user'
            },
            'OtherCommonKeys': {
                'alliance_data_virustotal': [],
                'alliance_link_virustotal': '',
                'alliance_score_virustotal': 0,
                'cmdline': 'whoami',
                'comms_ip': '1.2.3.4',
                'path': '/usr/bin/whoami',
            },
            'ValueDiffs': {
                '2000-01-01T00:00:00.000000Z': {
                    'streamalert:ioc': {'hello': 'world'},
                    'timestamp': 1234.5678
                },
                '2000-01-02T00:00:00.000000Z': {
                    'streamalert:ioc': {'goodbye': 'world'},
                    'timestamp': 9999
                }
            }

        }
        assert expected_record == merged.record

    def test_merge_nested(self):
        """Alert Class - Merge - Merge with Nested Keys"""
        record1 = {
            'NumMatchedRules': 1,
            'FileInfo': {
                'Deleted': None,
                'Nested': [1, 2, 'three']
            },
            'MatchedRules': {
                'Rule1': 'MatchedStrings'
            }
        }
        alert1 = Alert(
            'RuleName', record1, {'slack:channel'},
            created=datetime(year=2000, month=1, day=1),
            merge_by_keys=['Nested'],
            merge_window=timedelta(minutes=5)
        )

        record2 = {
            'NumMatchedRules': 2,
            'FileInfo': {
                'Deleted': None,
                'Nested': [1, 2, 'three']
            },
            'MatchedRules': {
                'Rule1': 'MatchedStrings'
            }
        }
        alert2 = Alert(
            'RuleName', record2, {'slack:channel'},
            created=datetime(year=2000, month=1, day=2),
            merge_by_keys=['Nested'],
            merge_window=timedelta(minutes=5)
        )

        record3 = {
            'MatchedRules': {
                'Rule1': 'MatchedStrings'
            },
            'Nested': [1, 2, 'three']  # This is in a different place in the record
        }
        alert3 = Alert(
            'RuleName', record3, {'slack:channel'},
            created=datetime(year=2000, month=1, day=3),
            merge_by_keys=['Nested'],
            merge_window=timedelta(minutes=5)
        )

        merged = Alert.merge([alert1, alert2, alert3])

        expected_record = {
            'AlertCount': 3,
            'AlertTimeFirst': '2000-01-01T00:00:00.000000Z',
            'AlertTimeLast': '2000-01-03T00:00:00.000000Z',
            'MergedBy': {
                'Nested': [1, 2, 'three']
            },
            'OtherCommonKeys': {
                'MatchedRules': {
                    'Rule1': 'MatchedStrings'
                }
            },
            'ValueDiffs': {
                '2000-01-01T00:00:00.000000Z': {
                    'NumMatchedRules': 1,
                    'FileInfo': {
                        'Deleted': None
                    }
                },
                '2000-01-02T00:00:00.000000Z': {
                    'NumMatchedRules': 2,
                    'FileInfo': {
                        'Deleted': None
                    }
                },
                '2000-01-03T00:00:00.000000Z': {}
            }
        }

        assert expected_record == merged.record

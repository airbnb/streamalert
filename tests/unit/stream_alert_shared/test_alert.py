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
import copy
import json

from stream_alert.shared.alert import Alert

from nose.tools import assert_equal, assert_is_instance, assert_not_in, assert_raises


class TestAlert(object):
    """Test shared Alert class."""
    # pylint: disable=no-self-use,protected-access

    @staticmethod
    def _basic_alert():
        return Alert('test_rule', {'abc': 123}, {'aws-sns:test-output'})

    @staticmethod
    def _customized_alert():
        return Alert(
            'test_rule',
            {'abc': 123},
            {'aws-sns:test-output', 'aws-s3:other-output'},
            alert_id='abc-123',
            attempts=1,
            cluster='',
            context={'rule': 'context'},
            created='now',
            dispatched=10,
            log_source='source',
            log_type='csv',
            merge_by_keys=['abc'],
            merge_window_mins=5,
            retry_outputs={'aws-sns:test-output'},
            rule_description='A Test Rule',
            source_entity='entity',
            source_service='s3',
            staged=True
        )

    def test_alert_encoder_invalid_json(self):
        """Alert Class - Alert Encoder - Invalid JSON raises parent exception"""
        assert_raises(TypeError, json.dumps, RuntimeWarning, cls=Alert.AlertEncoder)

    def test_init_invalid_kwargs(self):
        """Alert Class - Init With Invalid Kwargs"""
        assert_raises(TypeError, Alert, '', {}, set(), cluster='test', invalid='nonsense')

    def test_ordering(self):
        """Alert Class - Alerts Are Sorted By Creation"""
        alerts = [self._basic_alert() for _ in range(5)]
        assert_equal(alerts, sorted([alerts[0], alerts[3], alerts[1], alerts[4], alerts[2]]))

    def test_repr(self):
        """Alert Class - Complete Alert Representation"""
        assert_is_instance(repr(self._basic_alert()), str)
        assert_is_instance(repr(self._customized_alert()), str)

    def test_str(self):
        """Alert Class - To String"""
        alert = self._customized_alert()
        assert_equal('<Alert abc-123 triggered from test_rule>', str(alert))

    def test_dynamo_key(self):
        """Alert Class - Dynamo Key"""
        alert = self._customized_alert()
        assert_equal({'RuleName': 'test_rule', 'AlertID': 'abc-123'}, alert.dynamo_key)

    def test_remaining_outputs(self):
        """Alert Class - Remaining Outputs"""
        # If there are no failed outputs, just the output set
        assert_equal({'aws-sns:test-output'}, self._basic_alert().remaining_outputs)
        # If there are failed outputs, just those should be returned
        assert_equal({'aws-sns:test-output'}, self._customized_alert().remaining_outputs)

    def test_dynamo_record(self):
        """Alert Class - Dynamo Record"""
        # Make sure there are no empty strings nor sets (not allowed in Dynamo)
        alert = Alert(
            'test_rule', {}, {'aws-sns:test-output'},
            cluster='',
            created='',
            log_source='',
            log_type='',
            retry_outputs=set(),
            rule_description='',
            source_entity='',
            source_service=''
        )
        record = alert.dynamo_record()
        assert_not_in('', record.values())
        assert_not_in(set(), record.values())

    def test_create_from_dynamo_record(self):
        """Alert Class - Create Alert from Dynamo Record"""
        alert = self._customized_alert()
        # Converting to a Dynamo record and back again should result in the exact same alert
        record = alert.dynamo_record()
        new_alert = Alert.create_from_dynamo_record(record)
        assert_equal(alert.dynamo_record(), new_alert.dynamo_record())

    def test_output_dict(self):
        """Alert Class - Output Dict"""
        alert = self._basic_alert()
        result = alert.output_dict()
        # Ensure result is JSON-serializable (no sets)
        assert_is_instance(json.dumps(result), str)
        # Ensure result is Athena compatible (no None values)
        assert_not_in(None, result.values())

    def test_compute_common_empty_record(self):
        """Alert Class - Compute Common - Empty Record List"""
        assert_equal({}, Alert._compute_common([]))

    def test_compute_common_single_record(self):
        """Alert Class - Compute Common - Single Record"""
        # The greatest common subset of a single record is itself
        record = {'a': 1, 'b': 2, 'c': {'d': {'e': 3}}}
        assert_equal(record, Alert._compute_common([record]))

    def test_compute_common_top_level(self):
        """Alert Class - Compute Common - No Nested Dictionaries"""
        record1 = {'a': 1, 'b': 2, 'c': 3}
        record2 = {'b': 2, 'c': 3, 'd': 4}
        record3 = {'c': 3, 'd': 4, 'e': 5}
        assert_equal({'c': 3}, Alert._compute_common([record1, record2, record3]))

    def test_compute_common_no_similarities(self):
        """Alert Class - Compute Common - Empty Common Set"""
        record1 = {'a': -1, 'b': -2, 'c': -3, 'd': {'e': 0}}
        record2 = {'a': 1, 'b': 2, 'c': 3}
        assert_equal({}, Alert._compute_common([record1, record2]))

    def test_compute_common_partial_nested(self):
        """Alert Class - Compute Common - Some Common Features in Nested Dictionary"""
        # This is the example given in the docstring
        record1 = {'abc': 123, 'nested': {'A': 1, 'B': 2}}
        record2 = {'abc': 123, 'def': 456, 'nested': {'A': 1}}
        assert_equal({'abc': 123, 'nested': {'A': 1}}, Alert._compute_common([record1, record2]))

    def test_compute_common_different_types(self):
        """Alert Class - Compute Common - Same Keys, Different Types"""
        record1 = {'a': 1, 'b': None, 'c': {'d': {'e': 5}, 'f': {'g': 6}}}
        record2 = {'a': '1', 'b': 0, 'c': []}
        assert_equal({}, Alert._compute_common([record1, record2]))

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
        assert_equal(expected, Alert._compute_common([record1, record2]))

    def test_compute_common_all_identical(self):
        """Alert Class - Compute Common - Identical Records"""
        record = {'a': 1, 'b': 2, 'c': {'d': {'e': 3}}}
        assert_equal(record, Alert._compute_common([record] * 4))

    def test_compute_diff_no_common(self):
        """Alert Class - Compute Diff - No Common Set"""
        record = {'a': 1, 'b': 2, 'c': {'d': {'e': 3}}}
        assert_equal(record, Alert._compute_diff({}, record))

    def test_compute_diff_no_diff(self):
        """Alert Class - Compute Diff - Record Identical to Common"""
        record = {'a': 1, 'b': 2, 'c': {'d': {'e': 3}}}
        common = record
        assert_equal({}, Alert._compute_diff(common, record))

    def test_compute_diff_top_level(self):
        """Alert Class - Compute Diff - Top Level Keys"""
        common = {'c': 3}
        record = {'a': 1, 'b': 2, 'c': 3}
        assert_equal({'a': 1, 'b': 2}, Alert._compute_diff(common, record))

    def test_compute_diff_different_types(self):
        """Alert Class - Compute Diff - Type Mismatch Short-Circuits Recursion"""
        common = {'b': 2}
        record = {'a': 1, 'b': {'nested': 'stuff'}}
        assert_equal(record, Alert._compute_diff(common, record))

    def test_compute_diff_nested(self):
        """Alert Class - Compute Diff - Difference in Nested Dictionary"""
        # This is the example given in the docstring
        common = {'abc': 123, 'nested': {'A': 1}}
        record = {'abc': 123, 'nested': {'A': 1, 'B': 2}}
        assert_equal({'nested': {'B': 2}}, Alert._compute_diff(common, record))

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
        assert_equal(expected_diff1, Alert._compute_diff(common, record1))

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
        assert_equal(expected_diff2, Alert._compute_diff(common, record2))

    def test_merge(self):
        """Alert Class - Create Merged Alert"""
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
            created='time1',
            merge_by_keys=['hostname', 'username'],
            merge_window_mins=5
        )

        # Second alert has slightly different record and different outputs
        record2 = copy.deepcopy(record1)
        record2['streamalert:ioc'] = {'goodbye': 'world'}
        record2['timestamp'] = 9999
        alert2 = Alert(
            'RuleName', record2, {'slack:channel'},
            created='time2',
            merge_by_keys=['hostname', 'username'],
            merge_window_mins=5
        )

        merged = Alert.merge([alert1, alert2])
        assert_is_instance(merged, Alert)
        assert_equal({'aws-sns:topic', 'slack:channel'}, merged.outputs)  # Outputs were merged

        expected_record = {
            'AlertCount': 2,
            'AlertTimeFirst': 'time1',
            'AlertTimeLast': 'time2',
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
            'ValueDiffs': [
                {
                    'streamalert:ioc': {'hello': 'world'},
                    'timestamp': 1234.5678
                },
                {
                    'streamalert:ioc': {'goodbye': 'world'},
                    'timestamp': 9999
                }
            ]
        }
        assert_equal(expected_record, merged.record)

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
from unittest.mock import patch

from streamalert.classifier.payload.payload_base import (RegisterInput,
                                                         StreamPayload)


class TestRegisterInput:
    """RegisterInput tests"""
    # pylint: disable=no-self-use,protected-access

    def setup(self):
        """RegisterInput - Setup"""
        # pylint: disable=attribute-defined-outside-init
        self._service = 'foobar'

        @RegisterInput
        class Test:
            """Fake test class to register"""

            def __init__(self, *args, **kwargs):
                pass

            @classmethod
            def service(cls):
                return self._service

        self._class = Test

    def test_load_for_service(self):
        """RegisterInput - Load For Service"""
        loaded_input = RegisterInput.load_for_service(
            self._service,
            'resource',
            'record'
        )
        assert isinstance(loaded_input, self._class)

    @patch('logging.Logger.error')
    def test_load_for_service_error(self, log_mock):
        """RegisterInput - Load For Service, Error"""
        service = 'foobarbaz'
        assert RegisterInput.load_for_service(service, None, None) == False
        log_mock.assert_called_with('Requested payload service [%s] does not exist', service)

    def test_get_payload_class(self):
        """RegisterInput - Get Payload Class"""
        class_type = RegisterInput._get_payload_class(self._service)
        assert self._class == class_type


class TestStreamPayload:
    """StreamPayload tests"""
    # pylint: disable=no-self-use

    @patch.object(StreamPayload, '__abstractmethods__', frozenset())
    def setup(self):
        """StreamPayload - Setup"""
        # pylint: disable=abstract-class-instantiated,attribute-defined-outside-init
        self._resource = 'foobar'
        self._record = {'key': 'value'}
        self._payload = StreamPayload(self._resource, self._record)

    def test_non_zero_false(self):
        """StreamPayload - Non Zero/Bool, False"""
        self._payload.fully_classified = False
        assert not bool(self._payload)

    def test_non_zero_true(self):
        """StreamPayload - Non Zero/Bool, True"""
        assert bool(self._payload)

    def test_repr(self):
        """StreamPayload - Repr"""
        expected_result = '<StreamPayload valid:True; resource:foobar;>'
        assert repr(self._payload) == expected_result

    def test_repr_invalid(self):
        """StreamPayload - Repr, Invalid"""
        self._payload.fully_classified = False
        expected_result = (
            '<StreamPayload valid:False; resource:foobar; raw record:{"key": "value"};>'
        )
        assert repr(self._payload) == expected_result

    def test_load_from_raw_record_kinesis(self):
        """StreamPayload - Load from Raw Record, Kinesis"""
        record = {
            'kinesis': {},
            'eventSourceARN': 'arn:aws:kinesis:us-east-1:123456789012:stream/test_stream_name'
        }
        with patch.object(RegisterInput, 'load_for_service') as load_mock:
            StreamPayload.load_from_raw_record(record)
            load_mock.assert_called_with('kinesis', 'test_stream_name', record)

    def test_load_from_raw_record_s3(self):
        """StreamPayload - Load from Raw Record, S3"""
        record = {
            's3': {
                'bucket': {
                    'name': 'test_bucket_name'
                }
            }
        }
        with patch.object(RegisterInput, 'load_for_service') as load_mock:
            StreamPayload.load_from_raw_record(record)
            load_mock.assert_called_with('s3', 'test_bucket_name', record)

    def test_load_from_raw_record_app(self):
        """StreamPayload - Load from Raw Record, StreamAlertApp"""
        record = {
            'streamalert_app': 'test_app'
        }
        with patch.object(RegisterInput, 'load_for_service') as load_mock:
            StreamPayload.load_from_raw_record(record)
            load_mock.assert_called_with('streamalert_app', 'test_app', record)

    def test_load_from_raw_record_sns_s3(self):
        """StreamPayload - Load from Raw Record, SNS S3 Event"""
        s3_record = {
            's3': {
                'bucket': {
                    'name': 'test_bucket_name'
                }
            }
        }
        record = {
            'Sns': {
                'Type': 'Notification',
                'Subject': 'Amazon S3 Notification',
                'TopicArn': 'arn:aws:sns:us-east-1:123456789012:test_topic_arn',
                'Message': json.dumps(
                    {
                        'Records': [
                            s3_record
                        ]
                    }
                )
            }
        }
        with patch.object(RegisterInput, 'load_for_service') as load_mock:
            StreamPayload.load_from_raw_record(record)
            load_mock.assert_called_with('s3', 'test_bucket_name', s3_record)

    def test_load_from_raw_record_sns(self):
        """StreamPayload - Load from Raw Record, SNS"""
        record = {
            'Sns': {
                'TopicArn': 'arn:aws:sns:us-east-1:123456789012:test_topic_arn',
            }
        }
        with patch.object(RegisterInput, 'load_for_service') as load_mock:
            StreamPayload.load_from_raw_record(record)
            load_mock.assert_called_with('sns', 'test_topic_arn', record)

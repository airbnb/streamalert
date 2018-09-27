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
import json

from mock import patch
from nose.tools import assert_equal

from stream_alert.classifier.payload.payload_base import (
    RegisterInput,
    StreamPayload
)


class TestRegisterInput(object):
    """RegisterInput tests"""
    # pylint: disable=no-self-use,protected-access

    def setup(self):
        """RegisterInput - Setup"""
        # pylint: disable=attribute-defined-outside-init
        self._service = 'foobar'

        @RegisterInput
        class Test(object):
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
        assert_equal(isinstance(loaded_input, self._class), True)

    @patch('logging.Logger.error')
    def test_load_for_service_error(self, log_mock):
        """RegisterInput - Load For Service, Error"""
        service = 'foobarbaz'
        assert_equal(RegisterInput.load_for_service(service, None, None), False)
        log_mock.assert_called_with('Requested payload service [%s] does not exist', service)

    def test_get_payload_class(self):
        """RegisterInput - Get Payload Class"""
        class_type = RegisterInput._get_payload_class(self._service)
        assert_equal(self._class, class_type)


class TestStreamPayload(object):
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
        assert_equal(bool(self._payload), False)

    def test_non_zero_true(self):
        """StreamPayload - Non Zero/Bool, True"""
        self._payload.data_type = 'type'
        self._payload.log_source = 'source'
        self._payload.records = ['records']
        assert_equal(bool(self._payload), True)

    def test_repr(self):
        """StreamPayload - Repr"""
        self._payload.data_type = 'type'
        self._payload.log_source = 'source'
        self._payload.records = ['records']
        self._payload.fully_classified = False
        expected_result = (
            '<StreamPayload valid:False log_source:source resource:foobar '
            'type:type record:[\'records\']>'
        )
        assert_equal(repr(self._payload), expected_result)

    def test_log_type_property(self):
        """StreamPayload - Log Type"""
        self._payload.log_source = 'source:log_type'
        assert_equal(self._payload.log_type, 'source')

    def test_log_sub_type_property(self):
        """StreamPayload - Log Sub Type"""
        self._payload.log_source = 'source:log_type'
        assert_equal(self._payload.log_subtype, 'log_type')

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
            'stream_alert_app': 'test_app'
        }
        with patch.object(RegisterInput, 'load_for_service') as load_mock:
            StreamPayload.load_from_raw_record(record)
            load_mock.assert_called_with('stream_alert_app', 'test_app', record)

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

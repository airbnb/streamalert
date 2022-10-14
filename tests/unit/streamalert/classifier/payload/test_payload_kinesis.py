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

from streamalert.classifier.payload.kinesis import KinesisPayload


class TestKinesisPayload:
    """KinesisPayload tests"""
    # pylint: disable=no-self-use,protected-access

    @classmethod
    def _record_data(cls, data):
        """Helper for getting record data"""
        return {
            'kinesis': {
                'data': data
            },
            'eventID': 'test_event_id',
            'eventSourceARN': (
                'arn:aws:kinesis:us-east-1:123456789012:stream/test_stream_name'
            )
        }

    def test_pre_parse(self):
        """KinesisPayload - Pre Parse, Uncompressed"""
        # Base64 encoded uncompressed json
        record = self._record_data('eyJrZXkiOiAidmFsdWUifQ==')
        expected_result = [
            json.dumps({
                'key': 'value'
            }).encode()
        ]

        payload = KinesisPayload(None, record)
        result = [rec._record_data for rec in list(payload.pre_parse())]
        assert result == expected_result

    def test_pre_parse_compressed(self):
        """KinesisPayload - Pre Parse, GZIP Compressed"""
        # Base64 encoded GZIP compressed json
        record = self._record_data('H4sIAPdArVsAA6tWyk6tVLJSUCpLzClNVaoFABtINTMQAAAA')
        expected_result = [
            json.dumps({
                'key': 'value'
            }).encode()
        ]

        payload = KinesisPayload(None, record)
        result = [rec._record_data for rec in list(payload.pre_parse())]
        assert result == expected_result

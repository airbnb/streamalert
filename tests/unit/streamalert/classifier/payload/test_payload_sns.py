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

from streamalert.classifier.payload.sns import SnsPayload


class TestSnsPayload:
    """SnsPayload tests"""
    # pylint: disable=no-self-use,protected-access

    def test_pre_parse(self):
        """SnsPayload - Pre Parse"""
        # pylint: disable=protected-access
        expected_result = ['foobarbaz']
        record = {
            'Sns': {
                'MessageId': 'db42ca0e-215c-5f63-9e92-9e2e953c4e6c',
                'Message': expected_result[0]
            },
            'EventSubscriptionArn': (
                'arn:aws:sns:us-east-1:123456789012:foobar:44dbbe73-3aca-4bb1-863b-b82f058c0b19'
            )
        }

        payload = SnsPayload(None, record)
        result = [rec._record_data for rec in list(payload.pre_parse())]
        assert result == expected_result

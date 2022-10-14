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

from streamalert.classifier.payload.apps import AppPayload


class TestAppPayload:
    """AppPayload tests"""
    # pylint: disable=no-self-use

    def test_pre_parse(self):
        """AppPayload - Pre Parse"""
        # pylint: disable=protected-access
        expected_result = [
            {
                'record_01': 'value'
            },
            {
                'record_02': 'value'
            }
        ]
        record = {
            'logs': expected_result
        }

        payload = AppPayload(None, record)
        result = [rec._record_data for rec in list(payload.pre_parse())]
        assert result == expected_result

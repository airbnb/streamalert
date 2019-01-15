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
# pylint: disable=no-self-use,unused-argument,attribute-defined-outside-init,protected-access
from collections import OrderedDict

from mock import call, patch, Mock, MagicMock
from moto import mock_s3, mock_kms
from nose.tools import assert_false, assert_is_instance, assert_true

from stream_alert.alert_processor.outputs.demisto import DemistoOutput

from tests.unit.stream_alert_alert_processor import (
    CONFIG,
    KMS_ALIAS,
    MOCK_ENV,
    REGION
)
from tests.unit.stream_alert_alert_processor.helpers import (
    get_alert,
    put_mock_creds,
    remove_temp_secrets
)

# THIS COMMAND WORKS:
# curl --request POST -v --header "Authorization: MIpC1rrxstLnJqLuz8pxKnJxoIstDFzt" --header "Content-Type: application/json" --header "Accept: application/json" -d '{"filter":{}}' https://demisto.ypy.fyi/incidents/search
class TestDemistoIntegrationTestSuite(object):
    """Test class for SlackOutput"""
    DESCRIPTOR = 'unit_test_demisto'
    SERVICE = 'demisto'
    OUTPUT = ':'.join([SERVICE, DESCRIPTOR])
    CREDS = {
        'url': 'https://demisto.ypy.fyi',
        'token': 'MIpC1rrxstLnJqLuz8pxKnJxoIstDFzt',
    }

    @patch('stream_alert.alert_processor.outputs.output_base.OutputCredentialsProvider')
    def setup(self, provider_constructor):
        """Setup before each method"""
        provider = MagicMock()
        provider_constructor.return_value = provider
        provider.load_credentials = Mock(
            side_effect=lambda x: self.CREDS if x == self.DESCRIPTOR else None
        )

        self._provider = provider
        self._dispatcher = DemistoOutput(None)

    def test_get_user_defined_properties(self):
        """DemistoOutput - User Defined Properties"""
        assert_is_instance(DemistoOutput.get_user_defined_properties(), OrderedDict)

    # @patch('logging.Logger.info')
    # @patch('requests.get')
    # @patch('requests.post')
    def test_dispatch_issue_new(self):
        """DemistoOutput - Dispatch Success, New Issue"""

        alert_context = {
            'demisto': {
                'foo': 'bar',
                'baz': 'buzz',
                'deepArray': [
                    {
                        "key": "value",
                    },
                    {
                        "key": "value2",
                    }
                ]
            }
        }

        assert_true(self._dispatcher.dispatch(get_alert(context=alert_context), self.OUTPUT))

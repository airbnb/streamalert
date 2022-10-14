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
# pylint: disable=protected-access,attribute-defined-outside-init
from unittest.mock import MagicMock, Mock, patch

from streamalert.alert_processor.outputs.komand import KomandOutput
from tests.unit.streamalert.alert_processor.helpers import get_alert


@patch('streamalert.alert_processor.outputs.output_base.OutputDispatcher.MAX_RETRY_ATTEMPTS', 1)
class TestKomandutput:
    """Test class for KomandOutput"""
    DESCRIPTOR = 'unit_test_komand'
    SERVICE = 'komand'
    OUTPUT = ':'.join([SERVICE, DESCRIPTOR])
    CREDS = {'url': 'http://komand.foo.bar',
             'komand_auth_token': 'mocked_auth_token'}

    @patch('streamalert.alert_processor.outputs.output_base.OutputCredentialsProvider')
    def setup(self, provider_constructor):
        """Setup before each method"""
        provider = MagicMock()
        provider_constructor.return_value = provider
        provider.load_credentials = Mock(
            side_effect=lambda x: self.CREDS if x == self.DESCRIPTOR else None
        )
        self._provider = provider
        self._dispatcher = KomandOutput(None)

    @patch('logging.Logger.info')
    @patch('requests.post')
    def test_dispatch_existing_container(self, post_mock, log_mock):
        """KomandOutput - Dispatch Success"""
        post_mock.return_value.status_code = 200

        assert self._dispatcher.dispatch(get_alert(), self.OUTPUT)

        log_mock.assert_called_with('Successfully sent alert to %s:%s',
                                    self.SERVICE, self.DESCRIPTOR)

    @patch('logging.Logger.error')
    @patch('requests.post')
    def test_dispatch_container_failure(self, post_mock, log_mock):
        """KomandOutput - Dispatch Failure"""
        post_mock.return_value.status_code = 400
        json_error = {'message': 'error message', 'errors': ['error1']}
        post_mock.return_value.json.return_value = json_error

        assert not self._dispatcher.dispatch(get_alert(), self.OUTPUT)

        log_mock.assert_called_with('Failed to send alert to %s:%s', self.SERVICE, self.DESCRIPTOR)

    @patch('logging.Logger.error')
    def test_dispatch_bad_descriptor(self, log_error_mock):
        """KomandOutput - Dispatch Failure, Bad Descriptor"""
        assert not self._dispatcher.dispatch(
            get_alert(), ':'.join([self.SERVICE, 'bad_descriptor']))

        log_error_mock.assert_called_with('Failed to send alert to %s:%s',
                                          self.SERVICE, 'bad_descriptor')

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
# pylint: disable=protected-access,attribute-defined-outside-init,no-self-use
import base64
from unittest.mock import MagicMock, Mock, patch

from streamalert.alert_processor.outputs.github import GithubOutput
from tests.unit.streamalert.alert_processor.helpers import get_alert


@patch('streamalert.alert_processor.outputs.output_base.OutputDispatcher.MAX_RETRY_ATTEMPTS', 1)
class TestGithubOutput:
    """Test class for GithubOutput"""
    DESCRIPTOR = 'unit_test_repo'
    SERVICE = 'github'
    OUTPUT = ':'.join([SERVICE, DESCRIPTOR])
    CREDS = {'username': 'unit_test_user',
             'access_token': 'unit_test_access_token',
             'repository': 'unit_test_org/unit_test_repo',
             'labels': 'label1,label2',
             'api': 'https://api.github.com',
             }

    @patch('streamalert.alert_processor.outputs.output_base.OutputCredentialsProvider')
    def setup(self, provider_constructor):
        """Setup before each method"""
        provider = MagicMock()
        provider_constructor.return_value = provider
        provider.load_credentials = Mock(
            side_effect=lambda x: self.CREDS if x == self.DESCRIPTOR else None
        )
        self._provider = provider
        self._dispatcher = GithubOutput(None)

    @patch('logging.Logger.info')
    @patch('requests.post')
    def test_dispatch_success(self, url_mock, log_mock):
        """GithubOutput - Dispatch Success"""
        url_mock.return_value.status_code = 200
        url_mock.return_value.json.return_value = {}

        assert self._dispatcher.dispatch(get_alert(), self.OUTPUT)

        assert (url_mock.call_args[0][0] ==
                'https://api.github.com/repos/unit_test_org/unit_test_repo/issues')
        assert url_mock.call_args[1]['headers']['Authorization'] is not None

        credentials = url_mock.call_args[1]['headers']['Authorization'].split(' ')[-1]
        decoded_username_password = base64.b64decode(credentials)
        assert decoded_username_password == f"{self.CREDS['username']}:{self.CREDS['access_token']}".encode(
        )

        log_mock.assert_called_with('Successfully sent alert to %s:%s',
                                    self.SERVICE, self.DESCRIPTOR)

    @patch('logging.Logger.info')
    @patch('requests.post')
    def test_dispatch_success_with_labels(self, url_mock, log_mock):
        """GithubOutput - Dispatch Success with Labels"""
        url_mock.return_value.status_code = 200
        url_mock.return_value.json.return_value = {}

        assert self._dispatcher.dispatch(get_alert(), self.OUTPUT)

        assert url_mock.call_args[1]['json']['labels'] == ['label1', 'label2']
        log_mock.assert_called_with('Successfully sent alert to %s:%s',
                                    self.SERVICE, self.DESCRIPTOR)

    @patch('logging.Logger.error')
    @patch('requests.post')
    def test_dispatch_failure(self, url_mock, log_mock):
        """GithubOutput - Dispatch Failure, Bad Request"""
        json_error = {'message': 'error message', 'errors': ['error1']}
        url_mock.return_value.json.return_value = json_error
        url_mock.return_value.status_code = 400

        assert not self._dispatcher.dispatch(get_alert(), self.OUTPUT)

        log_mock.assert_called_with('Failed to send alert to %s:%s', self.SERVICE, self.DESCRIPTOR)

    @patch('logging.Logger.error')
    def test_dispatch_bad_descriptor(self, log_mock):
        """GithubOutput - Dispatch Failure, Bad Descriptor"""
        assert not self._dispatcher.dispatch(
            get_alert(), ':'.join([self.SERVICE, 'bad_descriptor']))

        log_mock.assert_called_with('Failed to send alert to %s:%s', self.SERVICE, 'bad_descriptor')

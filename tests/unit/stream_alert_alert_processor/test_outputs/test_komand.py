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
# pylint: disable=protected-access,attribute-defined-outside-init
from mock import patch
from moto import mock_s3, mock_kms
from nose.tools import assert_false, assert_true

from stream_alert.alert_processor.outputs.komand import KomandOutput
from stream_alert_cli.helpers import put_mock_creds
from tests.unit.stream_alert_alert_processor import (
    ACCOUNT_ID,
    FUNCTION_NAME,
    KMS_ALIAS,
    REGION
)
from tests.unit.stream_alert_alert_processor.helpers import get_alert, remove_temp_secrets


@mock_s3
@mock_kms
@patch('stream_alert.alert_processor.outputs.output_base.OutputDispatcher.MAX_RETRY_ATTEMPTS', 1)
class TestKomandutput(object):
    """Test class for KomandOutput"""
    DESCRIPTOR = 'unit_test_komand'
    SERVICE = 'komand'
    OUTPUT = ':'.join([SERVICE, DESCRIPTOR])
    CREDS = {'url': 'http://komand.foo.bar',
             'komand_auth_token': 'mocked_auth_token'}

    def setup(self):
        """Setup before each method"""
        self._dispatcher = KomandOutput(REGION, ACCOUNT_ID, FUNCTION_NAME, None)
        remove_temp_secrets()
        output_name = self._dispatcher.output_cred_name(self.DESCRIPTOR)
        put_mock_creds(output_name, self.CREDS, self._dispatcher.secrets_bucket, REGION, KMS_ALIAS)

    @patch('logging.Logger.info')
    @patch('requests.post')
    def test_dispatch_existing_container(self, post_mock, log_mock):
        """KomandOutput - Dispatch Success"""
        post_mock.return_value.status_code = 200

        assert_true(self._dispatcher.dispatch(get_alert(), self.OUTPUT))

        log_mock.assert_called_with('Successfully sent alert to %s:%s',
                                    self.SERVICE, self.DESCRIPTOR)

    @patch('logging.Logger.error')
    @patch('requests.post')
    def test_dispatch_container_failure(self, post_mock, log_mock):
        """KomandOutput - Dispatch Failure"""
        post_mock.return_value.status_code = 400
        json_error = {'message': 'error message', 'errors': ['error1']}
        post_mock.return_value.json.return_value = json_error

        assert_false(self._dispatcher.dispatch(get_alert(), self.OUTPUT))

        log_mock.assert_called_with('Failed to send alert to %s:%s', self.SERVICE, self.DESCRIPTOR)

    @patch('logging.Logger.error')
    def test_dispatch_bad_descriptor(self, log_error_mock):
        """KomandOutput - Dispatch Failure, Bad Descriptor"""
        assert_false(
            self._dispatcher.dispatch(get_alert(), ':'.join([self.SERVICE, 'bad_descriptor'])))

        log_error_mock.assert_called_with('Failed to send alert to %s:%s',
                                          self.SERVICE, 'bad_descriptor')

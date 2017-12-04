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
from mock import call, patch, PropertyMock
from moto import mock_s3, mock_kms
from nose.tools import assert_false, assert_true

from stream_alert.alert_processor.outputs.phantom import PhantomOutput
from stream_alert_cli.helpers import put_mock_creds
from tests.unit.stream_alert_alert_processor import CONFIG, FUNCTION_NAME, KMS_ALIAS, REGION
from tests.unit.stream_alert_alert_processor.helpers import get_alert, remove_temp_secrets


@mock_s3
@mock_kms
@patch('stream_alert.alert_processor.outputs.output_base.OutputDispatcher.MAX_RETRY_ATTEMPTS', 1)
class TestPhantomOutput(object):
    """Test class for PhantomOutput"""
    DESCRIPTOR = 'unit_test_phantom'
    SERVICE = 'phantom'
    CREDS = {'url': 'http://phantom.foo.bar',
             'ph_auth_token': 'mocked_auth_token'}

    def setup(self):
        """Setup before each method"""
        self._dispatcher = PhantomOutput(REGION, FUNCTION_NAME, CONFIG)
        remove_temp_secrets()
        output_name = self._dispatcher.output_cred_name(self.DESCRIPTOR)
        put_mock_creds(output_name, self.CREDS, self._dispatcher.secrets_bucket, REGION, KMS_ALIAS)

    @patch('logging.Logger.info')
    @patch('requests.get')
    @patch('requests.post')
    def test_dispatch_existing_container(self, post_mock, get_mock, log_mock):
        """PhantomOutput - Dispatch Success, Existing Container"""
        # _check_container_exists
        get_mock.return_value.status_code = 200
        get_mock.return_value.json.return_value = {'count': 1, 'data': [{'id': 1948}]}
        # dispatch
        post_mock.return_value.status_code = 200

        assert_true(self._dispatcher.dispatch(descriptor=self.DESCRIPTOR,
                                              rule_name='rule_name',
                                              alert=get_alert()))

        log_mock.assert_called_with('Successfully sent alert to %s', self.SERVICE)

    @patch('logging.Logger.info')
    @patch('requests.get')
    @patch('requests.post')
    def test_dispatch_new_container(self, post_mock, get_mock, log_mock):
        """PhantomOutput - Dispatch Success, New Container"""
        # _check_container_exists
        get_mock.return_value.status_code = 200
        get_mock.return_value.json.return_value = {'count': 0, 'data': []}
        # _setup_container, dispatch
        post_mock.return_value.status_code = 200
        post_mock.return_value.json.return_value = {'id': 1948}

        assert_true(self._dispatcher.dispatch(descriptor=self.DESCRIPTOR,
                                              rule_name='rule_name',
                                              alert=get_alert()))

        log_mock.assert_called_with('Successfully sent alert to %s', self.SERVICE)

    @patch('logging.Logger.error')
    @patch('requests.get')
    @patch('requests.post')
    def test_dispatch_container_failure(self, post_mock, get_mock, log_mock):
        """PhantomOutput - Dispatch Failure, Setup Container"""
        # _check_container_exists
        get_mock.return_value.status_code = 200
        get_mock.return_value.json.return_value = {'count': 0, 'data': []}
        # _setup_container
        post_mock.return_value.status_code = 400
        json_error = {'message': 'error message', 'errors': ['error1']}
        post_mock.return_value.json.return_value = json_error

        assert_false(self._dispatcher.dispatch(descriptor=self.DESCRIPTOR,
                                               rule_name='rule_name',
                                               alert=get_alert()))

        log_mock.assert_called_with('Failed to send alert to %s', self.SERVICE)

    @patch('logging.Logger.error')
    @patch('requests.get')
    @patch('requests.post')
    def test_dispatch_check_container_error(self, post_mock, get_mock, log_mock):
        """PhantomOutput - Dispatch Failure, Decode Error w/ Container Check"""
        # _check_container_exists
        get_mock.return_value.status_code = 200
        get_mock.return_value.text = '{}'
        # _setup_container
        post_mock.return_value.status_code = 400
        json_error = {'message': 'error message', 'errors': ['error1']}
        post_mock.return_value.json.return_value = json_error

        assert_false(self._dispatcher.dispatch(descriptor=self.DESCRIPTOR,
                                               rule_name='rule_name',
                                               alert=get_alert()))

        log_mock.assert_called_with('Failed to send alert to %s', self.SERVICE)

    @patch('logging.Logger.error')
    @patch('requests.get')
    @patch('requests.post')
    def test_dispatch_check_container_no_response(self, post_mock, get_mock, log_mock):
        """PhantomOutput - Dispatch Failure, No Response Container Check"""
        # _check_container_exists
        get_mock.return_value.status_code = 200
        get_mock.return_value.json.return_value = {}
        # _setup_container
        post_mock.return_value.status_code = 200
        post_mock.return_value.json.return_value = {}

        assert_false(self._dispatcher.dispatch(descriptor=self.DESCRIPTOR,
                                               rule_name='rule_name',
                                               alert=get_alert()))

        log_mock.assert_called_with('Failed to send alert to %s', self.SERVICE)

    @patch('logging.Logger.error')
    @patch('requests.get')
    @patch('requests.post')
    def test_dispatch_setup_container_error(self, post_mock, get_mock, log_mock):
        """PhantomOutput - Dispatch Failure, Decode Error w/ Container Creation)"""
        # _check_container_exists
        get_mock.return_value.status_code = 200
        get_mock.return_value.json.return_value = {'count': 0, 'data': []}
        # _setup_container
        post_mock.return_value.status_code = 200
        post_mock.return_value.json.return_value = dict()


        assert_false(self._dispatcher.dispatch(descriptor=self.DESCRIPTOR,
                                               rule_name='rule_name',
                                               alert=get_alert()))

        log_mock.assert_called_with('Failed to send alert to %s', self.SERVICE)

    @patch('logging.Logger.error')
    @patch('requests.get')
    @patch('requests.post')
    def test_dispatch_failure(self, post_mock, get_mock, log_mock):
        """PhantomOutput - Dispatch Failure, Artifact"""
        # _check_container_exists
        get_mock.return_value.status_code = 200
        get_mock.return_value.json.return_value = {'count': 0, 'data': []}
        # _setup_container, dispatch
        type(post_mock.return_value).status_code = PropertyMock(side_effect=[200, 400])
        json_error = {'message': 'error message', 'errors': ['error1']}
        post_mock.return_value.json.return_value.side_effect = [{'id': 1948}, json_error]

        assert_false(self._dispatcher.dispatch(descriptor=self.DESCRIPTOR,
                                               rule_name='rule_name',
                                               alert=get_alert()))

        log_mock.assert_called_with('Failed to send alert to %s', self.SERVICE)

    @patch('logging.Logger.error')
    def test_dispatch_bad_descriptor(self, log_error_mock):
        """PhantomOutput - Dispatch Failure, Bad Descriptor"""
        assert_false(self._dispatcher.dispatch(descriptor='bad_descriptor',
                                               rule_name='rule_name',
                                               alert=get_alert()))

        log_error_mock.assert_called_with('Failed to send alert to %s', self.SERVICE)

    @patch('stream_alert.alert_processor.outputs.output_base.OutputDispatcher._get_request')
    @patch('stream_alert.alert_processor.outputs.output_base.OutputDispatcher._post_request')
    def test_dispatch_container_query(self, post_mock, get_mock):
        """PhantomOutput - Container Query URL"""
        rule_description = 'Info about this rule and what actions to take'
        headers = {'ph-auth-token': 'mocked_auth_token'}
        assert_false(PhantomOutput._setup_container('rule_name',
                                                    rule_description,
                                                    self.CREDS['url'],
                                                    headers))

        full_url = '{}/rest/container'.format(self.CREDS['url'])
        params = {'_filter_name': '"rule_name"', 'page_size': 1}
        get_mock.assert_has_calls([call(full_url, params, headers, False)])
        ph_container = {'name': 'rule_name', 'description': rule_description}
        post_mock.assert_has_calls([call(full_url, ph_container, headers, False)])

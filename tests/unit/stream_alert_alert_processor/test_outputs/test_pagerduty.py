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
# pylint: disable=protected-access
import json
from mock import patch, PropertyMock
from moto import mock_s3, mock_kms
from nose.tools import (
    assert_equal,
    assert_false
)

from stream_alert.alert_processor.outputs.output_base import StreamAlertOutput
from stream_alert_cli.helpers import put_mock_creds
from tests.unit.stream_alert_alert_processor import CONFIG, FUNCTION_NAME, KMS_ALIAS, REGION
from tests.unit.stream_alert_alert_processor.helpers import (
    get_alert,
    remove_temp_secrets
)


class TestPagerDutyOutput(object):
    """Test class for PagerDutyOutput"""
    @classmethod
    def setup_class(cls):
        """Setup the class before any methods"""
        cls.__service = 'pagerduty'
        cls.__descriptor = 'unit_test_pagerduty'
        cls.__backup_method = None
        cls.__dispatcher = StreamAlertOutput.create_dispatcher(cls.__service,
                                                               REGION,
                                                               FUNCTION_NAME,
                                                               CONFIG)

    @classmethod
    def teardown_class(cls):
        """Teardown the class after all methods"""
        cls.__dispatcher = None

    def test_get_default_properties(self):
        """Get Default Properties - PagerDuty"""
        props = self.__dispatcher._get_default_properties()
        assert_equal(len(props), 1)
        assert_equal(props['url'],
                     'https://events.pagerduty.com/generic/2010-04-15/create_event.json')

    def _setup_dispatch(self):
        """Helper for setting up PagerDutyOutput dispatch"""
        remove_temp_secrets()

        # Cache the _get_default_properties and set it to return None
        self.__backup_method = self.__dispatcher._get_default_properties
        self.__dispatcher._get_default_properties = lambda: None

        output_name = self.__dispatcher.output_cred_name(self.__descriptor)

        creds = {'url': 'http://pagerduty.foo.bar/create_event.json',
                 'service_key': 'mocked_service_key'}

        put_mock_creds(output_name, creds, self.__dispatcher.secrets_bucket, REGION, KMS_ALIAS)

        return get_alert()

    def _teardown_dispatch(self):
        """Replace method with cached method"""
        self.__dispatcher._get_default_properties = self.__backup_method

    @patch('logging.Logger.info')
    @patch('requests.post')
    @mock_s3
    @mock_kms
    def test_dispatch_success(self, post_mock, log_info_mock):
        """PagerDutyOutput dispatch success"""
        alert = self._setup_dispatch()
        post_mock.return_value.status_code = 200
        post_mock.return_value.text = ''

        self.__dispatcher.dispatch(descriptor=self.__descriptor,
                                   rule_name='rule_name',
                                   alert=alert)

        self._teardown_dispatch()

        log_info_mock.assert_called_with('Successfully sent alert to %s', self.__service)

    @patch('logging.Logger.error')
    @patch('requests.post')
    @mock_s3
    @mock_kms
    def test_dispatch_failure(self, post_mock, log_error_mock):
        """PagerDutyOutput dispatch failure"""
        alert = self._setup_dispatch()
        post_mock.return_value.text = '{"message": "error message", "errors": ["error1"]}'
        post_mock.return_value.status_code = 400

        self.__dispatcher.dispatch(descriptor=self.__descriptor,
                                   rule_name='rule_name',
                                   alert=alert)

        self._teardown_dispatch()

        log_error_mock.assert_called_with('Failed to send alert to %s', self.__service)

    @patch('logging.Logger.error')
    @mock_s3
    @mock_kms
    def test_dispatch_bad_descriptor(self, log_error_mock):
        """PagerDutyOutput dispatch bad descriptor"""
        alert = self._setup_dispatch()
        self.__dispatcher.dispatch(descriptor='bad_descriptor',
                                   rule_name='rule_name',
                                   alert=alert)

        self._teardown_dispatch()

        log_error_mock.assert_called_with('Failed to send alert to %s', self.__service)

class TestPagerDutyOutputV2(object):
    """Test class for PagerDutyOutputV2"""
    @classmethod
    def setup_class(cls):
        """Setup the class before any methods"""
        cls.__service = 'pagerduty-v2'
        cls.__descriptor = 'unit_test_pagerduty-v2'
        cls.__backup_method = None
        cls.__dispatcher = StreamAlertOutput.create_dispatcher(cls.__service,
                                                               REGION,
                                                               FUNCTION_NAME,
                                                               CONFIG)

    @classmethod
    def teardown_class(cls):
        """Teardown the class after all methods"""
        cls.__dispatcher = None

    def test_get_default_properties(self):
        """Get Default Properties - PagerDuty"""
        props = self.__dispatcher._get_default_properties()
        assert_equal(len(props), 1)
        assert_equal(props['url'],
                     'https://events.pagerduty.com/v2/enqueue')

    def _setup_dispatch(self):
        """Helper for setting up PagerDutyOutputV2 dispatch"""
        remove_temp_secrets()

        # Cache the _get_default_properties and set it to return None
        self.__backup_method = self.__dispatcher._get_default_properties
        self.__dispatcher._get_default_properties = lambda: None

        output_name = self.__dispatcher.output_cred_name(self.__descriptor)

        creds = {'url': 'http://pagerduty.foo.bar/create_event.json',
                 'routing_key': 'mocked_routing_key'}

        put_mock_creds(output_name, creds, self.__dispatcher.secrets_bucket, REGION, KMS_ALIAS)

        return get_alert()

    def _teardown_dispatch(self):
        """Replace method with cached method"""
        self.__dispatcher._get_default_properties = self.__backup_method

    @patch('logging.Logger.info')
    @patch('requests.post')
    @mock_s3
    @mock_kms
    def test_dispatch_success(self, post_mock, log_info_mock):
        """PagerDutyOutputV2 dispatch success"""
        alert = self._setup_dispatch()
        post_mock.return_value.status_code = 200
        post_mock.return_value.text = ''

        self.__dispatcher.dispatch(descriptor=self.__descriptor,
                                   rule_name='rule_name',
                                   alert=alert)

        self._teardown_dispatch()

        log_info_mock.assert_called_with('Successfully sent alert to %s', self.__service)

    @patch('logging.Logger.error')
    @patch('requests.post')
    @mock_s3
    @mock_kms
    def test_dispatch_failure(self, post_mock, log_error_mock):
        """PagerDutyOutputV2 dispatch failure"""
        alert = self._setup_dispatch()
        json_error = json.loads('{"message": "error message", "errors": ["error1"]}')
        post_mock.return_value.json.return_value = json_error
        post_mock.return_value.status_code = 400

        self.__dispatcher.dispatch(descriptor=self.__descriptor,
                                   rule_name='rule_name',
                                   alert=alert)

        self._teardown_dispatch()

        log_error_mock.assert_called_with('Failed to send alert to %s', self.__service)

    @patch('logging.Logger.error')
    @mock_s3
    @mock_kms
    def test_dispatch_bad_descriptor(self, log_error_mock):
        """PagerDutyOutputV2 dispatch bad descriptor"""
        alert = self._setup_dispatch()
        self.__dispatcher.dispatch(descriptor='bad_descriptor',
                                   rule_name='rule_name',
                                   alert=alert)

        self._teardown_dispatch()

        log_error_mock.assert_called_with('Failed to send alert to %s', self.__service)

class TestPagerDutyIncidentOutput(object):
    """Test class for PagerDutyIncidentOutput"""
    @classmethod
    def setup_class(cls):
        """Setup the class before any methods"""
        cls.__service = 'pagerduty-incident'
        cls.__descriptor = 'unit_test_pagerduty-incident'
        cls.__backup_method = None
        cls.__dispatcher = StreamAlertOutput.create_dispatcher(cls.__service,
                                                               REGION,
                                                               FUNCTION_NAME,
                                                               CONFIG)

    @classmethod
    def teardown_class(cls):
        """Teardown the class after all methods"""
        cls.__dispatcher = None

    def test_get_default_properties(self):
        """Get Default Properties - PagerDutyIncidentOutput"""
        props = self.__dispatcher._get_default_properties()
        assert_equal(len(props), 1)
        assert_equal(props['api'],
                     'https://api.pagerduty.com')

    def test_get_endpoint(self):
        """Get Endpoint - PagerDutyIncidentOutput"""
        props = self.__dispatcher._get_default_properties()
        endpoint = self.__dispatcher._get_endpoint(props['api'], 'testtest')
        assert_equal(endpoint,
                     'https://api.pagerduty.com/testtest')

    def _setup_dispatch(self, context=None):
        """Helper for setting up PagerDutyIncidentOutput dispatch"""
        remove_temp_secrets()

        # Cache the _get_default_properties and set it to return None
        self.__backup_method = self.__dispatcher._get_default_properties
        self.__dispatcher._get_default_properties = lambda: None

        output_name = self.__dispatcher.output_cred_name(self.__descriptor)

        creds = {'api': 'https://api.pagerduty.com',
                 'token': 'mocked_token',
                 'service_key': 'mocked_service_key',
                 'escalation_policy': 'mocked_escalation_policy'}

        put_mock_creds(output_name, creds, self.__dispatcher.secrets_bucket, REGION, KMS_ALIAS)

        return get_alert(context)

    def _teardown_dispatch(self):
        """Replace method with cached method"""
        self.__dispatcher._get_default_properties = self.__backup_method

    @patch('requests.get')
    def test_check_exists_get_id(self, get_mock):
        """Check Exists Get Id - PagerDutyIncidentOutput"""
        # /check
        get_mock.return_value.status_code = 200
        json_check = json.loads('{"check": [{"id": "checked_id"}]}')
        get_mock.return_value.json.return_value = json_check

        checked = self.__dispatcher._check_exists_get_id('filter', 'http://mock_url', 'check')
        assert_equal(checked, 'checked_id')

    @patch('requests.get')
    def test_check_exists_get_id_fail(self, get_mock):
        """Check Exists Get Id Fail - PagerDutyIncidentOutput"""
        # /check
        get_mock.return_value.status_code = 200
        json_check = json.loads('{}')
        get_mock.return_value.json.return_value = json_check

        checked = self.__dispatcher._check_exists_get_id('filter', 'http://mock_url', 'check')
        assert_false(checked)

    @patch('requests.get')
    def test_user_verify_success(self, get_mock):
        """User Verify Success - PagerDutyIncidentOutput"""
        get_mock.return_value.status_code = 200
        json_check = json.loads('{"users": [{"id": "verified_user_id"}]}')
        get_mock.return_value.json.return_value = json_check

        user_verified = self.__dispatcher._user_verify('valid_user')
        assert_equal(user_verified['id'], 'verified_user_id')
        assert_equal(user_verified['type'], 'user_reference')

    @patch('requests.get')
    def test_user_verify_fail(self, get_mock):
        """User Verify Fail - PagerDutyIncidentOutput"""
        get_mock.return_value.status_code = 200
        json_check = json.loads('{"not_users": [{"not_id": "verified_user_id"}]}')
        get_mock.return_value.json.return_value = json_check

        user_verified = self.__dispatcher._user_verify('valid_user')
        assert_false(user_verified)

    @patch('requests.get')
    def test_policy_verify_success_no_default(self, get_mock):
        """Policy Verify Success (No Default) - PagerDutyIncidentOutput"""
        # /escalation_policies
        get_mock.return_value.status_code = 200
        json_check = json.loads('{"escalation_policies": [{"id": "good_policy_id"}]}')
        get_mock.return_value.json.return_value = json_check

        policy_verified = self.__dispatcher._policy_verify('valid_policy', '')
        assert_equal(policy_verified['id'], 'good_policy_id')
        assert_equal(policy_verified['type'], 'escalation_policy_reference')

    @patch('requests.get')
    def test_policy_verify_success_default(self, get_mock):
        """Policy Verify Success (Default) - PagerDutyIncidentOutput"""
        # /escalation_policies
        type(get_mock.return_value).status_code = PropertyMock(side_effect=[200, 200])
        json_check_bad = json.loads('{"no_escalation_policies": [{"id": "bad_policy_id"}]}')
        json_check_good = json.loads('{"escalation_policies": [{"id": "good_policy_id"}]}')
        get_mock.return_value.json.side_effect = [json_check_bad, json_check_good]

        policy_verified = self.__dispatcher._policy_verify('valid_policy', 'default_policy')
        assert_equal(policy_verified['id'], 'good_policy_id')
        assert_equal(policy_verified['type'], 'escalation_policy_reference')

    @patch('requests.get')
    def test_policy_verify_fail_default(self, get_mock):
        """Policy Verify Fail (Default) - PagerDutyIncidentOutput"""
        # /not_escalation_policies
        type(get_mock.return_value).status_code = PropertyMock(side_effect=[400, 400])
        json_check_bad = json.loads('{"escalation_policies": [{"id": "bad_policy_id"}]}')
        json_check_bad_default = json.loads('{"escalation_policies": [{"id": "good_policy_id"}]}')
        get_mock.return_value.json.side_effect = [json_check_bad, json_check_bad_default]
        policy_verified = self.__dispatcher._policy_verify('valid_policy', 'default_policy')
        assert_false(policy_verified)

    @patch('requests.get')
    def test_policy_verify_fail_no_default(self, get_mock):
        """Policy Verify Fail (No Default) - PagerDutyIncidentOutput"""
        # /not_escalation_policies
        get_mock.return_value.status_code = 200
        json_check = json.loads('{"not_escalation_policies": [{"not_id": "verified_policy_id"}]}')
        get_mock.return_value.json.return_value = json_check

        policy_verified = self.__dispatcher._policy_verify('valid_policy', 'default_policy')
        assert_false(policy_verified)

    @patch('requests.get')
    def test_service_verify_success(self, get_mock):
        """Service Verify Success - PagerDutyIncidentOutput"""
        # /services
        get_mock.return_value.status_code = 200
        json_check = json.loads('{"services": [{"id": "verified_service_id"}]}')
        get_mock.return_value.json.return_value = json_check

        service_verified = self.__dispatcher._service_verify('valid_service')
        assert_equal(service_verified['id'], 'verified_service_id')
        assert_equal(service_verified['type'], 'service_reference')

    @patch('requests.get')
    def test_service_verify_fail(self, get_mock):
        """Service Verify Fail - PagerDutyIncidentOutput"""
        get_mock.return_value.status_code = 200
        json_check = json.loads('{"not_services": [{"not_id": "verified_service_id"}]}')
        get_mock.return_value.json.return_value = json_check

        service_verified = self.__dispatcher._service_verify('valid_service')
        assert_false(service_verified)

    @patch('requests.get')
    def test_item_verify_success(self, get_mock):
        """Item Verify Success - PagerDutyIncidentOutput"""
        # /items
        get_mock.return_value.status_code = 200
        json_check = json.loads('{"items": [{"id": "verified_item_id"}]}')
        get_mock.return_value.json.return_value = json_check

        item_verified = self.__dispatcher._item_verify('http://mock_url', 'valid_item',
                                                       'items', 'item_reference')
        assert_equal(item_verified['id'], 'verified_item_id')
        assert_equal(item_verified['type'], 'item_reference')

    @patch('requests.get')
    def test_incident_assignment_user(self, get_mock):
        """Incident Assignment User - PagerDutyIncidentOutput"""
        context = {'assigned_user': 'user_to_assign'}
        get_mock.return_value.status_code = 200
        json_user = json.loads('{"users": [{"id": "verified_user_id"}]}')
        get_mock.return_value.json.return_value = json_user

        assigned_key, assigned_value = self.__dispatcher._incident_assignment(context)

        assert_equal(assigned_key, 'assignments')
        assert_equal(assigned_value[0]['assignee']['id'], 'verified_user_id')
        assert_equal(assigned_value[0]['assignee']['type'], 'user_reference')

    @patch('requests.get')
    def test_incident_assignment_policy_no_default(self, get_mock):
        """Incident Assignment Policy (No Default) - PagerDutyIncidentOutput"""
        context = {'assigned_policy': 'policy_to_assign'}
        get_mock.return_value.status_code = 200
        json_policy = json.loads('{"escalation_policies": [{"id": "verified_policy_id"}]}')
        get_mock.return_value.json.return_value = json_policy

        assigned_key, assigned_value = self.__dispatcher._incident_assignment(context)

        assert_equal(assigned_key, 'escalation_policy')
        assert_equal(assigned_value['id'], 'verified_policy_id')
        assert_equal(assigned_value['type'], 'escalation_policy_reference')

    @patch('requests.get')
    def test_incident_assignment_policy_default(self, get_mock):
        """Incident Assignment Policy (Default) - PagerDutyIncidentOutput"""
        context = {'assigned_policy': 'bad_invalid_policy_to_assign'}
        type(get_mock.return_value).status_code = PropertyMock(side_effect=[200, 200])
        json_bad_policy = json.loads('{"not_escalation_policies": [{"id": "bad_policy_id"}]}')
        json_good_policy = json.loads('{"escalation_policies": [{"id": "verified_policy_id"}]}')
        get_mock.return_value.json.side_effect = [json_bad_policy, json_good_policy]

        assigned_key, assigned_value = self.__dispatcher._incident_assignment(context)

        assert_equal(assigned_key, 'escalation_policy')
        assert_equal(assigned_value['id'], 'verified_policy_id')
        assert_equal(assigned_value['type'], 'escalation_policy_reference')

    @patch('requests.get')
    def test_item_verify_fail(self, get_mock):
        """Item Verify Fail - PagerDutyIncidentOutput"""
        # /not_items
        get_mock.return_value.status_code = 200
        json_check = json.loads('{"not_items": [{"not_id": "verified_item_id"}]}')
        get_mock.return_value.json.return_value = json_check

        item_verified = self.__dispatcher._item_verify('http://mock_url', 'valid_item',
                                                       'items', 'item_reference')
        assert_false(item_verified)

    @patch('logging.Logger.info')
    @patch('requests.post')
    @patch('requests.get')
    @mock_s3
    @mock_kms
    def test_dispatch_success_good_user(self, get_mock, post_mock, log_info_mock):
        """PagerDutyIncidentOutput dispatch success - Good User"""
        ctx = {
            'pagerduty-incident': {
                'assigned_user': 'valid_user'
            }
        }
        alert = self._setup_dispatch(context=ctx)

        # /users, /services
        type(get_mock.return_value).status_code = PropertyMock(side_effect=[200, 200])
        json_user = json.loads('{"users": [{"id": "valid_user_id"}]}')
        json_service = json.loads('{"services": [{"id": "service_id"}]}')
        get_mock.return_value.json.side_effect = [json_user, json_service]

        # /incidents
        post_mock.return_value.status_code = 200

        self.__dispatcher.dispatch(descriptor=self.__descriptor,
                                   rule_name='rule_name',
                                   alert=alert)

        self._teardown_dispatch()

        log_info_mock.assert_called_with('Successfully sent alert to %s', self.__service)

    @patch('logging.Logger.info')
    @patch('requests.post')
    @patch('requests.get')
    @mock_s3
    @mock_kms
    def test_dispatch_success_good_policy(self, get_mock, post_mock, log_info_mock):
        """PagerDutyIncidentOutput dispatch success - Good Policy"""
        ctx = {
            'pagerduty-incident': {
                'assigned_policy': 'valid_policy'
            }
        }
        alert = self._setup_dispatch(context=ctx)

        # /escalation_policies, /services
        type(get_mock.return_value).status_code = PropertyMock(side_effect=[200, 200])
        json_policy = json.loads('{"escalation_policies": [{"id": "policy_id"}]}')
        json_service = json.loads('{"services": [{"id": "service_id"}]}')
        get_mock.return_value.json.side_effect = [json_policy, json_service]

        # /incidents
        post_mock.return_value.status_code = 200

        self.__dispatcher.dispatch(descriptor=self.__descriptor,
                                   rule_name='rule_name',
                                   alert=alert)

        self._teardown_dispatch()

        log_info_mock.assert_called_with('Successfully sent alert to %s', self.__service)

    @patch('logging.Logger.info')
    @patch('requests.post')
    @patch('requests.get')
    @mock_s3
    @mock_kms
    def test_dispatch_success_bad_user(self, get_mock, post_mock, log_info_mock):
        """PagerDutyIncidentOutput dispatch success - Bad User"""
        ctx = {
            'pagerduty-incident': {
                'assigned_user': 'invalid_user'
            }
        }
        alert = self._setup_dispatch(context=ctx)

        # /users, /escalation_policies, /services
        type(get_mock.return_value).status_code = PropertyMock(side_effect=[200, 200, 200])
        json_user = json.loads('{"not_users": [{"id": "user_id"}]}')
        json_policy = json.loads('{"escalation_policies": [{"id": "policy_id"}]}')
        json_service = json.loads('{"services": [{"id": "service_id"}]}')
        get_mock.return_value.json.side_effect = [json_user, json_policy, json_service]

        # /incidents
        post_mock.return_value.status_code = 200

        self.__dispatcher.dispatch(descriptor=self.__descriptor,
                                   rule_name='rule_name',
                                   alert=alert)

        self._teardown_dispatch()

        log_info_mock.assert_called_with('Successfully sent alert to %s', self.__service)

    @patch('logging.Logger.info')
    @patch('requests.post')
    @patch('requests.get')
    @mock_s3
    @mock_kms
    def test_dispatch_success_no_context(self, get_mock, post_mock, log_info_mock):
        """PagerDutyIncidentOutput dispatch success - No Context"""
        alert = self._setup_dispatch()

        # /escalation_policies, /services
        type(get_mock.return_value).status_code = PropertyMock(side_effect=[200, 200])
        json_policy = json.loads('{"escalation_policies": [{"id": "policy_id"}]}')
        json_service = json.loads('{"services": [{"id": "service_id"}]}')
        get_mock.return_value.json.side_effect = [json_policy, json_service]

        # /incidents
        post_mock.return_value.status_code = 200

        self.__dispatcher.dispatch(descriptor=self.__descriptor,
                                   rule_name='rule_name',
                                   alert=alert)

        self._teardown_dispatch()

        log_info_mock.assert_called_with('Successfully sent alert to %s', self.__service)

    @patch('logging.Logger.error')
    @patch('requests.post')
    @patch('requests.get')
    @mock_s3
    @mock_kms
    def test_dispatch_failure_bad_everything(self, get_mock, post_mock, log_error_mock):
        """PagerDutyIncidentOutput dispatch failure - No User, Bad Policy, Bad Service"""
        alert = self._setup_dispatch()
        # /escalation_policies, /services
        type(get_mock.return_value).status_code = PropertyMock(side_effect=[400, 400, 400])
        json_empty = json.loads('{}')
        get_mock.return_value.json.side_effect = [json_empty, json_empty, json_empty]

        # /incidents
        post_mock.return_value.status_code = 400

        self.__dispatcher.dispatch(descriptor=self.__descriptor,
                                   rule_name='rule_name',
                                   alert=alert)

        self._teardown_dispatch()

        log_error_mock.assert_called_with('Failed to send alert to %s', self.__service)

    @patch('logging.Logger.info')
    @patch('requests.post')
    @patch('requests.get')
    @mock_s3
    @mock_kms
    def test_dispatch_success_bad_policy(self, get_mock, post_mock, log_info_mock):
        """PagerDutyIncidentOutput dispatch success - Bad Policy"""
        ctx = {
            'pagerduty-incident': {
                'assigned_policy': 'valid_policy'
            }
        }
        alert = self._setup_dispatch(context=ctx)
        # /escalation_policies, /services
        get_mock.return_value.side_effect = [400, 200, 200]
        type(get_mock.return_value).status_code = PropertyMock(side_effect=[400, 200, 200])
        json_bad_policy = json.loads('{}')
        json_good_policy = json.loads('{"escalation_policies": [{"id": "policy_id"}]}')
        json_service = json.loads('{"services": [{"id": "service_id"}]}')
        get_mock.return_value.json.side_effect = [json_bad_policy, json_good_policy, json_service]

        # /incidents
        post_mock.return_value.status_code = 200

        self.__dispatcher.dispatch(descriptor=self.__descriptor,
                                   rule_name='rule_name',
                                   alert=alert)

        self._teardown_dispatch()

        log_info_mock.assert_called_with('Successfully sent alert to %s', self.__service)

    @patch('logging.Logger.error')
    @patch('requests.post')
    @patch('requests.get')
    @mock_s3
    @mock_kms
    def test_dispatch_bad_dispatch(self, get_mock, post_mock, log_error_mock):
        """PagerDutyIncidentOutput dispatch - Bad Dispatch"""
        alert = self._setup_dispatch()
        # /escalation_policies, /services
        type(get_mock.return_value).status_code = PropertyMock(side_effect=[200, 200])
        json_policy = json.loads('{"escalation_policies": [{"id": "policy_id"}]}')
        json_service = json.loads('{"services": [{"id": "service_id"}]}')
        get_mock.return_value.json.side_effect = [json_policy, json_service]

        # /incidents
        post_mock.return_value.status_code = 400

        self.__dispatcher.dispatch(descriptor=self.__descriptor,
                                   rule_name='rule_name',
                                   alert=alert)

        self._teardown_dispatch()

        log_error_mock.assert_called_with('Failed to send alert to %s', self.__service)

    @patch('logging.Logger.error')
    @mock_s3
    @mock_kms
    def test_dispatch_bad_descriptor(self, log_error_mock):
        """PagerDutyIncidentOutput dispatch - Bad Descriptor"""
        alert = self._setup_dispatch()
        self.__dispatcher.dispatch(descriptor='bad_descriptor',
                                   rule_name='rule_name',
                                   alert=alert)

        self._teardown_dispatch()

        log_error_mock.assert_called_with('Failed to send alert to %s', self.__service)

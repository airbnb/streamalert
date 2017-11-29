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
from mock import patch, PropertyMock
from moto import mock_s3, mock_kms
from nose.tools import assert_equal, assert_false, assert_true, assert_raises

from stream_alert.alert_processor.outputs.output_base import (
    OutputRequestFailure
)
from stream_alert.alert_processor.outputs.pagerduty import (
    PagerDutyOutput,
    PagerDutyOutputV2,
    PagerDutyIncidentOutput
)
from stream_alert_cli.helpers import put_mock_creds
from tests.unit.stream_alert_alert_processor import CONFIG, FUNCTION_NAME, KMS_ALIAS, REGION
from tests.unit.stream_alert_alert_processor.helpers import get_alert, remove_temp_secrets


@mock_s3
@mock_kms
class TestPagerDutyOutput(object):
    """Test class for PagerDutyOutput"""
    DESCRIPTOR = 'unit_test_pagerduty'
    SERVICE = 'pagerduty'
    CREDS = {'url': 'http://pagerduty.foo.bar/create_event.json',
             'service_key': 'mocked_service_key'}

    def setup(self):
        """Setup before each method"""
        self._dispatcher = PagerDutyOutput(REGION, FUNCTION_NAME, CONFIG)
        remove_temp_secrets()
        output_name = self._dispatcher.output_cred_name(self.DESCRIPTOR)
        put_mock_creds(output_name, self.CREDS, self._dispatcher.secrets_bucket, REGION, KMS_ALIAS)

    def test_get_default_properties(self):
        """PagerDutyOutput - Get Default Properties"""
        props = self._dispatcher._get_default_properties()
        assert_equal(len(props), 1)
        assert_equal(props['url'],
                     'https://events.pagerduty.com/generic/2010-04-15/create_event.json')

    @patch('logging.Logger.info')
    @patch('requests.post')
    def test_dispatch_success(self, post_mock, log_mock):
        """PagerDutyOutput - Dispatch Success"""
        post_mock.return_value.status_code = 200

        assert_true(self._dispatcher.dispatch(descriptor=self.DESCRIPTOR,
                                              rule_name='rule_name',
                                              alert=get_alert()))

        log_mock.assert_called_with('Successfully sent alert to %s', self.SERVICE)

    @patch('requests.post')
    def test_dispatch_failure(self, post_mock):
        """PagerDutyOutput - Dispatch Failure, Bad Request"""
        post_mock.return_value.status_code = 400

        assert_raises(OutputRequestFailure, self._dispatcher.dispatch,
                      descriptor=self.DESCRIPTOR,
                      rule_name='rule_name',
                      alert=get_alert())

    @patch('logging.Logger.error')
    def test_dispatch_bad_descriptor(self, log_mock):
        """PagerDutyOutput - Dispatch Failure, Bad Descriptor"""
        assert_false(self._dispatcher.dispatch(descriptor='bad_descriptor',
                                               rule_name='rule_name',
                                               alert=get_alert()))

        log_mock.assert_called_with('Failed to send alert to %s', self.SERVICE)

@mock_s3
@mock_kms
class TestPagerDutyOutputV2(object):
    """Test class for PagerDutyOutputV2"""
    DESCRIPTOR = 'unit_test_pagerduty-v2'
    SERVICE = 'pagerduty-v2'
    CREDS = {'url': 'http://pagerduty.foo.bar/create_event.json',
             'routing_key': 'mocked_routing_key'}

    def setup(self):
        """Setup before each method"""
        self._dispatcher = PagerDutyOutputV2(REGION, FUNCTION_NAME, CONFIG)
        remove_temp_secrets()
        output_name = self._dispatcher.output_cred_name(self.DESCRIPTOR)
        put_mock_creds(output_name, self.CREDS, self._dispatcher.secrets_bucket, REGION, KMS_ALIAS)

    def test_get_default_properties(self):
        """PagerDutyOutputV2 - Get Default Properties"""
        props = self._dispatcher._get_default_properties()
        assert_equal(len(props), 1)
        assert_equal(props['url'], 'https://events.pagerduty.com/v2/enqueue')

    @patch('logging.Logger.info')
    @patch('requests.post')
    def test_dispatch_success(self, post_mock, log_mock):
        """PagerDutyOutputV2 - Dispatch Success"""
        post_mock.return_value.status_code = 200

        assert_true(self._dispatcher.dispatch(descriptor=self.DESCRIPTOR,
                                              rule_name='rule_name',
                                              alert=get_alert()))

        log_mock.assert_called_with('Successfully sent alert to %s', self.SERVICE)

    @patch('requests.post')
    def test_dispatch_failure(self, post_mock):
        """PagerDutyOutputV2 - Dispatch Failure, Bad Request"""
        json_error = {'message': 'error message', 'errors': ['error1']}
        post_mock.return_value.json.return_value = json_error
        post_mock.return_value.status_code = 400

        assert_raises(OutputRequestFailure, self._dispatcher.dispatch,
                      descriptor=self.DESCRIPTOR,
                      rule_name='rule_name',
                      alert=get_alert())

    @patch('logging.Logger.error')
    def test_dispatch_bad_descriptor(self, log_mock):
        """PagerDutyOutputV2 - Dispatch Failure, Bad Descriptor"""
        assert_false(self._dispatcher.dispatch(descriptor='bad_descriptor',
                                               rule_name='rule_name',
                                               alert=get_alert()))

        log_mock.assert_called_with('Failed to send alert to %s', self.SERVICE)


#pylint: disable=too-many-public-methods
@mock_s3
@mock_kms
class TestPagerDutyIncidentOutput(object):
    """Test class for PagerDutyIncidentOutput"""
    DESCRIPTOR = 'unit_test_pagerduty-incident'
    SERVICE = 'pagerduty-incident'
    CREDS = {'api': 'https://api.pagerduty.com',
             'token': 'mocked_token',
             'service_key': 'mocked_service_key',
             'escalation_policy': 'mocked_escalation_policy',
             'email_from': 'email@domain.com'}

    def setup(self):
        """Setup before each method"""
        self._dispatcher = PagerDutyIncidentOutput(REGION, FUNCTION_NAME, CONFIG)
        self._dispatcher._base_url = self.CREDS['api']
        remove_temp_secrets()
        output_name = self._dispatcher.output_cred_name(self.DESCRIPTOR)
        put_mock_creds(output_name, self.CREDS, self._dispatcher.secrets_bucket, REGION, KMS_ALIAS)

    def test_get_default_properties(self):
        """PagerDutyIncidentOutput - Get Default Properties"""
        props = self._dispatcher._get_default_properties()
        assert_equal(len(props), 1)
        assert_equal(props['api'], 'https://api.pagerduty.com')

    def test_get_endpoint(self):
        """PagerDutyIncidentOutput - Get Endpoint"""
        endpoint = self._dispatcher._get_endpoint(self.CREDS['api'], 'testtest')
        assert_equal(endpoint, 'https://api.pagerduty.com/testtest')

    @patch('requests.get')
    def test_check_exists_get_id(self, get_mock):
        """PagerDutyIncidentOutput - Check Exists Get ID"""
        # /check
        get_mock.return_value.status_code = 200
        json_check = {'check': [{'id': 'checked_id'}]}
        get_mock.return_value.json.return_value = json_check

        checked = self._dispatcher._check_exists('filter', 'http://mock_url', 'check')
        assert_equal(checked, 'checked_id')

    @patch('requests.get')
    def test_check_exists_get_id_fail(self, get_mock):
        """PagerDutyIncidentOutput - Check Exists Get Id Fail"""
        get_mock.return_value.status_code = 200
        get_mock.return_value.json.return_value = dict()

        checked = self._dispatcher._check_exists('filter', 'http://mock_url', 'check')
        assert_false(checked)

    @patch('requests.get')
    def test_check_exists_no_get_id(self, get_mock):
        """Check Exists No Get Id - PagerDutyIncidentOutput"""
        # /check
        get_mock.return_value.status_code = 200
        json_check = {'check': [{'id': 'checked_id'}]}
        get_mock.return_value.json.return_value = json_check

        assert_true(self._dispatcher._check_exists('filter', 'http://mock_url', 'check', False))

    @patch('requests.get')
    def test_user_verify_success(self, get_mock):
        """PagerDutyIncidentOutput - User Verify Success"""
        get_mock.return_value.status_code = 200
        json_check = {'users': [{'id': 'verified_user_id'}]}
        get_mock.return_value.json.return_value = json_check

        user_verified = self._dispatcher._user_verify('valid_user')
        assert_equal(user_verified['id'], 'verified_user_id')
        assert_equal(user_verified['type'], 'user_reference')

    @patch('requests.get')
    def test_user_verify_fail(self, get_mock):
        """PagerDutyIncidentOutput - User Verify Fail"""
        get_mock.return_value.status_code = 200
        json_check = {'not_users': [{'not_id': 'verified_user_id'}]}
        get_mock.return_value.json.return_value = json_check

        user_verified = self._dispatcher._user_verify('valid_user')
        assert_false(user_verified)

    @patch('requests.get')
    def test_policy_verify_success_no_default(self, get_mock):
        """PagerDutyIncidentOutput - Policy Verify Success (No Default)"""
        # /escalation_policies
        get_mock.return_value.status_code = 200
        json_check = {'escalation_policies': [{'id': 'good_policy_id'}]}
        get_mock.return_value.json.return_value = json_check

        policy_verified = self._dispatcher._policy_verify('valid_policy', '')
        assert_equal(policy_verified['id'], 'good_policy_id')
        assert_equal(policy_verified['type'], 'escalation_policy_reference')

    @patch('requests.get')
    def test_policy_verify_success_default(self, get_mock):
        """PagerDutyIncidentOutput - Policy Verify Success (Default)"""
        # /escalation_policies
        type(get_mock.return_value).status_code = PropertyMock(side_effect=[200, 200])
        json_check_bad = {'no_escalation_policies': [{'id': 'bad_policy_id'}]}
        json_check_good = {'escalation_policies': [{'id': 'good_policy_id'}]}
        get_mock.return_value.json.side_effect = [json_check_bad, json_check_good]

        policy_verified = self._dispatcher._policy_verify('valid_policy', 'default_policy')
        assert_equal(policy_verified['id'], 'good_policy_id')
        assert_equal(policy_verified['type'], 'escalation_policy_reference')

    @patch('requests.get')
    def test_policy_verify_fail_default(self, get_mock):
        """PagerDutyIncidentOutput - Policy Verify Fail (Default)"""
        # /not_escalation_policies
        type(get_mock.return_value).status_code = PropertyMock(side_effect=[400, 400])
        json_check_bad = {'escalation_policies': [{'id': 'bad_policy_id'}]}
        json_check_bad_default = {'escalation_policies': [{'id': 'good_policy_id'}]}
        get_mock.return_value.json.side_effect = [json_check_bad, json_check_bad_default]

        assert_false(self._dispatcher._policy_verify('valid_policy', 'default_policy'))

    @patch('requests.get')
    def test_policy_verify_fail_no_default(self, get_mock):
        """PagerDutyIncidentOutput - Policy Verify Fail (No Default)"""
        # /not_escalation_policies
        get_mock.return_value.status_code = 200
        json_check = {'not_escalation_policies': [{'not_id': 'verified_policy_id'}]}
        get_mock.return_value.json.return_value = json_check

        assert_false(self._dispatcher._policy_verify('valid_policy', 'default_policy'))

    @patch('requests.get')
    def test_service_verify_success(self, get_mock):
        """PagerDutyIncidentOutput - Service Verify Success"""
        # /services
        get_mock.return_value.status_code = 200
        json_check = {'services': [{'id': 'verified_service_id'}]}
        get_mock.return_value.json.return_value = json_check

        service_verified = self._dispatcher._service_verify('valid_service')
        assert_equal(service_verified['id'], 'verified_service_id')
        assert_equal(service_verified['type'], 'service_reference')

    @patch('requests.get')
    def test_service_verify_fail(self, get_mock):
        """PagerDutyIncidentOutput - Service Verify Fail"""
        get_mock.return_value.status_code = 200
        json_check = {'not_services': [{'not_id': 'verified_service_id'}]}
        get_mock.return_value.json.return_value = json_check

        assert_false(self._dispatcher._service_verify('valid_service'))

    @patch('requests.get')
    def test_item_verify_success(self, get_mock):
        """PagerDutyIncidentOutput - Item Verify Success"""
        # /items
        get_mock.return_value.status_code = 200
        json_check = {'items': [{'id': 'verified_item_id'}]}
        get_mock.return_value.json.return_value = json_check

        item_verified = self._dispatcher._item_verify('valid_item', 'items', 'item_reference')

        assert_equal(item_verified['id'], 'verified_item_id')
        assert_equal(item_verified['type'], 'item_reference')

    @patch('requests.get')
    def test_item_verify_no_get_id_success(self, get_mock):
        """Item Verify No Get Id Success - PagerDutyIncidentOutput"""
        # /items
        get_mock.return_value.status_code = 200
        json_check = {'items': [{'id': 'verified_item_id'}]}
        get_mock.return_value.json.return_value = json_check

        assert_true(self._dispatcher._item_verify('valid_item', 'items', 'item_reference', False))

    @patch('requests.get')
    def test_priority_verify_success(self, get_mock):
        """PagerDutyIncidentOutput - Priority Verify Success"""
        priority_name = 'priority_name'
        # /priorities
        get_mock.return_value.status_code = 200
        json_check = {'priorities': [{'id': 'verified_priority_id', 'name': priority_name}]}
        get_mock.return_value.json.return_value = json_check

        context = {'incident_priority': priority_name}

        priority_verified = self._dispatcher._priority_verify(context)
        assert_equal(priority_verified['id'], 'verified_priority_id')
        assert_equal(priority_verified['type'], 'priority_reference')

    @patch('requests.get')
    def test_priority_verify_fail(self, get_mock):
        """PagerDutyIncidentOutput - Priority Verify Fail"""
        # /priorities
        get_mock.return_value.status_code = 404

        context = {'incident_priority': 'priority_name'}

        priority_not_verified = self._dispatcher._priority_verify(context)
        assert_equal(priority_not_verified, dict())

    @patch('requests.get')
    def test_priority_verify_empty(self, get_mock):
        """PagerDutyIncidentOutput - Priority Verify Empty"""
        # /priorities
        get_mock.return_value.status_code = 200
        json_check = {}
        get_mock.return_value.json.return_value = json_check

        context = {'incident_priority': 'priority_name'}

        priority_not_verified = self._dispatcher._priority_verify(context)
        assert_equal(priority_not_verified, dict())

    @patch('requests.get')
    def test_priority_verify_not_found(self, get_mock):
        """PagerDutyIncidentOutput - Priority Verify Not Found"""
        # /priorities
        get_mock.return_value.status_code = 200
        json_check = {'priorities': [{'id': 'verified_priority_id', 'name': 'not_priority_name'}]}
        get_mock.return_value.json.return_value = json_check

        context = {'incident_priority': 'priority_name'}

        priority_not_verified = self._dispatcher._priority_verify(context)
        assert_equal(priority_not_verified, dict())

    @patch('requests.get')
    def test_priority_verify_invalid(self, get_mock):
        """PagerDutyIncidentOutput - Priority Verify Invalid"""
        # /priorities
        get_mock.return_value.status_code = 200
        json_check = {'not_priorities': [{'id': 'verified_priority_id', 'name': 'priority_name'}]}
        get_mock.return_value.json.return_value = json_check

        context = {'incident_priority': 'priority_name'}

        priority_not_verified = self._dispatcher._priority_verify(context)
        assert_equal(priority_not_verified, dict())

    @patch('requests.get')
    def test_incident_assignment_user(self, get_mock):
        """PagerDutyIncidentOutput - Incident Assignment User"""
        context = {'assigned_user': 'user_to_assign'}
        get_mock.return_value.status_code = 200
        json_user = {'users': [{'id': 'verified_user_id'}]}
        get_mock.return_value.json.return_value = json_user

        assigned_key, assigned_value = self._dispatcher._incident_assignment(context)

        assert_equal(assigned_key, 'assignments')
        assert_equal(assigned_value[0]['assignee']['id'], 'verified_user_id')
        assert_equal(assigned_value[0]['assignee']['type'], 'user_reference')

    @patch('requests.get')
    def test_incident_assignment_policy_no_default(self, get_mock):
        """PagerDutyIncidentOutput - Incident Assignment Policy (No Default)"""
        context = {'assigned_policy': 'policy_to_assign'}
        get_mock.return_value.status_code = 200
        json_policy = {'escalation_policies': [{'id': 'verified_policy_id'}]}
        get_mock.return_value.json.return_value = json_policy

        assigned_key, assigned_value = self._dispatcher._incident_assignment(context)

        assert_equal(assigned_key, 'escalation_policy')
        assert_equal(assigned_value['id'], 'verified_policy_id')
        assert_equal(assigned_value['type'], 'escalation_policy_reference')

    @patch('requests.get')
    def test_incident_assignment_policy_default(self, get_mock):
        """PagerDutyIncidentOutput - Incident Assignment Policy (Default)"""
        context = {'assigned_policy': 'bad_invalid_policy_to_assign'}
        type(get_mock.return_value).status_code = PropertyMock(side_effect=[200, 200])
        json_bad_policy = {'not_escalation_policies': [{'id': 'bad_policy_id'}]}
        json_good_policy = {'escalation_policies': [{'id': 'verified_policy_id'}]}
        get_mock.return_value.json.side_effect = [json_bad_policy, json_good_policy]

        assigned_key, assigned_value = self._dispatcher._incident_assignment(context)

        assert_equal(assigned_key, 'escalation_policy')
        assert_equal(assigned_value['id'], 'verified_policy_id')
        assert_equal(assigned_value['type'], 'escalation_policy_reference')

    @patch('requests.get')
    def test_item_verify_fail(self, get_mock):
        """PagerDutyIncidentOutput - Item Verify Fail"""
        # /not_items
        get_mock.return_value.status_code = 200
        json_check = {'not_items': [{'not_id': 'verified_item_id'}]}
        get_mock.return_value.json.return_value = json_check

        item_verified = self._dispatcher._item_verify('http://mock_url', 'valid_item',
                                                      'items', 'item_reference')
        assert_false(item_verified)

    @patch('logging.Logger.info')
    @patch('requests.post')
    @patch('requests.get')
    def test_dispatch_success_good_user(self, get_mock, post_mock, log_mock):
        """PagerDutyIncidentOutput - Dispatch Success, Good User"""
        # /users, /users, /services
        type(get_mock.return_value).status_code = PropertyMock(side_effect=[200, 200, 200])
        json_user = {'users': [{'id': 'valid_user_id'}]}
        json_service = {'services': [{'id': 'service_id'}]}
        get_mock.return_value.json.side_effect = [json_user, json_user, json_service]

        # /incidents
        post_mock.return_value.status_code = 200

        ctx = {'pagerduty-incident': {'assigned_user': 'valid_user'}}

        assert_true(self._dispatcher.dispatch(descriptor=self.DESCRIPTOR,
                                              rule_name='rule_name',
                                              alert=get_alert(context=ctx)))

        log_mock.assert_called_with('Successfully sent alert to %s', self.SERVICE)

    @patch('logging.Logger.info')
    @patch('requests.post')
    @patch('requests.get')
    def test_dispatch_success_good_policy(self, get_mock, post_mock, log_mock):
        """PagerDutyIncidentOutput - Dispatch Success, Good Policy"""
         # /users, /escalation_policies, /services
        type(get_mock.return_value).status_code = PropertyMock(side_effect=[200, 200, 200])
        json_user = {'users': [{'id': 'user_id'}]}
        json_policy = {'escalation_policies': [{'id': 'policy_id'}]}
        json_service = {'services': [{'id': 'service_id'}]}
        get_mock.return_value.json.side_effect = [json_user, json_policy, json_service]

        # /incidents
        post_mock.return_value.status_code = 200

        ctx = {'pagerduty-incident': {'assigned_policy': 'valid_policy'}}

        assert_true(self._dispatcher.dispatch(descriptor=self.DESCRIPTOR,
                                              rule_name='rule_name',
                                              alert=get_alert(context=ctx)))

        log_mock.assert_called_with('Successfully sent alert to %s', self.SERVICE)

    @patch('logging.Logger.info')
    @patch('requests.post')
    @patch('requests.get')
    def test_dispatch_success_with_priority(self, get_mock, post_mock, log_mock):
        """PagerDutyIncidentOutput - Dispatch Success With Priority"""
         # /priorities, /users, /escalation_policies, /services
        type(get_mock.return_value).status_code = PropertyMock(side_effect=[200, 200, 200, 200])
        json_user = {'users': [{'id': 'user_id'}]}
        json_priority = {'priorities': [{'id': 'priority_id', 'name': 'priority_name'}]}
        json_policy = {'escalation_policies': [{'id': 'policy_id'}]}
        json_service = {'services': [{'id': 'service_id'}]}
        get_mock.return_value.json.side_effect = [json_user, json_priority,
                                                  json_policy, json_service]

        # /incidents
        post_mock.return_value.status_code = 200

        ctx = {
            'pagerduty-incident': {
                'assigned_policy': 'valid_policy',
                'incident_priority': 'priority_name'
            }
        }

        assert_true(self._dispatcher.dispatch(descriptor=self.DESCRIPTOR,
                                              rule_name='rule_name',
                                              alert=get_alert(context=ctx)))

        log_mock.assert_called_with('Successfully sent alert to %s', self.SERVICE)

    @patch('logging.Logger.info')
    @patch('requests.post')
    @patch('requests.get')
    def test_dispatch_success_bad_user(self, get_mock, post_mock, log_mock):
        """PagerDutyIncidentOutput - Dispatch Success, Bad User"""
        # /users, /users, /escalation_policies, /services
        type(get_mock.return_value).status_code = PropertyMock(side_effect=[200, 200, 200, 200])
        json_user = {'users': [{'id': 'user_id'}]}
        json_not_user = {'not_users': [{'id': 'user_id'}]}
        json_policy = {'escalation_policies': [{'id': 'policy_id'}]}
        json_service = {'services': [{'id': 'service_id'}]}
        get_mock.return_value.json.side_effect = [json_user, json_not_user,
                                                  json_policy, json_service]

        # /incidents
        post_mock.return_value.status_code = 200

        ctx = {'pagerduty-incident': {'assigned_user': 'invalid_user'}}

        assert_true(self._dispatcher.dispatch(descriptor=self.DESCRIPTOR,
                                              rule_name='rule_name',
                                              alert=get_alert(context=ctx)))

        log_mock.assert_called_with('Successfully sent alert to %s', self.SERVICE)

    @patch('logging.Logger.info')
    @patch('requests.post')
    @patch('requests.get')
    def test_dispatch_success_no_context(self, get_mock, post_mock, log_mock):
        """PagerDutyIncidentOutput - Dispatch Success, No Context"""
        # /users, /escalation_policies, /services
        type(get_mock.return_value).status_code = PropertyMock(side_effect=[200, 200, 200])
        json_user = {'users': [{'id': 'user_id'}]}
        json_policy = {'escalation_policies': [{'id': 'policy_id'}]}
        json_service = {'services': [{'id': 'service_id'}]}
        get_mock.return_value.json.side_effect = [json_user, json_policy, json_service]

        # /incidents
        post_mock.return_value.status_code = 200

        assert_true(self._dispatcher.dispatch(descriptor=self.DESCRIPTOR,
                                              rule_name='rule_name',
                                              alert=get_alert()))

        log_mock.assert_called_with('Successfully sent alert to %s', self.SERVICE)

    @patch('requests.post')
    @patch('requests.get')
    def test_dispatch_failure_bad_everything(self, get_mock, post_mock):
        """PagerDutyIncidentOutput - Dispatch Failure: No User, Bad Policy, Bad Service"""
        # /users, /users, /escalation_policies, /services
        type(get_mock.return_value).status_code = PropertyMock(side_effect=[200, 400, 400, 400])
        json_user = {'users': [{'id': 'user_id'}]}
        get_mock.return_value.json.side_effect = [json_user, dict(), dict(), dict()]

        # /incidents
        post_mock.return_value.status_code = 400

        assert_raises(OutputRequestFailure, self._dispatcher.dispatch,
                      descriptor=self.DESCRIPTOR,
                      rule_name='rule_name',
                      alert=get_alert())

    @patch('logging.Logger.info')
    @patch('requests.post')
    @patch('requests.get')
    def test_dispatch_success_bad_policy(self, get_mock, post_mock, log_mock):
        """PagerDutyIncidentOutput - Dispatch Success, Bad Policy"""
        # /users, /escalation_policies, /escalation_policies, /services
        type(get_mock.return_value).status_code = PropertyMock(side_effect=[200, 400, 200, 200])
        json_user = {'users': [{'id': 'user_id'}]}
        json_bad_policy = dict()
        json_good_policy = {'escalation_policies': [{'id': 'policy_id'}]}
        json_service = {'services': [{'id': 'service_id'}]}
        get_mock.return_value.json.side_effect = [json_user, json_bad_policy,
                                                  json_good_policy, json_service]

        # /incidents
        post_mock.return_value.status_code = 200

        ctx = {'pagerduty-incident': {'assigned_policy': 'valid_policy'}}

        assert_true(self._dispatcher.dispatch(descriptor=self.DESCRIPTOR,
                                              rule_name='rule_name',
                                              alert=get_alert(context=ctx)))

        log_mock.assert_called_with('Successfully sent alert to %s', self.SERVICE)

    @patch('requests.post')
    @patch('requests.get')
    def test_dispatch_bad_dispatch(self, get_mock, post_mock):
        """PagerDutyIncidentOutput - Dispatch Failure, Bad Request"""
        # /users, /escalation_policies, /services
        type(get_mock.return_value).status_code = PropertyMock(side_effect=[200, 200, 200])
        json_user = {'users': [{'id': 'user_id'}]}
        json_policy = {'escalation_policies': [{'id': 'policy_id'}]}
        json_service = {'services': [{'id': 'service_id'}]}
        get_mock.return_value.json.side_effect = [json_user, json_policy, json_service]

        # /incidents
        post_mock.return_value.status_code = 400

        assert_raises(OutputRequestFailure, self._dispatcher.dispatch,
                      descriptor=self.DESCRIPTOR,
                      rule_name='rule_name',
                      alert=get_alert())


    @patch('logging.Logger.error')
    @patch('requests.get')
    def test_dispatch_bad_email(self, get_mock, log_mock):
        """PagerDutyIncidentOutput - Dispatch Failure, Bad Email"""
        # /users, /escalation_policies, /services
        get_mock.return_value.status_code = 400
        json_user = {'not_users': [{'id': 'no_user_id'}]}
        get_mock.return_value.json.return_value = json_user

        assert_false(self._dispatcher.dispatch(descriptor=self.DESCRIPTOR,
                                               rule_name='rule_name',
                                               alert=get_alert()))

        log_mock.assert_called_with('Failed to send alert to %s', self.SERVICE)

    @patch('logging.Logger.error')
    def test_dispatch_bad_descriptor(self, log_mock):
        """PagerDutyIncidentOutput - Dispatch Failure, Bad Descriptor"""
        assert_false(self._dispatcher.dispatch(descriptor='bad_descriptor',
                                               rule_name='rule_name',
                                               alert=get_alert()))

        log_mock.assert_called_with('Failed to send alert to %s', self.SERVICE)

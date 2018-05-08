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
from nose.tools import assert_equal, assert_false, assert_true

from stream_alert.alert_processor.outputs.pagerduty import (
    PagerDutyOutput,
    PagerDutyOutputV2,
    PagerDutyIncidentOutput
)
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
class TestPagerDutyOutput(object):
    """Test class for PagerDutyOutput"""
    DESCRIPTOR = 'unit_test_pagerduty'
    SERVICE = 'pagerduty'
    OUTPUT = ':'.join([SERVICE, DESCRIPTOR])
    CREDS = {'url': 'http://pagerduty.foo.bar/create_event.json',
             'service_key': 'mocked_service_key'}

    def setup(self):
        """Setup before each method"""
        self._dispatcher = PagerDutyOutput(REGION, ACCOUNT_ID, FUNCTION_NAME, None)
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

        assert_true(self._dispatcher.dispatch(get_alert(), self.OUTPUT))

        log_mock.assert_called_with('Successfully sent alert to %s:%s',
                                    self.SERVICE, self.DESCRIPTOR)

    @patch('logging.Logger.error')
    @patch('requests.post')
    def test_dispatch_failure(self, post_mock, log_mock):
        """PagerDutyOutput - Dispatch Failure, Bad Request"""
        post_mock.return_value.status_code = 400

        assert_false(self._dispatcher.dispatch(get_alert(), self.OUTPUT))

        log_mock.assert_called_with('Failed to send alert to %s:%s', self.SERVICE, self.DESCRIPTOR)

    @patch('logging.Logger.error')
    def test_dispatch_bad_descriptor(self, log_mock):
        """PagerDutyOutput - Dispatch Failure, Bad Descriptor"""
        assert_false(
            self._dispatcher.dispatch(get_alert(), ':'.join([self.SERVICE, 'bad_descriptor'])))

        log_mock.assert_called_with('Failed to send alert to %s:%s', self.SERVICE, 'bad_descriptor')

@mock_s3
@mock_kms
@patch('stream_alert.alert_processor.outputs.output_base.OutputDispatcher.MAX_RETRY_ATTEMPTS', 1)
class TestPagerDutyOutputV2(object):
    """Test class for PagerDutyOutputV2"""
    DESCRIPTOR = 'unit_test_pagerduty-v2'
    SERVICE = 'pagerduty-v2'
    OUTPUT = ':'.join([SERVICE, DESCRIPTOR])
    CREDS = {'url': 'http://pagerduty.foo.bar/create_event.json',
             'routing_key': 'mocked_routing_key'}

    def setup(self):
        """Setup before each method"""
        self._dispatcher = PagerDutyOutputV2(REGION, ACCOUNT_ID, FUNCTION_NAME, None)
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

        assert_true(self._dispatcher.dispatch(get_alert(), self.OUTPUT))

        log_mock.assert_called_with('Successfully sent alert to %s:%s',
                                    self.SERVICE, self.DESCRIPTOR)

    @patch('logging.Logger.error')
    @patch('requests.post')
    def test_dispatch_failure(self, post_mock, log_mock):
        """PagerDutyOutputV2 - Dispatch Failure, Bad Request"""
        json_error = {'message': 'error message', 'errors': ['error1']}
        post_mock.return_value.json.return_value = json_error
        post_mock.return_value.status_code = 400

        assert_false(self._dispatcher.dispatch(get_alert(), self.OUTPUT))

        log_mock.assert_called_with('Failed to send alert to %s:%s', self.SERVICE, self.DESCRIPTOR)

    @patch('logging.Logger.error')
    def test_dispatch_bad_descriptor(self, log_mock):
        """PagerDutyOutputV2 - Dispatch Failure, Bad Descriptor"""
        assert_false(
            self._dispatcher.dispatch(get_alert(), ':'.join([self.SERVICE, 'bad_descriptor'])))

        log_mock.assert_called_with('Failed to send alert to %s:%s', self.SERVICE, 'bad_descriptor')


#pylint: disable=too-many-public-methods
@mock_s3
@mock_kms
@patch('stream_alert.alert_processor.outputs.output_base.OutputDispatcher.MAX_RETRY_ATTEMPTS', 1)
@patch('stream_alert.alert_processor.outputs.pagerduty.PagerDutyIncidentOutput.BACKOFF_MAX', 0)
@patch('stream_alert.alert_processor.outputs.pagerduty.PagerDutyIncidentOutput.BACKOFF_TIME', 0)
class TestPagerDutyIncidentOutput(object):
    """Test class for PagerDutyIncidentOutput"""
    DESCRIPTOR = 'unit_test_pagerduty-incident'
    SERVICE = 'pagerduty-incident'
    OUTPUT = ':'.join([SERVICE, DESCRIPTOR])
    CREDS = {'api': 'https://api.pagerduty.com',
             'token': 'mocked_token',
             'service_name': 'mocked_service_name',
             'service_id': 'mocked_service_id',
             'escalation_policy': 'mocked_escalation_policy',
             'escalation_policy_id': 'mocked_escalation_policy_id',
             'email_from': 'email@domain.com',
             'integration_key': 'mocked_key'}

    def setup(self):
        """Setup before each method"""
        self._dispatcher = PagerDutyIncidentOutput(REGION, ACCOUNT_ID, FUNCTION_NAME, None)
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
        # GET /check
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
        """PagerDutyIncidentOutput - Check Exists No Get Id"""
        # GET /check
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
        # GET /escalation_policies
        get_mock.return_value.status_code = 200
        json_check = {'escalation_policies': [{'id': 'good_policy_id'}]}
        get_mock.return_value.json.return_value = json_check

        policy_verified = self._dispatcher._policy_verify('valid_policy', '')
        assert_equal(policy_verified['id'], 'good_policy_id')
        assert_equal(policy_verified['type'], 'escalation_policy_reference')

    @patch('requests.get')
    def test_policy_verify_success_default(self, get_mock):
        """PagerDutyIncidentOutput - Policy Verify Success (Default)"""
        # GET /escalation_policies
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
        # GET /not_escalation_policies
        type(get_mock.return_value).status_code = PropertyMock(side_effect=[400, 400])
        json_check_bad = {'escalation_policies': [{'id': 'bad_policy_id'}]}
        json_check_bad_default = {'escalation_policies': [{'id': 'good_policy_id'}]}
        get_mock.return_value.json.side_effect = [json_check_bad, json_check_bad_default]

        assert_false(self._dispatcher._policy_verify('valid_policy', 'default_policy'))

    @patch('requests.get')
    def test_policy_verify_fail_no_default(self, get_mock):
        """PagerDutyIncidentOutput - Policy Verify Fail (No Default)"""
        # GET /not_escalation_policies
        get_mock.return_value.status_code = 200
        json_check = {'not_escalation_policies': [{'not_id': 'verified_policy_id'}]}
        get_mock.return_value.json.return_value = json_check

        assert_false(self._dispatcher._policy_verify('valid_policy', 'default_policy'))

    @patch('requests.get')
    def test_service_verify_success(self, get_mock):
        """PagerDutyIncidentOutput - Service Verify Success"""
        # GET /services
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
        # GET /items
        get_mock.return_value.status_code = 200
        json_check = {'items': [{'id': 'verified_item_id'}]}
        get_mock.return_value.json.return_value = json_check

        item_verified = self._dispatcher._item_verify('valid_item', 'items', 'item_reference')

        assert_equal(item_verified['id'], 'verified_item_id')
        assert_equal(item_verified['type'], 'item_reference')

    @patch('requests.get')
    def test_item_verify_no_get_id_success(self, get_mock):
        """PagerDutyIncidentOutput - Item Verify No Get Id Success"""
        # GET /items
        get_mock.return_value.status_code = 200
        json_check = {'items': [{'id': 'verified_item_id'}]}
        get_mock.return_value.json.return_value = json_check

        assert_true(self._dispatcher._item_verify('valid_item', 'items', 'item_reference', False))

    @patch('requests.get')
    def test_priority_verify_success(self, get_mock):
        """PagerDutyIncidentOutput - Priority Verify Success"""
        priority_name = 'priority_name'
        # GET /priorities
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
        # GET /priorities
        get_mock.return_value.status_code = 404

        context = {'incident_priority': 'priority_name'}

        priority_not_verified = self._dispatcher._priority_verify(context)
        assert_equal(priority_not_verified, dict())

    @patch('requests.get')
    def test_priority_verify_empty(self, get_mock):
        """PagerDutyIncidentOutput - Priority Verify Empty"""
        # GET /priorities
        get_mock.return_value.status_code = 200
        json_check = {}
        get_mock.return_value.json.return_value = json_check

        context = {'incident_priority': 'priority_name'}

        priority_not_verified = self._dispatcher._priority_verify(context)
        assert_equal(priority_not_verified, dict())

    @patch('requests.get')
    def test_priority_verify_not_found(self, get_mock):
        """PagerDutyIncidentOutput - Priority Verify Not Found"""
        # GET /priorities
        get_mock.return_value.status_code = 200
        json_check = {'priorities': [{'id': 'verified_priority_id', 'name': 'not_priority_name'}]}
        get_mock.return_value.json.return_value = json_check

        context = {'incident_priority': 'priority_name'}

        priority_not_verified = self._dispatcher._priority_verify(context)
        assert_equal(priority_not_verified, dict())

    @patch('requests.get')
    def test_priority_verify_invalid(self, get_mock):
        """PagerDutyIncidentOutput - Priority Verify Invalid"""
        # GET /priorities
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

    def test_incident_assignment_policy_no_default(self):
        """PagerDutyIncidentOutput - Incident Assignment Policy (No Default)"""
        context = {'assigned_policy_id': 'policy_id_to_assign'}

        assigned_key, assigned_value = self._dispatcher._incident_assignment(context)

        assert_equal(assigned_key, 'escalation_policy')
        assert_equal(assigned_value['id'], 'policy_id_to_assign')
        assert_equal(assigned_value['type'], 'escalation_policy_reference')

    @patch('requests.post')
    def test_add_note_incident_success(self, post_mock):
        """PagerDutyIncidentOutput - Add Note to Incident Success"""
        post_mock.return_value.status_code = 200
        json_note = {'note': {'id': 'created_note_id'}}
        post_mock.return_value.json.return_value = json_note

        note_id = self._dispatcher._add_incident_note('incident_id', 'this is the note')

        assert_equal(note_id, 'created_note_id')

    @patch('requests.post')
    def test_add_note_incident_fail(self, post_mock):
        """PagerDutyIncidentOutput - Add Note to Incident Fail"""
        post_mock.return_value.status_code = 200
        json_note = {'note': {'not_id': 'created_note_id'}}
        post_mock.return_value.json.return_value = json_note

        note_id = self._dispatcher._add_incident_note('incident_id', 'this is the note')

        assert_false(note_id)

    @patch('requests.post')
    def test_add_note_incident_bad_request(self, post_mock):
        """PagerDutyIncidentOutput - Add Note to Incident Bad Request"""
        post_mock.return_value.status_code = 400
        json_note = {'note': {'id': 'created_note_id'}}
        post_mock.return_value.json.return_value = json_note

        note_id = self._dispatcher._add_incident_note('incident_id', 'this is the note')

        assert_false(note_id)

    @patch('requests.post')
    def test_add_note_incident_no_response(self, post_mock):
        """PagerDutyIncidentOutput - Add Note to Incident No Response"""
        post_mock.return_value.status_code = 200
        json_note = {}
        post_mock.return_value.json.return_value = json_note

        note_id = self._dispatcher._add_incident_note('incident_id', 'this is the note')

        assert_false(note_id)

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
    @patch('requests.put')
    @patch('requests.post')
    @patch('requests.get')
    def test_dispatch_success_good_user(self, get_mock, post_mock, put_mock, log_mock):
        """PagerDutyIncidentOutput - Dispatch Success, Good User"""
        # GET /users, /users
        json_user = {'users': [{'id': 'valid_user_id'}]}

        # GET /incidents
        json_lookup = {'incidents': [{'id': 'incident_id'}]}

        get_mock.return_value.status_code = 200
        get_mock.return_value.json.side_effect = [json_user, json_user, json_lookup]

        # POST /incidents, /v2/enqueue, /incidents/incident_id/notes
        post_mock.return_value.status_code = 200
        json_incident = {'incident': {'id': 'incident_id'}}
        json_event = {'dedup_key': 'returned_dedup_key'}
        json_note = {'note': {'id': 'note_id'}}
        post_mock.return_value.json.side_effect = [json_incident, json_event, json_note]

        # PUT /incidents/indicent_id/merge
        put_mock.return_value.status_code = 200

        ctx = {'pagerduty-incident': {'assigned_user': 'valid_user'}}

        assert_true(self._dispatcher.dispatch(get_alert(context=ctx), self.OUTPUT))

        log_mock.assert_called_with('Successfully sent alert to %s:%s',
                                    self.SERVICE, self.DESCRIPTOR)

    @patch('logging.Logger.info')
    @patch('requests.put')
    @patch('requests.post')
    @patch('requests.get')
    def test_dispatch_success_good_policy(self, get_mock, post_mock, put_mock, log_mock):
        """PagerDutyIncidentOutput - Dispatch Success, Good Policy"""
         # GET /users
        json_user = {'users': [{'id': 'user_id'}]}

        # GET /incidents
        json_lookup = {'incidents': [{'id': 'incident_id'}]}

        get_mock.return_value.status_code = 200
        get_mock.return_value.json.side_effect = [json_user, json_lookup]

        # POST /incidents, /v2/enqueue, /incidents/incident_id/notes
        post_mock.return_value.status_code = 200
        json_incident = {'incident': {'id': 'incident_id'}}
        json_event = {'dedup_key': 'returned_dedup_key'}
        json_note = {'note': {'id': 'note_id'}}
        post_mock.return_value.json.side_effect = [json_incident, json_event, json_note]

        # PUT /incidents/indicent_id/merge
        put_mock.return_value.status_code = 200

        ctx = {'pagerduty-incident': {'assigned_policy_id': 'valid_policy_id'}}

        assert_true(self._dispatcher.dispatch(get_alert(context=ctx), self.OUTPUT))

        log_mock.assert_called_with('Successfully sent alert to %s:%s',
                                    self.SERVICE, self.DESCRIPTOR)

    @patch('logging.Logger.info')
    @patch('requests.put')
    @patch('requests.post')
    @patch('requests.get')
    def test_dispatch_success_with_priority(self, get_mock, post_mock, put_mock, log_mock):
        """PagerDutyIncidentOutput - Dispatch Success With Priority"""
         # GET /priorities, /users
        json_user = {'users': [{'id': 'user_id'}]}
        json_priority = {'priorities': [{'id': 'priority_id', 'name': 'priority_name'}]}

        # GET /incidents
        json_lookup = {'incidents': [{'id': 'incident_id'}]}
        get_mock.return_value.status_code = 200
        get_mock.return_value.json.side_effect = [json_user, json_priority, json_lookup]

        # POST /incidents, /v2/enqueue, /incidents/incident_id/notes
        post_mock.return_value.status_code = 200
        json_incident = {'incident': {'id': 'incident_id'}}
        json_event = {'dedup_key': 'returned_dedup_key'}
        json_note = {'note': {'id': 'note_id'}}
        post_mock.return_value.json.side_effect = [json_incident, json_event, json_note]

        # PUT /incidents/indicent_id/merge
        put_mock.return_value.status_code = 200

        ctx = {
            'pagerduty-incident': {
                'assigned_policy_id': 'valid_policy_id',
                'incident_priority': 'priority_name'
            }
        }

        assert_true(self._dispatcher.dispatch(get_alert(context=ctx), self.OUTPUT))

        log_mock.assert_called_with('Successfully sent alert to %s:%s',
                                    self.SERVICE, self.DESCRIPTOR)

    @patch('logging.Logger.info')
    @patch('requests.put')
    @patch('requests.post')
    @patch('requests.get')
    def test_dispatch_success_bad_user(self, get_mock, post_mock, put_mock, log_mock):
        """PagerDutyIncidentOutput - Dispatch Success, Bad User"""
        # GET /users, /users
        json_user = {'users': [{'id': 'user_id'}]}
        json_not_user = {'not_users': [{'id': 'user_id'}]}

        # GET /incidents
        json_lookup = {'incidents': [{'id': 'incident_id'}]}

        get_mock.return_value.status_code = 200
        get_mock.return_value.json.side_effect = [json_user, json_not_user, json_lookup]

        # POST /incidents, /v2/enqueue, /incidents/incident_id/notes
        post_mock.return_value.status_code = 200
        json_incident = {'incident': {'id': 'incident_id'}}
        json_event = {'dedup_key': 'returned_dedup_key'}
        json_note = {'note': {'id': 'note_id'}}
        post_mock.return_value.json.side_effect = [json_incident, json_event, json_note]

        # PUT /incidents/indicent_id/merge
        put_mock.return_value.status_code = 200

        ctx = {'pagerduty-incident': {'assigned_user': 'invalid_user'}}

        assert_true(self._dispatcher.dispatch(get_alert(context=ctx), self.OUTPUT))

        log_mock.assert_called_with('Successfully sent alert to %s:%s',
                                    self.SERVICE, self.DESCRIPTOR)

    @patch('logging.Logger.info')
    @patch('requests.put')
    @patch('requests.post')
    @patch('requests.get')
    def test_dispatch_success_no_context(self, get_mock, post_mock, put_mock, log_mock):
        """PagerDutyIncidentOutput - Dispatch Success, No Context"""
        # GET /users
        json_user = {'users': [{'id': 'user_id'}]}

        # GET /incidents
        json_lookup = {'incidents': [{'id': 'incident_id'}]}

        get_mock.return_value.status_code = 200
        get_mock.return_value.json.side_effect = [json_user, json_lookup]

        # POST /incidents, /v2/enqueue, /incidents/incident_id/notes
        post_mock.return_value.status_code = 200
        json_incident = {'incident': {'id': 'incident_id'}}
        json_event = {'dedup_key': 'returned_dedup_key'}
        json_note = {'note': {'id': 'note_id'}}
        post_mock.return_value.json.side_effect = [json_incident, json_event, json_note]

        # PUT /incidents/indicent_id/merge
        put_mock.return_value.status_code = 200

        assert_true(self._dispatcher.dispatch(get_alert(), self.OUTPUT))

        log_mock.assert_called_with('Successfully sent alert to %s:%s',
                                    self.SERVICE, self.DESCRIPTOR)

    @patch('logging.Logger.error')
    @patch('requests.post')
    @patch('requests.get')
    def test_dispatch_failure_bad_everything(self, get_mock, post_mock, log_mock):
        """PagerDutyIncidentOutput - Dispatch Failure: No User"""
        # GET /users, /users
        type(get_mock.return_value).status_code = PropertyMock(side_effect=[200, 400])

        # Only set the return_value here since there will only be one successful call
        # that makes it to the point of calling the .json() method
        get_mock.return_value.json.return_value = {'users': [{'id': 'user_id'}]}

        # POST /incidents
        post_mock.return_value.status_code = 400

        assert_false(self._dispatcher.dispatch(get_alert(), self.OUTPUT))

        log_mock.assert_called_with('Failed to send alert to %s:%s', self.SERVICE, self.DESCRIPTOR)

    @patch('logging.Logger.info')
    @patch('requests.put')
    @patch('requests.post')
    @patch('requests.get')
    def test_dispatch_success_no_merge_response(self, get_mock, post_mock, put_mock, log_mock):
        """PagerDutyIncidentOutput - Dispatch Success, No Merge Response"""
        # GET /users
        get_mock.return_value.status_code = 200
        json_user = {'users': [{'id': 'user_id'}]}
        json_lookup = {'incidents': [{'id': 'existing_incident_id'}]}
        get_mock.return_value.json.side_effect = [json_user, json_lookup]

        # POST /incidents, /v2/enqueue
        post_mock.return_value.status_code = 200
        json_incident = {'incident': {'id': 'incident_id'}}
        json_event = {'dedup_key': 'returned_dedup_key'}
        post_mock.return_value.json.side_effect = [json_incident, json_event]

        # PUT /incidents/indicent_id/merge
        put_mock.return_value.status_code = 200
        put_mock.return_value.json.return_value = {}

        ctx = {'pagerduty-incident': {'assigned_policy_id': 'valid_policy_id'}}

        assert_true(self._dispatcher.dispatch(get_alert(context=ctx), self.OUTPUT))

        log_mock.assert_called_with('Successfully sent alert to %s:%s',
                                    self.SERVICE, self.DESCRIPTOR)

    @patch('logging.Logger.error')
    @patch('requests.post')
    @patch('requests.get')
    def test_dispatch_no_dispatch_no_incident_response(self, get_mock, post_mock, log_mock):
        """PagerDutyIncidentOutput - Dispatch Failure, No Incident Response"""
        # /users
        get_mock.return_value.status_code = 200
        json_user = {'users': [{'id': 'user_id'}]}
        get_mock.return_value.json.return_value = json_user

        # /incidents
        post_mock.return_value.status_code = 200
        post_mock.return_value.json.return_value = {}

        assert_false(self._dispatcher.dispatch(get_alert(), self.OUTPUT))

        log_mock.assert_called_with('Failed to send alert to %s:%s', self.SERVICE, self.DESCRIPTOR)

    @patch('logging.Logger.error')
    @patch('requests.post')
    @patch('requests.get')
    def test_dispatch_no_dispatch_no_incident_event(self, get_mock, post_mock, log_mock):
        """PagerDutyIncidentOutput - Dispatch Failure, No Incident Event"""
        # /users
        get_mock.return_value.status_code = 200
        json_user = {'users': [{'id': 'user_id'}]}
        get_mock.return_value.json.return_value = json_user

        # /incidents, /v2/enqueue
        post_mock.return_value.status_code = 200
        json_incident = {'incident': {'id': 'incident_id'}}
        json_event = {}
        post_mock.return_value.json.side_effect = [json_incident, json_event]

        assert_false(self._dispatcher.dispatch(get_alert(), self.OUTPUT))

        log_mock.assert_called_with('Failed to send alert to %s:%s', self.SERVICE, self.DESCRIPTOR)

    @patch('logging.Logger.error')
    @patch('requests.post')
    @patch('requests.get')
    def test_dispatch_no_dispatch_no_incident_key(self, get_mock, post_mock, log_mock):
        """PagerDutyIncidentOutput - Dispatch Failure, No Incident Key"""
        # /users
        get_mock.return_value.status_code = 200
        json_user = {'users': [{'id': 'user_id'}]}
        get_mock.return_value.json.return_value = json_user

        # /incidents, /v2/enqueue
        post_mock.return_value.status_code = 200
        json_incident = {'incident': {'id': 'incident_id'}}
        json_event = {'not_dedup_key': 'returned_dedup_key'}
        post_mock.return_value.json.side_effect = [json_incident, json_event]

        assert_false(self._dispatcher.dispatch(get_alert(), self.OUTPUT))

        log_mock.assert_called_with('Failed to send alert to %s:%s', self.SERVICE, self.DESCRIPTOR)

    @patch('logging.Logger.error')
    @patch('requests.post')
    @patch('requests.get')
    def test_dispatch_bad_dispatch(self, get_mock, post_mock, log_mock):
        """PagerDutyIncidentOutput - Dispatch Failure, Bad Request"""
        # /users
        get_mock.return_value.status_code = 200
        json_user = {'users': [{'id': 'user_id'}]}
        get_mock.return_value.json.return_value = json_user

        # /incidents
        post_mock.return_value.status_code = 400

        assert_false(self._dispatcher.dispatch(get_alert(), self.OUTPUT))

        log_mock.assert_called_with('Failed to send alert to %s:%s', self.SERVICE, self.DESCRIPTOR)


    @patch('logging.Logger.error')
    @patch('requests.get')
    def test_dispatch_bad_email(self, get_mock, log_mock):
        """PagerDutyIncidentOutput - Dispatch Failure, Bad Email"""
        # /users
        get_mock.return_value.status_code = 400
        json_user = {'not_users': [{'id': 'no_user_id'}]}
        get_mock.return_value.json.return_value = json_user

        assert_false(self._dispatcher.dispatch(get_alert(), self.OUTPUT))

        log_mock.assert_called_with('Failed to send alert to %s:%s', self.SERVICE, self.DESCRIPTOR)

    @patch('logging.Logger.error')
    def test_dispatch_bad_descriptor(self, log_mock):
        """PagerDutyIncidentOutput - Dispatch Failure, Bad Descriptor"""
        assert_false(
            self._dispatcher.dispatch(get_alert(), ':'.join([self.SERVICE, 'bad_descriptor'])))

        log_mock.assert_called_with('Failed to send alert to %s:%s', self.SERVICE, 'bad_descriptor')

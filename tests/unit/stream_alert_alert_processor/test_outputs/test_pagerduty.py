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
# pylint: disable=protected-access,attribute-defined-outside-init,too-many-lines,invalid-name
from collections import OrderedDict
from mock import patch, PropertyMock, Mock, MagicMock, call
from nose.tools import assert_equal, assert_false, assert_true

from stream_alert.alert_processor.outputs.output_base import OutputDispatcher, OutputRequestFailure
from stream_alert.alert_processor.outputs.pagerduty import (
    PagerDutyOutput,
    PagerDutyOutputV2,
    PagerDutyIncidentOutput,
    WorkContext, PagerDutyRestApiClient, JsonHttpProvider)
from tests.unit.stream_alert_alert_processor.helpers import get_alert


@patch('stream_alert.alert_processor.outputs.output_base.OutputDispatcher.MAX_RETRY_ATTEMPTS', 1)
class TestPagerDutyOutput(object):
    """Test class for PagerDutyOutput"""
    DESCRIPTOR = 'unit_test_pagerduty'
    SERVICE = 'pagerduty'
    OUTPUT = ':'.join([SERVICE, DESCRIPTOR])
    CREDS = {'url': 'http://pagerduty.foo.bar/create_event.json',
             'service_key': 'mocked_service_key'}

    @patch('stream_alert.alert_processor.outputs.output_base.OutputCredentialsProvider')
    def setup(self, provider_constructor):
        """Setup before each method"""
        provider = MagicMock()
        provider_constructor.return_value = provider
        provider.load_credentials = Mock(
            side_effect=lambda x: self.CREDS if x == self.DESCRIPTOR else None
        )
        self._provider = provider
        self._dispatcher = PagerDutyOutput(None)

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

        post_mock.assert_called_with(
            'http://pagerduty.foo.bar/create_event.json',
            headers=None,
            json={
                'client_url': '',
                'event_type': 'trigger',
                'contexts': [],
                'client': 'streamalert',
                'details': {
                    'record': {
                        'compressed_size': '9982',
                        'node_id': '1',
                        'cb_server': 'cbserver',
                        'timestamp': '1496947381.18',
                        'md5': '0F9AA55DA3BDE84B35656AD8911A22E1',
                        'type': 'binarystore.file.added',
                        'file_path': '/tmp/5DA/AD8/0F9AA55DA3BDE84B35656AD8911A22E1.zip',
                        'size': '21504'
                    },
                    'description': 'Info about this rule and what actions to take'
                },
                'service_key': 'mocked_service_key',
                'description': 'StreamAlert Rule Triggered - cb_binarystore_file_added'
            },
            timeout=3.05,
            verify=True
        )

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


@patch('stream_alert.alert_processor.outputs.output_base.OutputDispatcher.MAX_RETRY_ATTEMPTS', 1)
class TestPagerDutyOutputV2(object):
    """Test class for PagerDutyOutputV2"""
    DESCRIPTOR = 'unit_test_pagerduty-v2'
    SERVICE = 'pagerduty-v2'
    OUTPUT = ':'.join([SERVICE, DESCRIPTOR])
    CREDS = {'url': 'http://pagerduty.foo.bar/create_event.json',
             'routing_key': 'mocked_routing_key'}

    @patch('stream_alert.alert_processor.outputs.output_base.OutputCredentialsProvider')
    def setup(self, provider_constructor):
        """Setup before each method"""
        provider = MagicMock()
        provider_constructor.return_value = provider
        provider.load_credentials = Mock(
            side_effect=lambda x: self.CREDS if x == self.DESCRIPTOR else None
        )
        self._provider = provider
        self._dispatcher = PagerDutyOutputV2(None)

    def test_get_default_properties(self):
        """PagerDutyOutputV2 - Get Default Properties"""
        props = self._dispatcher._get_default_properties()
        assert_equal(len(props), 1)
        assert_equal(props['url'], 'https://events.pagerduty.com/v2/enqueue')

    @patch('requests.post')
    def test_dispatch_sends_correct_request(self, post_mock):
        """PagerDutyOutputV2 - Dispatch Sends Correct Request"""
        post_mock.return_value.status_code = 200

        self._dispatcher.dispatch(get_alert(), self.OUTPUT)

        post_mock.assert_called_with(
            'http://pagerduty.foo.bar/create_event.json',
            headers=None,
            json={
                'event_action': 'trigger',
                'client': 'StreamAlert',
                'client_url': None,
                'payload': {
                    'custom_details': OrderedDict(
                        [
                            ('description', 'Info about this rule and what actions to take'),
                            ('record', {
                                'compressed_size': '9982', 'node_id': '1', 'cb_server': 'cbserver',
                                'timestamp': '1496947381.18',
                                'md5': '0F9AA55DA3BDE84B35656AD8911A22E1',
                                'type': 'binarystore.file.added',
                                'file_path': '/tmp/5DA/AD8/0F9AA55DA3BDE84B35656AD8911A22E1.zip',
                                'size': '21504'
                            })
                        ]
                    ),
                    'source': 'carbonblack:binarystore.file.added',
                    'severity': 'critical',
                    'summary': 'StreamAlert Rule Triggered - cb_binarystore_file_added',
                    'component': None,
                    'group': None,
                    'class': None,
                },
                'routing_key': 'mocked_routing_key',
                'images': [],
                'links': [],
            },
            timeout=3.05, verify=True
        )

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


# pylint: disable=too-many-public-methods
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

    @patch('stream_alert.alert_processor.outputs.output_base.OutputCredentialsProvider')
    def setup(self, provider_constructor):
        """Setup before each method"""
        provider = MagicMock()
        provider_constructor.return_value = provider
        provider.load_credentials = Mock(
            side_effect=lambda x: self.CREDS if x == self.DESCRIPTOR else None
        )
        self._provider = provider
        self._dispatcher = PagerDutyIncidentOutput(None)
        self._dispatcher._base_url = self.CREDS['api']

    def test_get_default_properties(self):
        """PagerDutyIncidentOutput - Get Default Properties"""
        props = self._dispatcher._get_default_properties()
        assert_equal(len(props), 1)
        assert_equal(props['api'], 'https://api.pagerduty.com')

    @patch('requests.put')
    @patch('requests.post')
    @patch('requests.get')
    def test_dispatch_sends_correct_create_request(self, get_mock, post_mock, put_mock):
        """PagerDutyIncidentOutput - Dispatch Success, Good User, Sends Correct Create Request"""
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

        self._dispatcher.dispatch(get_alert(context=ctx), self.OUTPUT)

        # Useful tidbit; for writing fixtures for implement multiple sequential calls, you can use
        # mock.assert_has_calls() to render out all of the calls in order:
        # post_mock.assert_has_calls([call()])
        post_mock.assert_any_call(
            'https://api.pagerduty.com/incidents',
            headers={
                'From': 'email@domain.com',
                'Content-Type': 'application/json',
                'Authorization': 'Token token=mocked_token',
                'Accept': 'application/vnd.pagerduty+json;version=2'
            },
            json={
                'incident': {
                    'body': {
                        'type': 'incident_body',
                        'details': 'Info about this rule and what actions to take'
                    },
                    'service': {
                        'type': 'service_reference',
                        'id': 'mocked_service_id'
                    },
                    'title': 'StreamAlert Incident - Rule triggered: cb_binarystore_file_added',
                    'priority': {},
                    'assignments': [
                        {
                            'assignee': {
                                'type': 'user_reference', 'id': 'valid_user_id'
                            }
                        }
                    ],
                    'type': 'incident',
                    'incident_key': '',
                }
            },
            timeout=3.05, verify=False
        )

    @patch('stream_alert.alert_processor.outputs.pagerduty.compose_alert')
    @patch('requests.put')
    @patch('requests.post')
    @patch('requests.get')
    def test_dispatch_sends_correct_with_urgency(self, get_mock, post_mock, put_mock,
                                                 compose_alert):
        """PagerDutyIncidentOutput - Dispatch Success, Good User, Sends Correct Urgency"""
        compose_alert.return_value = {
            '@pagerduty-incident.urgency': 'low'
        }

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

        self._dispatcher.dispatch(get_alert(context=ctx), self.OUTPUT)

        # Useful tidbit; for writing fixtures for implement multiple sequential calls, you can use
        # mock.assert_has_calls() to render out all of the calls in order:
        # post_mock.assert_has_calls([call()])
        post_mock.assert_any_call(
            'https://api.pagerduty.com/incidents',
            headers={
                'From': 'email@domain.com',
                'Content-Type': 'application/json',
                'Authorization': 'Token token=mocked_token',
                'Accept': 'application/vnd.pagerduty+json;version=2'
            },
            json={
                'incident': {
                    'body': {
                        'type': 'incident_body',
                        'details': 'Info about this rule and what actions to take'
                    },
                    'service': {
                        'type': 'service_reference',
                        'id': 'mocked_service_id'
                    },
                    'title': 'StreamAlert Incident - Rule triggered: cb_binarystore_file_added',
                    'priority': {},
                    'assignments': [
                        {
                            'assignee': {
                                'type': 'user_reference', 'id': 'valid_user_id'
                            }
                        }
                    ],
                    'urgency': 'low',
                    'type': 'incident',
                    'incident_key': '',
                }
            },
            timeout=3.05, verify=False
        )

    @patch('logging.Logger.warn')
    @patch('stream_alert.alert_processor.outputs.pagerduty.compose_alert')
    @patch('requests.put')
    @patch('requests.post')
    @patch('requests.get')
    def test_dispatch_sends_correct_bad_urgency(self, get_mock, post_mock, put_mock,
                                                compose_alert, log_mock):
        """PagerDutyIncidentOutput - Dispatch Success, Good User, Sends Correct Urgency"""
        compose_alert.return_value = {
            '@pagerduty-incident.urgency': 'asdf'
        }

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

        self._dispatcher.dispatch(get_alert(context=ctx), self.OUTPUT)

        # Useful tidbit; for writing fixtures for implement multiple sequential calls, you can use
        # mock.assert_has_calls() to render out all of the calls in order:
        # post_mock.assert_has_calls([call()])
        post_mock.assert_any_call(
            'https://api.pagerduty.com/incidents',
            headers={
                'From': 'email@domain.com',
                'Content-Type': 'application/json',
                'Authorization': 'Token token=mocked_token',
                'Accept': 'application/vnd.pagerduty+json;version=2'
            },
            json={
                'incident': {
                    'body': {
                        'type': 'incident_body',
                        'details': 'Info about this rule and what actions to take'
                    },
                    'service': {
                        'type': 'service_reference',
                        'id': 'mocked_service_id'
                    },
                    'title': 'StreamAlert Incident - Rule triggered: cb_binarystore_file_added',
                    'priority': {},
                    'assignments': [
                        {
                            'assignee': {
                                'type': 'user_reference', 'id': 'valid_user_id'
                            }
                        }
                    ],
                    'type': 'incident',
                    'incident_key': '',
                }
            },
            timeout=3.05, verify=False
        )
        log_mock.assert_called_with('[%s] Invalid pagerduty incident urgency: "%s"',
                                    'pagerduty-incident', 'asdf')

    @patch('requests.put')
    @patch('requests.post')
    @patch('requests.get')
    def test_dispatch_sends_correct_enqueue_event_request(self, get_mock, post_mock, put_mock):
        """PagerDutyIncidentOutput - Dispatch Success, Good User, Sends Correct Event Request"""
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

        self._dispatcher.dispatch(get_alert(context=ctx), self.OUTPUT)

        # post_mock.assert_has_calls([call()])
        post_mock.assert_any_call(
            'https://events.pagerduty.com/v2/enqueue',
            headers=None,
            json={
                'event_action': 'trigger',
                'client': 'StreamAlert',
                'client_url': None,
                'payload': {
                    'custom_details': OrderedDict(
                        [
                            ('description', 'Info about this rule and what actions to take'),
                            ('record', {
                                'compressed_size': '9982', 'node_id': '1', 'cb_server': 'cbserver',
                                'timestamp': '1496947381.18',
                                'md5': '0F9AA55DA3BDE84B35656AD8911A22E1',
                                'type': 'binarystore.file.added',
                                'file_path': '/tmp/5DA/AD8/0F9AA55DA3BDE84B35656AD8911A22E1.zip',
                                'size': '21504'
                            })
                        ]
                    ),
                    'source': 'carbonblack:binarystore.file.added',
                    'severity': 'critical',
                    'summary': 'StreamAlert Rule Triggered - cb_binarystore_file_added',
                    'component': None,
                    'group': None,
                    'class': None,
                },
                'routing_key': 'mocked_key',
                'images': [],
                'links': [],
            },
            timeout=3.05, verify=True
        )

    @patch('requests.put')
    @patch('requests.post')
    @patch('requests.get')
    def test_dispatch_sends_correct_merge_request(self, get_mock, post_mock, put_mock):
        """PagerDutyIncidentOutput - Dispatch Success, Good User, Sends Correct Merge Request"""
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

        self._dispatcher.dispatch(get_alert(context=ctx), self.OUTPUT)

        put_mock.assert_called_with(
            'https://api.pagerduty.com/incidents/incident_id/merge',
            headers={'From': 'email@domain.com', 'Content-Type': 'application/json',
                     'Authorization': 'Token token=mocked_token',
                     'Accept': 'application/vnd.pagerduty+json;version=2'},
            json={'source_incidents': [{'type': 'incident_reference', 'id': 'incident_id'}]},
            timeout=3.05,
            verify=False
        )

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

        # PUT /incidents/{incident_id}/merge
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
        json_lookup = {'incidents': [{'id': 'incident_id'}]}

        def setup_post_mock(mock, json_incident, json_event, json_note):
            def post(*args, **_):
                url = args[0]
                if url == 'https://api.pagerduty.com/incidents':
                    response = json_incident
                elif url == 'https://events.pagerduty.com/v2/enqueue':
                    response = json_event
                elif (
                        url.startswith('https://api.pagerduty.com/incidents/') and
                        url.endswith('/notes')
                ):
                    response = json_note
                else:
                    raise RuntimeError('Misconfigured mock: {}'.format(url))

                _mock = MagicMock()
                _mock.status_code = 200
                _mock.json.return_value = response
                return _mock

            mock.side_effect = post

        get_mock.return_value.status_code = 200
        get_mock.return_value.json.side_effect = [json_user, json_priority, json_lookup]

        # POST /incidents, /v2/enqueue, /incidents/{incident_id}/notes
        json_incident = {'incident': {'id': 'incident_id'}}
        json_event = {'dedup_key': 'returned_dedup_key'}
        json_note = {'note': {'id': 'note_id'}}
        # post_mock.return_value.status_code = 200
        # post_mock.return_value.json.side_effect = [json_incident, json_event, json_note]
        setup_post_mock(post_mock, json_incident, json_event, json_note)

        # PUT /incidents/{incident_id}/merge
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
    def test_dispatch_success_with_note(self, get_mock, post_mock, put_mock, log_mock):
        """PagerDutyIncidentOutput - Dispatch Success With Note"""
        # GET /priorities, /users
        json_user = {'users': [{'id': 'user_id'}]}
        json_lookup = {'incidents': [{'id': 'incident_id'}]}

        def setup_post_mock(mock, json_incident, json_event, json_note):
            def post(*args, **_):
                url = args[0]
                if url == 'https://api.pagerduty.com/incidents':
                    response = json_incident
                elif url == 'https://events.pagerduty.com/v2/enqueue':
                    response = json_event
                elif (
                        url.startswith('https://api.pagerduty.com/incidents/') and
                        url.endswith('/notes')
                ):
                    response = json_note
                else:
                    raise RuntimeError('Misconfigured mock: {}'.format(url))

                _mock = MagicMock()
                _mock.status_code = 200
                _mock.json.return_value = response
                return _mock

            mock.side_effect = post

        get_mock.return_value.status_code = 200
        get_mock.return_value.json.side_effect = [json_user, json_lookup]

        # POST /incidents, /v2/enqueue, /incidents/{incident_id}/notes
        json_incident = {'incident': {'id': 'incident_id'}}
        json_event = {'dedup_key': 'returned_dedup_key'}
        json_note = {'note': {'id': 'note_id'}}
        setup_post_mock(post_mock, json_incident, json_event, json_note)

        # PUT /incidents/{incident_id}/merge
        put_mock.return_value.status_code = 200

        ctx = {
            'pagerduty-incident': {
                'note': 'This is just a note'
            }
        }

        assert_true(self._dispatcher.dispatch(get_alert(context=ctx), self.OUTPUT))

        # post_mock.assert_has_calls([call()])
        post_mock.assert_any_call(
            'https://api.pagerduty.com/incidents/incident_id/notes',
            headers={'From': 'email@domain.com',
                     'Content-Type': 'application/json',
                     'Authorization': 'Token token=mocked_token',
                     'Accept': 'application/vnd.pagerduty+json;version=2'},
            json={'note': {'content': 'This is just a note'}},
            timeout=3.05, verify=False
        )

        log_mock.assert_called_with('Successfully sent alert to %s:%s',
                                    self.SERVICE, self.DESCRIPTOR)

    @patch('logging.Logger.info')
    @patch('requests.put')
    @patch('requests.post')
    @patch('requests.get')
    def test_dispatch_success_none_note(self, get_mock, post_mock, put_mock, log_mock):
        """PagerDutyIncidentOutput - Dispatch Success With No Note"""
        # GET /priorities, /users
        json_user = {'users': [{'id': 'user_id'}]}
        json_lookup = {'incidents': [{'id': 'incident_id'}]}

        def setup_post_mock(mock, json_incident, json_event):
            def post(*args, **_):
                url = args[0]
                if url == 'https://api.pagerduty.com/incidents':
                    response = json_incident
                elif url == 'https://events.pagerduty.com/v2/enqueue':
                    response = json_event
                elif (
                        url.startswith('https://api.pagerduty.com/incidents/') and
                        url.endswith('/notes')
                ):
                    # assert the /notes endpoint is never called
                    raise RuntimeError('This endpoint is not intended to be called')
                else:
                    raise RuntimeError('Misconfigured mock: {}'.format(url))

                _mock = MagicMock()
                _mock.status_code = 200
                _mock.json.return_value = response
                return _mock

            mock.side_effect = post

        get_mock.return_value.status_code = 200
        get_mock.return_value.json.side_effect = [json_user, json_lookup]

        # POST /incidents, /v2/enqueue, /incidents/{incident_id}/notes
        json_incident = {'incident': {'id': 'incident_id'}}
        json_event = {'dedup_key': 'returned_dedup_key'}
        setup_post_mock(post_mock, json_incident, json_event)

        # PUT /incidents/{incident_id}/merge
        put_mock.return_value.status_code = 200

        ctx = {
            'pagerduty-incident': {
                'note': None
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
        json_note = {'note': {'aa'}}
        post_mock.return_value.json.side_effect = [json_incident, json_event, json_note]

        # PUT /incidents/{incident_id}/merge
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


@patch('stream_alert.alert_processor.outputs.output_base.OutputDispatcher.MAX_RETRY_ATTEMPTS', 1)
@patch('stream_alert.alert_processor.outputs.pagerduty.PagerDutyIncidentOutput.BACKOFF_MAX', 0)
@patch('stream_alert.alert_processor.outputs.pagerduty.PagerDutyIncidentOutput.BACKOFF_TIME', 0)
class TestWorkContext(object):
    """Test class for WorkContext"""
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

    @patch('stream_alert.alert_processor.outputs.output_base.OutputCredentialsProvider')
    def setup(self, provider_constructor):
        """Setup before each method"""
        provider = MagicMock()
        provider_constructor.return_value = provider
        provider.load_credentials = Mock(
            side_effect=lambda x: self.CREDS if x == self.DESCRIPTOR else None
        )
        dispatcher = PagerDutyIncidentOutput(None)
        self._work = WorkContext(dispatcher, self.CREDS)

    @patch('requests.get')
    def test_get_standardized_priority_sends_correct_reuqest(self, get_mock):
        """PagerDutyIncidentOutput - Priority Verify Sends Correct Request"""
        priority_name = 'priority_name'
        # GET /priorities
        get_mock.return_value.status_code = 200
        context = {'incident_priority': priority_name}

        self._work.get_standardized_priority(context)

        get_mock.assert_called_with(
            'https://api.pagerduty.com/priorities',
            headers={
                'From': 'email@domain.com',
                'Content-Type': 'application/json',
                'Authorization': 'Token token=mocked_token',
                'Accept': 'application/vnd.pagerduty+json;version=2'
            },
            params=None,
            timeout=3.05,
            # verify=False  # FIXME (derek.wang) Before the refactor this was False. Why?
            verify=True
        )

    @patch('requests.get')
    def test_get_standardized_priority_success(self, get_mock):
        """PagerDutyIncidentOutput - Priority Verify Success"""
        priority_name = 'priority_name'
        # GET /priorities
        get_mock.return_value.status_code = 200
        json_check = {'priorities': [{'id': 'verified_priority_id', 'name': priority_name}]}
        get_mock.return_value.json.return_value = json_check

        context = {'incident_priority': priority_name}

        priority_verified = self._work.get_standardized_priority(context)
        assert_equal(priority_verified['id'], 'verified_priority_id')
        assert_equal(priority_verified['type'], 'priority_reference')

    @patch('requests.get')
    def test_get_standardized_priority_fail(self, get_mock):
        """PagerDutyIncidentOutput - Priority Verify Fail"""
        # GET /priorities
        get_mock.return_value.status_code = 404

        context = {'incident_priority': 'priority_name'}

        priority_not_verified = self._work.get_standardized_priority(context)
        assert_equal(priority_not_verified, dict())

    @patch('requests.get')
    def test_get_standardized_priority_empty(self, get_mock):
        """PagerDutyIncidentOutput - Priority Verify Empty"""
        # GET /priorities
        get_mock.return_value.status_code = 200
        json_check = {}
        get_mock.return_value.json.return_value = json_check

        context = {'incident_priority': 'priority_name'}

        priority_not_verified = self._work.get_standardized_priority(context)
        assert_equal(priority_not_verified, dict())

    @patch('requests.get')
    def test_get_standardized_priority_not_found(self, get_mock):
        """PagerDutyIncidentOutput - Priority Verify Not Found"""
        # GET /priorities
        get_mock.return_value.status_code = 200
        json_check = {'priorities': [{'id': 'verified_priority_id', 'name': 'not_priority_name'}]}
        get_mock.return_value.json.return_value = json_check

        context = {'incident_priority': 'priority_name'}

        priority_not_verified = self._work.get_standardized_priority(context)
        assert_equal(priority_not_verified, dict())

    @patch('requests.get')
    def test_get_standardized_priority_invalid(self, get_mock):
        """PagerDutyIncidentOutput - Priority Verify Invalid"""
        # GET /priorities
        get_mock.return_value.status_code = 200
        json_check = {'not_priorities': [{'id': 'verified_priority_id', 'name': 'priority_name'}]}
        get_mock.return_value.json.return_value = json_check

        context = {'incident_priority': 'priority_name'}

        priority_not_verified = self._work.get_standardized_priority(context)
        assert_equal(priority_not_verified, dict())

    @patch('requests.get')
    def test_get_incident_assignment_user_sends_correct_rquest(self, get_mock):
        """PagerDutyIncidentOutput - Incident Assignment User Sends Correct Request"""
        context = {'assigned_user': 'user_to_assign'}
        get_mock.return_value.status_code = 400

        self._work.get_incident_assignment(context)

        get_mock.assert_called_with(
            'https://api.pagerduty.com/users',
            headers={
                'Content-Type': 'application/json',
                'Authorization': 'Token token=mocked_token',
                'Accept': 'application/vnd.pagerduty+json;version=2'
            },
            params={'query': 'user_to_assign'},
            timeout=3.05,
            # verify=False  # FIXME (derek.wang) before the refactor, this was False. Why?
            verify=True
        )

    @patch('requests.get')
    def test_get_incident_assignment_user(self, get_mock):
        """PagerDutyIncidentOutput - Incident Assignment User"""
        context = {'assigned_user': 'user_to_assign'}
        get_mock.return_value.status_code = 200
        json_user = {'users': [{'id': 'verified_user_id'}]}
        get_mock.return_value.json.return_value = json_user

        assigned_key, assigned_value = self._work.get_incident_assignment(context)

        assert_equal(assigned_key, 'assignments')
        assert_equal(assigned_value[0]['assignee']['id'], 'verified_user_id')
        assert_equal(assigned_value[0]['assignee']['type'], 'user_reference')

    def test_get_incident_assignment_policy_no_default(self):
        """PagerDutyIncidentOutput - Incident Assignment Policy (No Default)"""
        context = {'assigned_policy_id': 'policy_id_to_assign'}

        assigned_key, assigned_value = self._work.get_incident_assignment(context)

        assert_equal(assigned_key, 'escalation_policy')
        assert_equal(assigned_value['id'], 'policy_id_to_assign')
        assert_equal(assigned_value['type'], 'escalation_policy_reference')

    @patch('requests.get')
    def test_user_verify_success(self, get_mock):
        """PagerDutyIncidentOutput - User Verify Success"""
        get_mock.return_value.status_code = 200
        json_check = {'users': [{'id': 'verified_user_id'}]}
        get_mock.return_value.json.return_value = json_check

        user_verified = self._work.verify_user_exists()
        assert_true(user_verified)

    @patch('requests.get')
    def test_user_verify_fail(self, get_mock):
        """PagerDutyIncidentOutput - User Verify Fail"""
        get_mock.return_value.status_code = 200
        json_check = {'not_users': [{'not_id': 'verified_user_id'}]}
        get_mock.return_value.json.return_value = json_check

        user_verified = self._work.verify_user_exists()
        assert_false(user_verified)


@patch('stream_alert.alert_processor.outputs.output_base.OutputDispatcher.MAX_RETRY_ATTEMPTS', 1)
@patch('stream_alert.alert_processor.outputs.pagerduty.PagerDutyIncidentOutput.BACKOFF_MAX', 0)
@patch('stream_alert.alert_processor.outputs.pagerduty.PagerDutyIncidentOutput.BACKOFF_TIME', 0)
class TestPagerDutyRestApiClient(object):

    @patch('stream_alert.alert_processor.outputs.output_base.OutputCredentialsProvider')
    def setup(self, _):
        dispatcher = PagerDutyIncidentOutput(None)
        http = JsonHttpProvider(dispatcher)
        self._api_client = PagerDutyRestApiClient('mocked_token', 'user@email.com', http)

    @patch('requests.post')
    def test_multiple_requests_verify_ssl_once(self, post_mock):
        """PagerDutyIncidentOutput - Multiple Requests Verify SSL Once"""
        post_mock.return_value.status_code = 200

        self._api_client.add_note('incident_id', 'this is the note')
        self._api_client.add_note('incident_id', 'this is another note')
        self._api_client.add_note('incident_id', 'this is a third note')

        class Anything(object):
            def __eq__(self, _):
                return True

        class VerifyIsCalledWith(object):
            def __init__(self, expected_verify_value):
                self._expected_verify_value = expected_verify_value

            def __eq__(self, other):
                return self._expected_verify_value == other

        post_mock.assert_has_calls(
            [
                call(
                    Anything(),
                    headers=Anything(), json=Anything(), timeout=Anything(),
                    verify=VerifyIsCalledWith(True)
                ),
                call(
                    Anything(),
                    headers=Anything(), json=Anything(), timeout=Anything(),
                    verify=VerifyIsCalledWith(False)
                ),
                call(
                    Anything(),
                    headers=Anything(), json=Anything(), timeout=Anything(),
                    verify=VerifyIsCalledWith(False)
                ),
            ],
            # So the problem with assert_has_calls() is that it requires you to declare all calls
            # including chained calls. This doesn't work because we do a bunch of random stuff
            # inbetween with the return value (such as .json() calls) and it's not really feasible
            # to declare ALL of the calls.
            #
            # By setting any_order=True, we ensure all of the above calls are made at least once.
            # We lose out on the ability to detect that we called verify=True FIRST (before the
            # two verify=False calls)... but, oh well?
            any_order=True
        )

    @patch('requests.post')
    def test_add_note_incident_sends_correct_request(self, post_mock):
        """PagerDutyIncidentOutput - Add Note to Incident Sends Correct Request"""
        post_mock.return_value.status_code = 200

        self._api_client.add_note('incident_id', 'this is the note')

        post_mock.assert_called_with(
            'https://api.pagerduty.com/incidents/incident_id/notes',
            headers={
                'From': 'user@email.com',
                'Content-Type': 'application/json',
                'Authorization': 'Token token=mocked_token',
                'Accept': 'application/vnd.pagerduty+json;version=2'
            },
            json={'note': {'content': 'this is the note'}},
            timeout=3.05,
            verify=True
        )

    @patch('requests.post')
    def test_add_note_incident_success(self, post_mock):
        """PagerDutyIncidentOutput - Add Note to Incident Success"""
        post_mock.return_value.status_code = 200
        json_note = {'note': {'id': 'created_note_id'}}
        post_mock.return_value.json.return_value = json_note

        note = self._api_client.add_note('incident_id', 'this is the note')

        assert_equal(note.get('id'), 'created_note_id')

    @patch('requests.post')
    def test_add_note_incident_fail(self, post_mock):
        """PagerDutyIncidentOutput - Add Note to Incident Fail"""
        post_mock.return_value.status_code = 200
        json_note = {'note': {'not_id': 'created_note_id'}}
        post_mock.return_value.json.return_value = json_note

        note = self._api_client.add_note('incident_id', 'this is the note')

        assert_false(note.get('id'))

    @patch('requests.post')
    def test_add_note_incident_bad_request(self, post_mock):
        """PagerDutyIncidentOutput - Add Note to Incident Bad Request"""
        post_mock.return_value.status_code = 400
        json_note = {'note': {'id': 'created_note_id'}}
        post_mock.return_value.json.return_value = json_note

        note = self._api_client.add_note('incident_id', 'this is the note')

        assert_false(note)

    @patch('requests.post')
    def test_add_note_incident_no_response(self, post_mock):
        """PagerDutyIncidentOutput - Add Note to Incident No Response"""
        post_mock.return_value.status_code = 200
        json_note = {}
        post_mock.return_value.json.return_value = json_note

        note = self._api_client.add_note('incident_id', 'this is the note')

        assert_false(note)

    @patch('requests.get')
    def test_get_escalation_policy_sends_correct_request(self, get_mock):
        """PagerDutyIncidentOutput - Get Escalation Policies Success"""
        get_mock.return_value.status_code = 200

        self._api_client.get_escalation_policy_by_id('PDUDOHF')

        get_mock.assert_called_with(
            'https://api.pagerduty.com/escalation_policies',
            headers={
                'From': 'user@email.com', 'Content-Type': 'application/json',
                'Authorization': 'Token token=mocked_token',
                'Accept': 'application/vnd.pagerduty+json;version=2'
            },
            params={
                'query': 'PDUDOHF'
            },
            timeout=3.05, verify=True
        )

    @patch('requests.get')
    def test_get_escalation_policy_success(self, get_mock):
        """PagerDutyIncidentOutput - Get Escalation Policies Success"""
        get_mock.return_value.status_code = 200
        json_note = {'escalation_policies': [{'id': 'PDUDOHF'}]}
        get_mock.return_value.json.return_value = json_note

        policy = self._api_client.get_escalation_policy_by_id('PDUDOHF')

        assert_equal(policy.get('id'), 'PDUDOHF')


class TestJsonHttpProvider(object):

    def setup(self):
        self._dispatcher = MagicMock(spec=OutputDispatcher)
        self._http = JsonHttpProvider(self._dispatcher)

    def test_get_sends_correct_arguments(self):
        """JsonHttpProvider - Get - Arguments"""
        self._http.get(
            'http://airbnb.com',
            {'q': 'zz'},
            headers={'Accept': 'application/tofu'},
            verify=True
        )
        self._dispatcher._get_request_retry.assert_called_with(
            'http://airbnb.com',
            {'q': 'zz'},
            {'Accept': 'application/tofu'},
            True
        )

    def test_get_returns_false_on_error(self):
        """JsonHttpProvider - Get - Error"""
        self._dispatcher._get_request_retry.side_effect = OutputRequestFailure('?')
        assert_false(self._http.get('http://airbnb.com', {'q': 'zz'}))

    def test_post_sends_correct_arguments(self):
        """JsonHttpProvider - Post - Arguments"""
        self._http.post(
            'http://airbnb.com',
            {'q': 'zz'},
            headers={'Accept': 'application/tofu'},
            verify=True
        )
        self._dispatcher._post_request_retry.assert_called_with(
            'http://airbnb.com',
            {'q': 'zz'},
            {'Accept': 'application/tofu'},
            True
        )

    def test_post_returns_false_on_error(self):
        """JsonHttpProvider - Post - Error"""
        self._dispatcher._post_request_retry.side_effect = OutputRequestFailure('?')
        assert_false(self._http.post('http://airbnb.com', {'q': 'zz'}))

    def test_put_sends_correct_arguments(self):
        """JsonHttpProvider - Post - Arguments"""
        self._http.put(
            'http://airbnb.com',
            {'q': 'zz'},
            headers={'Accept': 'application/tofu'},
            verify=True
        )
        self._dispatcher._put_request_retry.assert_called_with(
            'http://airbnb.com',
            {'q': 'zz'},
            {'Accept': 'application/tofu'},
            True
        )

    def test_put_returns_false_on_error(self):
        """JsonHttpProvider - Put - Error"""
        self._dispatcher._put_request_retry.side_effect = OutputRequestFailure('?')
        assert_false(self._http.put('http://airbnb.com', {}))


class TestWorkContextUnit(object):
    """This test focuses on testing corner cases instead of top-down.

    This class does not mock out entire requests but rather mocks out behavior on the Work class.
    """

    def setup(self):
        incident = {'id': 'ABCDEFGH'}
        event = {'dedup_key': '000000ppppdpdpdpdpd'}
        merged_incident = {'id': '12345678'}
        note = {'id': 'notepaid'}
        work = WorkContext(
            MagicMock(
                spec=OutputDispatcher,
                __service__='test'
            ),
            {
                'email_from': 'test@test.test',
                'escalation_policy_id': 'EP123123',
                'service_id': 'SP123123',
                'token': 'zzzzzzzzzz',
                'api': 'https://api.pagerduty.com',
            }
        )
        work.verify_user_exists = MagicMock(return_value=True)
        work._create_base_incident = MagicMock(return_value=incident)
        work._create_base_alert_event = MagicMock(return_value=event)
        work._merge_event_into_incident = MagicMock(return_value=merged_incident)
        work._add_incident_note = MagicMock(return_value=note)
        work._add_instability_note = MagicMock(return_value=note)

        self._work = work

    @patch('logging.Logger.error')
    @patch('stream_alert.alert_processor.outputs.pagerduty.compose_alert')
    def test_positive_case(self, compose_alert_mock, log_error):
        """PagerDuty WorkContext - Minimum Positive Case"""
        publication = {}
        compose_alert_mock.return_value = publication

        alert = get_alert()
        result = self._work.run(alert, 'descriptor')
        assert_true(result)

        log_error.assert_not_called()

    @patch('logging.Logger.error')
    @patch('stream_alert.alert_processor.outputs.pagerduty.compose_alert')
    def test_unstable_merge_fail(self, compose_alert_mock, log_error):
        """PagerDuty WorkContext - Unstable - Merge Failed"""
        publication = {}
        compose_alert_mock.return_value = publication

        self._work._merge_event_into_incident = MagicMock(return_value=False)

        alert = get_alert()
        result = self._work.run(alert, 'descriptor')
        assert_true(result)

        log_error.assert_called_with(
            '[%s] Failed to merge alert [%s] into [%s]', 'test', '000000ppppdpdpdpdpd', 'ABCDEFGH'
        )

    @patch('logging.Logger.error')
    @patch('stream_alert.alert_processor.outputs.pagerduty.compose_alert')
    def test_unstable_note_fail(self, compose_alert_mock, log_error):
        """PagerDuty WorkContext - Unstable - Add Node Failed"""
        publication = {}
        compose_alert_mock.return_value = publication

        self._work._add_incident_note = MagicMock(return_value=False)

        alert = get_alert()
        result = self._work.run(alert, 'descriptor')
        assert_true(result)

        log_error.assert_called_with(
            '[%s] Failed to add note to incident (%s)', 'test', 'ABCDEFGH'
        )

    @patch('stream_alert.alert_processor.outputs.pagerduty.compose_alert')
    def test_unstable_adds_instability_note(self, compose_alert_mock):
        """PagerDuty WorkContext - Unstable - Add Instability Note"""
        publication = {}
        compose_alert_mock.return_value = publication

        self._work._add_incident_note = MagicMock(return_value=False)

        alert = get_alert()
        result = self._work.run(alert, 'descriptor')
        assert_true(result)

        self._work._add_instability_note.assert_called_with('ABCDEFGH')

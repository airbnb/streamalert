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
# pylint: disable=protected-access,attribute-defined-outside-init,too-many-lines,invalid-name
import re
from collections import OrderedDict
from unittest.mock import MagicMock, Mock, call, patch

from streamalert.alert_processor.outputs.output_base import (
    OutputDispatcher, OutputRequestFailure)
from streamalert.alert_processor.outputs.pagerduty import (
    JsonHttpProvider, PagerDutyIncidentOutput, PagerDutyOutput,
    PagerDutyOutputV2, PagerDutyRestApiClient, WorkContext)
from tests.unit.streamalert.alert_processor.helpers import get_alert


@patch('streamalert.alert_processor.outputs.output_base.OutputDispatcher.MAX_RETRY_ATTEMPTS', 1)
class TestPagerDutyOutput:
    """Test class for PagerDutyOutput"""
    DESCRIPTOR = 'unit_test_pagerduty'
    SERVICE = 'pagerduty'
    OUTPUT = ':'.join([SERVICE, DESCRIPTOR])
    CREDS = {'url': 'http://pagerduty.foo.bar/create_event.json',
             'service_key': 'mocked_service_key'}

    @patch('streamalert.alert_processor.outputs.output_base.OutputCredentialsProvider')
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
        assert len(props) == 1
        assert (props['url'] ==
                'https://events.pagerduty.com/generic/2010-04-15/create_event.json')

    @patch('logging.Logger.info')
    @patch('requests.post')
    def test_dispatch_success(self, post_mock, log_mock):
        """PagerDutyOutput - Dispatch Success"""
        post_mock.return_value.status_code = 200

        assert self._dispatcher.dispatch(get_alert(), self.OUTPUT)

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

        assert not self._dispatcher.dispatch(get_alert(), self.OUTPUT)

        log_mock.assert_called_with('Failed to send alert to %s:%s', self.SERVICE, self.DESCRIPTOR)

    @patch('logging.Logger.error')
    def test_dispatch_bad_descriptor(self, log_mock):
        """PagerDutyOutput - Dispatch Failure, Bad Descriptor"""
        assert not self._dispatcher.dispatch(
            get_alert(), ':'.join([self.SERVICE, 'bad_descriptor']))

        log_mock.assert_called_with('Failed to send alert to %s:%s', self.SERVICE, 'bad_descriptor')

    @patch('streamalert.alert_processor.outputs.pagerduty.compose_alert')
    @patch('logging.Logger.info')
    @patch('requests.post')
    def test_dispatch_success_with_contexts(self, post_mock, log_mock, compose_alert):
        """PagerDutyOutput - Dispatch Success"""
        compose_alert.return_value = {
            '@pagerduty.contexts': [
                {
                    'type': 'link',
                    'href': 'https://streamalert.io',
                    'text': 'Link text'
                },
                {
                    'type': 'image',
                    'src': 'https://streamalert.io/en/stable/_images/sa-complete-arch.png',
                }
            ]
        }

        RequestMocker.setup_mock(post_mock)

        assert self._dispatcher.dispatch(get_alert(), self.OUTPUT)

        log_mock.assert_called_with('Successfully sent alert to %s:%s',
                                    self.SERVICE, self.DESCRIPTOR)

        post_mock.assert_called_with(
            'http://pagerduty.foo.bar/create_event.json',
            headers=None,
            json={
                'client_url': '',
                'event_type': 'trigger',
                'contexts': [
                    {
                        'text': 'Link text',
                        'href': 'https://streamalert.io', 'type': 'link'
                    },
                    {
                        'src': 'https://streamalert.io/en/stable/_images/sa-complete-arch.png',
                        'type': 'image'
                    }
                ],
                'client': 'streamalert',
                'details': {
                    'record': {
                        'compressed_size': '9982', 'node_id': '1', 'cb_server': 'cbserver',
                        'timestamp': '1496947381.18', 'md5': '0F9AA55DA3BDE84B35656AD8911A22E1',
                        'type': 'binarystore.file.added',
                        'file_path': '/tmp/5DA/AD8/0F9AA55DA3BDE84B35656AD8911A22E1.zip',
                        'size': '21504'
                    },
                    'description': 'Info about this rule and what actions to take'
                },
                'service_key': 'mocked_service_key',
                'description': 'StreamAlert Rule Triggered - cb_binarystore_file_added'
            },
            timeout=3.05, verify=True
        )


@patch('streamalert.alert_processor.outputs.output_base.OutputDispatcher.MAX_RETRY_ATTEMPTS', 1)
class TestPagerDutyOutputV2:
    """Test class for PagerDutyOutputV2"""
    DESCRIPTOR = 'unit_test_pagerduty-v2'
    SERVICE = 'pagerduty-v2'
    OUTPUT = ':'.join([SERVICE, DESCRIPTOR])
    CREDS = {'url': 'http://pagerduty.foo.bar/create_event.json',
             'routing_key': 'mocked_routing_key'}

    @patch('streamalert.alert_processor.outputs.output_base.OutputCredentialsProvider')
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
        assert len(props) == 1
        assert props['url'] == 'https://events.pagerduty.com/v2/enqueue'

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
                'dedup_key': 'unit_test_pagerduty-v2:79192344-4a6d-4850-8d06-9c3fef1060a4',
            },
            timeout=3.05, verify=True
        )

    @patch('logging.Logger.info')
    @patch('requests.post')
    def test_dispatch_success(self, post_mock, log_mock):
        """PagerDutyOutputV2 - Dispatch Success"""
        post_mock.return_value.status_code = 200

        assert self._dispatcher.dispatch(get_alert(), self.OUTPUT)

        log_mock.assert_called_with('Successfully sent alert to %s:%s',
                                    self.SERVICE, self.DESCRIPTOR)

    @patch('logging.Logger.error')
    @patch('requests.post')
    def test_dispatch_failure(self, post_mock, log_mock):
        """PagerDutyOutputV2 - Dispatch Failure, Bad Request"""
        json_error = {'message': 'error message', 'errors': ['error1']}
        post_mock.return_value.json.return_value = json_error
        post_mock.return_value.status_code = 400

        assert not self._dispatcher.dispatch(get_alert(), self.OUTPUT)

        log_mock.assert_called_with('Failed to send alert to %s:%s', self.SERVICE, self.DESCRIPTOR)

    @patch('logging.Logger.error')
    def test_dispatch_bad_descriptor(self, log_mock):
        """PagerDutyOutputV2 - Dispatch Failure, Bad Descriptor"""
        assert not self._dispatcher.dispatch(
            get_alert(), ':'.join([self.SERVICE, 'bad_descriptor']))

        log_mock.assert_called_with('Failed to send alert to %s:%s', self.SERVICE, 'bad_descriptor')


# pylint: disable=too-many-public-methods
@patch('streamalert.alert_processor.outputs.output_base.OutputDispatcher.MAX_RETRY_ATTEMPTS', 1)
@patch('streamalert.alert_processor.outputs.pagerduty.PagerDutyIncidentOutput.BACKOFF_MAX', 0)
@patch('streamalert.alert_processor.outputs.pagerduty.PagerDutyIncidentOutput.BACKOFF_TIME', 0)
class TestPagerDutyIncidentOutput:
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

    @patch('streamalert.alert_processor.outputs.output_base.OutputCredentialsProvider')
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
        assert len(props) == 1
        assert props['api'] == 'https://api.pagerduty.com'

    @patch('requests.put')
    @patch('requests.post')
    @patch('requests.get')
    def test_dispatch_sends_correct_create_request(self, get_mock, post_mock, put_mock):
        """PagerDutyIncidentOutput - Dispatch Success, Good User, Sends Correct Create Request

        This test ensures that the POST /v2/enqueue call is called with the proper params.
        """
        RequestMocker.setup_mock(get_mock)
        RequestMocker.setup_mock(post_mock)
        RequestMocker.setup_mock(put_mock)

        ctx = {}
        self._dispatcher.dispatch(get_alert(context=ctx), self.OUTPUT)

        post_mock.assert_any_call(
            'https://events.pagerduty.com/v2/enqueue',
            headers=None,
            json={
                'client_url': None,
                'client': 'StreamAlert',
                'payload': {
                    'custom_details': OrderedDict(
                        [
                            ('description', 'Info about this rule and what actions to take'),
                            ('record',
                             {
                                 'compressed_size': '9982',
                                 'node_id': '1',
                                 'cb_server': 'cbserver',
                                 'timestamp': '1496947381.18',
                                 'md5': '0F9AA55DA3BDE84B35656AD8911A22E1',
                                 'type': 'binarystore.file.added',
                                 'file_path': '/tmp/5DA/AD8/0F9AA55DA3BDE84B35656AD8911A22E1.zip',
                                 'size': '21504'
                             })
                        ]
                    ),
                    'group': None,
                    'severity': 'critical',
                    'component': None,
                    'summary': 'StreamAlert Rule Triggered - cb_binarystore_file_added',
                    'source': 'carbonblack:binarystore.file.added',
                    'class': None
                },
                'links': [],
                'images': [],
                'event_action': 'trigger',
                'routing_key': 'mocked_key',
                'dedup_key': 'unit_test_pagerduty-incident:79192344-4a6d-4850-8d06-9c3fef1060a4'
            }, timeout=3.05, verify=True
        )

    @patch('requests.put')
    @patch('requests.post')
    @patch('requests.get')
    def test_dispatch_sends_correct_put_incident_request(self, get_mock, post_mock, put_mock):
        """PagerDutyIncidentOutput - Dispatch Success, Good User, Sends Correct Update Request

        This test ensures that the PUT /incidents/## call is called with the proper params.
        """
        RequestMocker.setup_mock(get_mock)
        RequestMocker.setup_mock(post_mock)
        RequestMocker.setup_mock(put_mock)

        ctx = {}
        self._dispatcher.dispatch(get_alert(context=ctx), self.OUTPUT)

        put_mock.assert_any_call(
            'https://api.pagerduty.com/incidents/incident_id',
            headers={
                'From': 'email@domain.com',
                'Content-Type': 'application/json',
                'Authorization': 'Token token=mocked_token',
                'Accept': 'application/vnd.pagerduty+json;version=2'},
            json={
                'incident': {
                    'body': {
                        'type': 'incident_body',
                        'details': 'Info about this rule and what actions to take'
                    },
                    'escalation_policy': {
                        'type': 'escalation_policy_reference',
                        'id': 'mocked_escalation_policy_id'
                    },
                    'type': 'incident',
                    'service': {
                        'type': 'service_reference',
                        'id': 'mocked_service_id'
                    },
                    'title': 'StreamAlert Incident - Rule triggered: cb_binarystore_file_added'
                }
            },
            timeout=3.05, verify=False
        )

    @patch('requests.put')
    @patch('requests.post')
    @patch('requests.get')
    def test_dispatch_sends_correct_with_assigned_user(self, get_mock, post_mock, put_mock):
        """PagerDutyIncidentOutput - Dispatch Success with Assignee

        Ensure the PUT call includes assignments when there is an "assigned_user"
        """
        RequestMocker.setup_mock(get_mock)
        RequestMocker.setup_mock(post_mock)
        RequestMocker.setup_mock(put_mock)

        ctx = {
            'pagerduty-incident': {
                'assigned_user': 'valid_user'
            }
        }
        self._dispatcher.dispatch(get_alert(context=ctx), self.OUTPUT)

        put_mock.assert_any_call(
            'https://api.pagerduty.com/incidents/incident_id',
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
                    'type': 'incident',

                    # Assignment here; the valid_user_id comes from the /users API
                    'assignments': [
                        {
                            'assignee': {
                                'type': 'user_reference', 'id': 'valid_user_id'
                            }
                        }
                    ],
                }
            },
            timeout=3.05, verify=False
        )

    @patch('logging.Logger.warning')
    @patch('logging.Logger.info')
    @patch('requests.put')
    @patch('requests.post')
    @patch('requests.get')
    def test_dispatch_sends_correct_with_invalid_assigned_user(self, get_mock, post_mock, put_mock,
                                                               log_info_mock, log_warn_mock):
        """PagerDutyIncidentOutput - Dispatch Success with invalid Assignee

        When a user is assigned but the email address is not found in PagerDuty, the call
        should still succeed. It should log a warning and default to using the escalation policy.
        """

        def invalid_user_matcher(*args, **kwargs):
            if args[0] != 'https://api.pagerduty.com/users':
                return False

            query = kwargs.get('params', {}).get('query', None)
            return query == 'invalid_user'

        RequestMocker.setup_mock(post_mock)
        RequestMocker.setup_mock(put_mock)
        RequestMocker.setup_mock(
            get_mock,
            [
                [invalid_user_matcher, 200, {'users': []}],
                ['/users', 200, RequestMocker.USERS_JSON],
                ['/incidents', 200, RequestMocker.INCIDENTS_JSON],
            ]
        )

        ctx = {'pagerduty-incident': {'assigned_user': 'invalid_user'}}
        assert self._dispatcher.dispatch(get_alert(context=ctx), self.OUTPUT)

        put_mock.assert_any_call(
            'https://api.pagerduty.com/incidents/incident_id',
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
                    'type': 'incident',

                    # Cannot do assignment, so default to escalation policy
                    'escalation_policy': {
                        'type': 'escalation_policy_reference',
                        'id': 'mocked_escalation_policy_id'
                    },
                }
            },
            timeout=3.05, verify=False
        )

        log_warn_mock.assert_called_with(
            '[%s] Assignee (%s) could not be found in PagerDuty',
            self.SERVICE,
            'invalid_user'
        )
        log_info_mock.assert_called_with('Successfully sent alert to %s:%s',
                                         self.SERVICE, self.DESCRIPTOR)

    @patch('streamalert.alert_processor.outputs.pagerduty.compose_alert')
    @patch('requests.put')
    @patch('requests.post')
    @patch('requests.get')
    def test_dispatch_sends_correct_with_urgency(self, get_mock, post_mock, put_mock,
                                                 compose_alert):
        """PagerDutyIncidentOutput - Dispatch Success, Good User, Sends Correct Urgency

        Ensure the PUT call respects a publisher urgency.
        """
        RequestMocker.setup_mock(get_mock)
        RequestMocker.setup_mock(post_mock)
        RequestMocker.setup_mock(put_mock)

        compose_alert.return_value = {
            '@pagerduty-incident.urgency': 'low'
        }

        ctx = {}
        self._dispatcher.dispatch(get_alert(context=ctx), self.OUTPUT)

        put_mock.assert_any_call(
            'https://api.pagerduty.com/incidents/incident_id',
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
                    'escalation_policy': {
                        'type': 'escalation_policy_reference',
                        'id': 'mocked_escalation_policy_id'
                    },
                    'type': 'incident',

                    # This field should exist
                    'urgency': 'low',
                }
            },
            timeout=3.05, verify=False
        )

    @patch('logging.Logger.warning')
    @patch('streamalert.alert_processor.outputs.pagerduty.compose_alert')
    @patch('requests.put')
    @patch('requests.post')
    @patch('requests.get')
    def test_dispatch_sends_correct_bad_urgency(self, get_mock, post_mock, put_mock,
                                                compose_alert, log_mock):
        """PagerDutyIncidentOutput - Dispatch Success, Good User, Omit Bad Urgency

        When an urgency is provided that is not valid, it should omit it entirely.
        """
        RequestMocker.setup_mock(get_mock)
        RequestMocker.setup_mock(post_mock)
        RequestMocker.setup_mock(put_mock)

        compose_alert.return_value = {
            '@pagerduty-incident.urgency': 'asdf'
        }

        ctx = {}
        self._dispatcher.dispatch(get_alert(context=ctx), self.OUTPUT)

        put_mock.assert_any_call(
            'https://api.pagerduty.com/incidents/incident_id',
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
                    'escalation_policy': {
                        'type': 'escalation_policy_reference',
                        'id': 'mocked_escalation_policy_id'
                    },
                    'type': 'incident',

                    # urgency is omitted here because the original urgency was invalid
                }
            },
            timeout=3.05, verify=False
        )
        log_mock.assert_called_with('[%s] Invalid pagerduty incident urgency: "%s"',
                                    'pagerduty-incident', 'asdf')

    @patch('logging.Logger.info')
    @patch('requests.put')
    @patch('requests.post')
    @patch('requests.get')
    def test_dispatch_success_good_policy(self, get_mock, post_mock, put_mock, log_mock):
        """PagerDutyIncidentOutput - Dispatch Success, Good Policy

        Ensures that we respect a custom escalation policy
        """
        RequestMocker.setup_mock(get_mock)
        RequestMocker.setup_mock(post_mock)
        RequestMocker.setup_mock(put_mock)

        ctx = {
            'pagerduty-incident': {
                'assigned_policy_id': 'valid_policy_id'
            }
        }
        assert self._dispatcher.dispatch(get_alert(context=ctx), self.OUTPUT)

        put_mock.assert_any_call(
            'https://api.pagerduty.com/incidents/incident_id',
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
                    'escalation_policy': {
                        'type': 'escalation_policy_reference',
                        'id': 'valid_policy_id',  # Policy is sent here
                    },
                    'type': 'incident',
                }
            },
            timeout=3.05, verify=False
        )

        log_mock.assert_called_with('Successfully sent alert to %s:%s',
                                    self.SERVICE, self.DESCRIPTOR)

    @patch('logging.Logger.info')
    @patch('requests.put')
    @patch('requests.post')
    @patch('requests.get')
    def test_dispatch_success_with_priority(self, get_mock, post_mock, put_mock, log_mock):
        """PagerDutyIncidentOutput - Dispatch Success With Priority

        Ensure the PUT call respects a priority, if a valid one is given.
        """
        RequestMocker.setup_mock(get_mock)
        RequestMocker.setup_mock(post_mock)
        RequestMocker.setup_mock(put_mock)

        ctx = {
            'pagerduty-incident': {
                'incident_priority': 'priority_name',
            }
        }
        assert self._dispatcher.dispatch(get_alert(context=ctx), self.OUTPUT)

        put_mock.assert_any_call(
            'https://api.pagerduty.com/incidents/incident_id',
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
                    'escalation_policy': {
                        'type': 'escalation_policy_reference',
                        'id': 'mocked_escalation_policy_id',
                    },
                    'type': 'incident',

                    # This priority node should show up
                    'priority': {
                        'type': 'priority_reference',
                        'id': 'priority_id'
                    }
                }
            },
            timeout=3.05, verify=False
        )

        log_mock.assert_called_with('Successfully sent alert to %s:%s',
                                    self.SERVICE, self.DESCRIPTOR)

    @patch('logging.Logger.info')
    @patch('requests.put')
    @patch('requests.post')
    @patch('requests.get')
    def test_dispatch_success_with_note(self, get_mock, post_mock, put_mock, log_mock):
        """PagerDutyIncidentOutput - Dispatch Success With Note"""
        RequestMocker.setup_mock(get_mock)
        RequestMocker.setup_mock(post_mock)
        RequestMocker.setup_mock(put_mock)

        ctx = {
            'pagerduty-incident': {
                'note': 'This is just a note'
            }
        }
        assert self._dispatcher.dispatch(get_alert(context=ctx), self.OUTPUT)

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
        RequestMocker.setup_mock(get_mock)
        RequestMocker.setup_mock(post_mock)
        RequestMocker.setup_mock(put_mock)

        ctx = {
            'pagerduty-incident': {
                'note': None
            }
        }
        assert self._dispatcher.dispatch(get_alert(context=ctx), self.OUTPUT)

        def notes_api_call(*args, **_):
            return args[0].endswith('/notes')

        RequestMocker.assert_mock_with_no_calls_like(post_mock, notes_api_call)

        log_mock.assert_called_with('Successfully sent alert to %s:%s',
                                    self.SERVICE, self.DESCRIPTOR)

    @patch('logging.Logger.info')
    @patch('requests.put')
    @patch('requests.post')
    @patch('requests.get')
    def test_dispatch_success_no_context(self, get_mock, post_mock, put_mock, log_mock):
        """PagerDutyIncidentOutput - Dispatch Success, No Context"""
        RequestMocker.setup_mock(get_mock)
        RequestMocker.setup_mock(post_mock)
        RequestMocker.setup_mock(put_mock)

        assert self._dispatcher.dispatch(get_alert(), self.OUTPUT)

        log_mock.assert_called_with('Successfully sent alert to %s:%s',
                                    self.SERVICE, self.DESCRIPTOR)

    @patch('logging.Logger.error')
    @patch('requests.post')
    @patch('requests.get')
    def test_dispatch_failure_bad_from_user(self, get_mock, post_mock, log_mock):
        """PagerDutyIncidentOutput - Dispatch Failure: No User

        This fixtures the behavior if the "from_email" configuration param is invalid.
        This causes significant problems on the PagerDuty API so we want to error out early.
        """
        RequestMocker.setup_mock(post_mock)
        RequestMocker.setup_mock(
            get_mock,
            [
                ['/users', 200, {'users': []}],
                ['/incidents', 200, RequestMocker.INCIDENTS_JSON],
            ]
        )

        assert not self._dispatcher.dispatch(get_alert(), self.OUTPUT)

        log_mock.assert_called_with('Failed to send alert to %s:%s', self.SERVICE, self.DESCRIPTOR)

    @patch('logging.Logger.error')
    @patch('requests.post')
    @patch('requests.get')
    def test_dispatch_no_dispatch_no_event_response(self, get_mock, post_mock, log_mock):
        """PagerDutyIncidentOutput - Dispatch Failure, Event Enqueue No Response

        Tests behavior if the /enqueue API call fails.
        """
        RequestMocker.setup_mock(get_mock)
        RequestMocker.setup_mock(
            post_mock,
            [
                ['/enqueue', 400, {}],
            ]
        )

        assert not self._dispatcher.dispatch(get_alert(), self.OUTPUT)

        log_mock.assert_called_with('Failed to send alert to %s:%s', self.SERVICE, self.DESCRIPTOR)

    @patch('logging.Logger.error')
    @patch('requests.put')
    @patch('requests.post')
    @patch('requests.get')
    def test_dispatch_no_dispatch_no_incident_response(self, get_mock, post_mock, put_mock,
                                                       log_mock):
        """PagerDutyIncidentOutput - Dispatch Failure, No Incident Response

        Tests behavior if the PUT /incidents/# API call fails.
        """
        RequestMocker.setup_mock(get_mock)
        RequestMocker.setup_mock(post_mock)
        RequestMocker.setup_mock(
            put_mock,
            [
                [re.compile(r'^.*/incidents/[a-zA-Z0-9-_]+$'), 400, {}],
            ]
        )

        assert not self._dispatcher.dispatch(get_alert(), self.OUTPUT)

        log_mock.assert_any_call('[%s] Failed to update container incident for event', self.SERVICE)
        log_mock.assert_called_with('Failed to send alert to %s:%s', self.SERVICE, self.DESCRIPTOR)

    @patch('logging.Logger.error')
    @patch('requests.put')
    @patch('requests.post')
    @patch('requests.get')
    def test_dispatch_no_dispatch_no_incident_id_in_response(self, get_mock, post_mock, put_mock,
                                                             log_mock):
        """PagerDutyIncidentOutput - Dispatch Failure, No Incident Id in Response

        This is somewhat of a specific weird case when the response structure is not what we
        expect and is missing the id.
        """
        RequestMocker.setup_mock(get_mock)
        RequestMocker.setup_mock(post_mock)
        RequestMocker.setup_mock(
            put_mock,
            [
                [re.compile(r'^.*/incidents/[a-zA-Z0-9-_]+$'), 200, {'incident': {'not_id': '?'}}],
            ]
        )

        assert not self._dispatcher.dispatch(get_alert(), self.OUTPUT)
        log_mock.assert_any_call('[%s] Incident is missing "id"??', self.SERVICE)

    @patch('logging.Logger.error')
    def test_dispatch_bad_descriptor(self, log_mock):
        """PagerDutyIncidentOutput - Dispatch Failure, Bad Descriptor"""
        assert not self._dispatcher.dispatch(
            get_alert(), ':'.join([self.SERVICE, 'bad_descriptor']))

        log_mock.assert_called_with('Failed to send alert to %s:%s', self.SERVICE, 'bad_descriptor')

    @patch('logging.Logger.info')
    @patch('requests.put')
    @patch('requests.post')
    @patch('requests.get')
    def test_dispatch_request_responder(self, get_mock, post_mock, put_mock, log_mock):
        """PagerDutyIncidentOutput - Dispatch Success, Request Responder

        Ensures the correct calls are made to Request Responders.
        """
        RequestMocker.setup_mock(get_mock)
        RequestMocker.setup_mock(post_mock)
        RequestMocker.setup_mock(put_mock)

        ctx = {
            'pagerduty-incident': {
                'responders': ['responder1@airbnb.com'],
                'responder_message': 'I am tea kettle short and stout',
            }
        }
        assert self._dispatcher.dispatch(get_alert(context=ctx), self.OUTPUT)

        get_mock.assert_any_call(
            'https://api.pagerduty.com/users',
            headers={
                'Content-Type': 'application/json',
                'Authorization': 'Token token=mocked_token',
                'Accept': 'application/vnd.pagerduty+json;version=2'
            },
            params={'query': 'responder1@airbnb.com'},
            timeout=3.05, verify=False
        )

        post_mock.assert_any_call(
            'https://api.pagerduty.com/incidents/incident_id/responder_requests',
            headers={
                'From': 'email@domain.com',
                'Content-Type': 'application/json',
                'Authorization': 'Token token=mocked_token',
                'Accept': 'application/vnd.pagerduty+json;version=2'
            },
            json={
                'requester_id': 'valid_user_id',
                'message': 'I am tea kettle short and stout',
                'responder_request_targets': [
                    {
                        'responder_request_target': {
                            'type': 'user_reference',
                            'id': 'valid_user_id'
                        }
                    }
                ]
            },
            timeout=3.05,
            verify=False
        )

        log_mock.assert_called_with(
            'Successfully sent alert to %s:%s', self.SERVICE, self.DESCRIPTOR
        )

    @patch('logging.Logger.info')
    @patch('requests.put')
    @patch('requests.post')
    @patch('requests.get')
    def test_dispatch_request_responder_single(self, get_mock, post_mock, put_mock, log_mock):
        """PagerDutyIncidentOutput - Dispatch Success, Support single responder and default message

        Ensure support for omitting the message and using string syntax for responder.
        """
        RequestMocker.setup_mock(get_mock)
        RequestMocker.setup_mock(post_mock)
        RequestMocker.setup_mock(put_mock)

        ctx = {
            'pagerduty-incident': {
                'responders': 'responder1@airbnb.com',
            }
        }
        assert self._dispatcher.dispatch(get_alert(context=ctx), self.OUTPUT)

        get_mock.assert_any_call(
            'https://api.pagerduty.com/users',
            headers={
                'Content-Type': 'application/json',
                'Authorization': 'Token token=mocked_token',
                'Accept': 'application/vnd.pagerduty+json;version=2'
            },
            params={'query': 'responder1@airbnb.com'},
            timeout=3.05, verify=False
        )

        post_mock.assert_any_call(
            'https://api.pagerduty.com/incidents/incident_id/responder_requests',
            headers={
                'From': 'email@domain.com',
                'Content-Type': 'application/json',
                'Authorization': 'Token token=mocked_token',
                'Accept': 'application/vnd.pagerduty+json;version=2'
            },
            json={
                'requester_id': 'valid_user_id',
                'message': 'An incident was reported that requires your attention.',
                'responder_request_targets': [
                    {
                        'responder_request_target': {
                            'type': 'user_reference',
                            'id': 'valid_user_id'
                        }
                    }
                ]
            },
            timeout=3.05,
            verify=False
        )

        log_mock.assert_called_with(
            'Successfully sent alert to %s:%s', self.SERVICE, self.DESCRIPTOR
        )

    @patch('logging.Logger.error')
    @patch('logging.Logger.info')
    @patch('requests.put')
    @patch('requests.post')
    @patch('requests.get')
    def test_dispatch_request_responder_not_valid(self, get_mock, post_mock, put_mock,
                                                  log_mock, log_error_mock):
        """PagerDutyIncidentOutput - Dispatch Success, Responder not valid

        When a responer is requested but the email is not associated with a PD user, it will
        omit the request, log an error, add an instability note, but the overall request will
        still succeed.
        """
        def invalid_user_matcher(*args, **kwargs):
            if args[0] != 'https://api.pagerduty.com/users':
                return False

            query = kwargs.get('params', {}).get('query', None)
            return query == 'invalid_responder@airbnb.com'

        RequestMocker.setup_mock(post_mock)
        RequestMocker.setup_mock(put_mock)
        RequestMocker.setup_mock(
            get_mock,
            [
                [invalid_user_matcher, 200, {'users': []}],
                ['/users', 200, RequestMocker.USERS_JSON],
                ['/incidents', 200, RequestMocker.INCIDENTS_JSON],
            ]
        )

        ctx = {
            'pagerduty-incident': {
                'responders': ['invalid_responder@airbnb.com'],
            }
        }
        assert self._dispatcher.dispatch(get_alert(context=ctx), self.OUTPUT)

        def responder_request_calls(*args, **_):
            return args[0].endswith('/responder_requests')

        RequestMocker.assert_mock_with_no_calls_like(post_mock, responder_request_calls)
        log_error_mock.assert_called_with(
            '[pagerduty-incident] Failed to request a responder (invalid_responder@airbnb.com)'
            ' on incident (incident_id)'
        )

        expected_note = (
            'StreamAlert failed to correctly setup this incident. Please contact your '
            'StreamAlert administrator.\n\nErrors:\n- [pagerduty-incident] Failed to request '
            'a responder (invalid_responder@airbnb.com) on incident (incident_id)'
        )
        post_mock.assert_any_call(
            'https://api.pagerduty.com/incidents/incident_id/notes',
            headers={'From': 'email@domain.com',
                     'Content-Type': 'application/json',
                     'Authorization': 'Token token=mocked_token',
                     'Accept': 'application/vnd.pagerduty+json;version=2'},
            json={'note': {'content': expected_note}},
            timeout=3.05, verify=False
        )

        log_mock.assert_called_with('Successfully sent alert to %s:%s',
                                    self.SERVICE, self.DESCRIPTOR)

        log_mock.assert_called_with(
            'Successfully sent alert to %s:%s', self.SERVICE, self.DESCRIPTOR
        )


@patch('streamalert.alert_processor.outputs.output_base.OutputDispatcher.MAX_RETRY_ATTEMPTS', 1)
@patch('streamalert.alert_processor.outputs.pagerduty.PagerDutyIncidentOutput.BACKOFF_MAX', 0)
@patch('streamalert.alert_processor.outputs.pagerduty.PagerDutyIncidentOutput.BACKOFF_TIME', 0)
class TestWorkContext:
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

    @patch('streamalert.alert_processor.outputs.output_base.OutputCredentialsProvider')
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

        self._work._get_standardized_priority(context)

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

        priority_verified = self._work._get_standardized_priority(context)
        assert priority_verified['id'] == 'verified_priority_id'
        assert priority_verified['type'] == 'priority_reference'

    @patch('requests.get')
    def test_get_standardized_priority_fail(self, get_mock):
        """PagerDutyIncidentOutput - Priority Verify Fail"""
        # GET /priorities
        get_mock.return_value.status_code = 404

        context = {'incident_priority': 'priority_name'}

        priority_not_verified = self._work._get_standardized_priority(context)
        assert not priority_not_verified

    @patch('requests.get')
    def test_get_standardized_priority_empty(self, get_mock):
        """PagerDutyIncidentOutput - Priority Verify Empty"""
        # GET /priorities
        get_mock.return_value.status_code = 200
        json_check = {}
        get_mock.return_value.json.return_value = json_check

        context = {'incident_priority': 'priority_name'}

        priority_not_verified = self._work._get_standardized_priority(context)
        assert not priority_not_verified

    @patch('requests.get')
    def test_get_standardized_priority_not_found(self, get_mock):
        """PagerDutyIncidentOutput - Priority Verify Not Found"""
        # GET /priorities
        get_mock.return_value.status_code = 200
        json_check = {'priorities': [{'id': 'verified_priority_id', 'name': 'not_priority_name'}]}
        get_mock.return_value.json.return_value = json_check

        context = {'incident_priority': 'priority_name'}

        priority_not_verified = self._work._get_standardized_priority(context)
        assert not priority_not_verified

    @patch('requests.get')
    def test_get_standardized_priority_invalid(self, get_mock):
        """PagerDutyIncidentOutput - Priority Verify Invalid"""
        # GET /priorities
        get_mock.return_value.status_code = 200
        json_check = {'not_priorities': [{'id': 'verified_priority_id', 'name': 'priority_name'}]}
        get_mock.return_value.json.return_value = json_check

        context = {'incident_priority': 'priority_name'}

        priority_not_verified = self._work._get_standardized_priority(context)
        assert not priority_not_verified

    @patch('requests.get')
    def test_get_incident_assignment_user_sends_correct_rquest(self, get_mock):
        """PagerDutyIncidentOutput - Incident Assignment User Sends Correct Request"""
        context = {'assigned_user': 'user_to_assign'}
        get_mock.return_value.status_code = 400

        self._work._get_incident_assignments(context)

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

        assigned_value = self._work._get_incident_assignments(context)

        assert assigned_value[0]['assignee']['id'] == 'verified_user_id'
        assert assigned_value[0]['assignee']['type'] == 'user_reference'

    def test_get_incident_escalation_policy_no_default(self):
        """PagerDutyIncidentOutput - Incident Assignment Policy (No Default)"""
        context = {'assigned_policy_id': 'policy_id_to_assign'}

        assigned_value = self._work._get_incident_escalation_policy(context)

        assert assigned_value['id'] == 'policy_id_to_assign'
        assert assigned_value['type'] == 'escalation_policy_reference'

    @patch('requests.get')
    def test_user_verify_success(self, get_mock):
        """PagerDutyIncidentOutput - User Verify Success"""
        get_mock.return_value.status_code = 200
        json_check = {'users': [{'id': 'verified_user_id'}]}
        get_mock.return_value.json.return_value = json_check

        user_verified = self._work._verify_user_exists()
        assert user_verified

    @patch('requests.get')
    def test_user_verify_fail(self, get_mock):
        """PagerDutyIncidentOutput - User Verify Fail"""
        get_mock.return_value.status_code = 200
        json_check = {'not_users': [{'not_id': 'verified_user_id'}]}
        get_mock.return_value.json.return_value = json_check

        user_verified = self._work._verify_user_exists()
        assert not user_verified


@patch('streamalert.alert_processor.outputs.output_base.OutputDispatcher.MAX_RETRY_ATTEMPTS', 1)
@patch('streamalert.alert_processor.outputs.pagerduty.PagerDutyIncidentOutput.BACKOFF_MAX', 0)
@patch('streamalert.alert_processor.outputs.pagerduty.PagerDutyIncidentOutput.BACKOFF_TIME', 0)
class TestPagerDutyRestApiClient:

    @patch('streamalert.alert_processor.outputs.output_base.OutputCredentialsProvider')
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

        class Anything:
            def __eq__(self, _):
                return True

        class VerifyIsCalledWith:
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

        assert note.get('id') == 'created_note_id'

    @patch('requests.post')
    def test_add_note_incident_fail(self, post_mock):
        """PagerDutyIncidentOutput - Add Note to Incident Fail"""
        post_mock.return_value.status_code = 200
        json_note = {'note': {'not_id': 'created_note_id'}}
        post_mock.return_value.json.return_value = json_note

        note = self._api_client.add_note('incident_id', 'this is the note')

        assert not note.get('id')

    @patch('requests.post')
    def test_add_note_incident_bad_request(self, post_mock):
        """PagerDutyIncidentOutput - Add Note to Incident Bad Request"""
        post_mock.return_value.status_code = 400
        json_note = {'note': {'id': 'created_note_id'}}
        post_mock.return_value.json.return_value = json_note

        note = self._api_client.add_note('incident_id', 'this is the note')

        assert not note

    @patch('requests.post')
    def test_add_note_incident_no_response(self, post_mock):
        """PagerDutyIncidentOutput - Add Note to Incident No Response"""
        post_mock.return_value.status_code = 200
        json_note = {}
        post_mock.return_value.json.return_value = json_note

        note = self._api_client.add_note('incident_id', 'this is the note')

        assert not note

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

        assert policy.get('id') == 'PDUDOHF'


class TestJsonHttpProvider:

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
        assert not self._http.get('http://airbnb.com', {'q': 'zz'})

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
        assert not self._http.post('http://airbnb.com', {'q': 'zz'})

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
        assert not self._http.put('http://airbnb.com', {})


class TestWorkContextUnit:
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
        work._update_base_incident = MagicMock(return_value=incident)
        work._create_base_alert_event = MagicMock(return_value=event)
        work._merge_event_into_incident = MagicMock(return_value=merged_incident)
        work._add_incident_note = MagicMock(return_value=note)
        work._add_instability_note = MagicMock(return_value=note)

        self._work = work

    @patch('logging.Logger.error')
    @patch('streamalert.alert_processor.outputs.pagerduty.compose_alert')
    def test_positive_case(self, compose_alert_mock, log_error):
        """PagerDuty WorkContext - Minimum Positive Case"""
        publication = {}
        compose_alert_mock.return_value = publication

        alert = get_alert()
        result = self._work.run(alert, 'descriptor')
        assert result

        log_error.assert_not_called()

    @patch('logging.Logger.error')
    @patch('streamalert.alert_processor.outputs.pagerduty.compose_alert')
    def test_unstable_note_fail(self, compose_alert_mock, log_error):
        """PagerDuty WorkContext - Unstable - Add Note Failed"""
        publication = {}
        compose_alert_mock.return_value = publication

        self._work._add_incident_note = MagicMock(return_value=False)

        alert = get_alert()
        result = self._work.run(alert, 'descriptor')
        assert result

        log_error.assert_called_with(StringThatStartsWith("[test] Failed to add note to incident"))

    @patch('streamalert.alert_processor.outputs.pagerduty.compose_alert')
    def test_unstable_adds_instability_note(self, compose_alert_mock):
        """PagerDuty WorkContext - Unstable - Add Instability Note"""
        publication = {}
        compose_alert_mock.return_value = publication

        self._work._add_incident_note = MagicMock(return_value=False)

        alert = get_alert()
        result = self._work.run(alert, 'descriptor')
        assert result

        self._work._add_instability_note.assert_called_with(
            'ABCDEFGH', ['[test] Failed to add note to incident (ABCDEFGH)']
        )


class StringThatStartsWith(str):
    def __eq__(self, other):
        return other.startswith(self)


class RequestMocker:
    CREATE_EVENT_JSON = {'something': '?'}
    USERS_JSON = {'users': [{'id': 'valid_user_id'}]}
    INCIDENTS_JSON = {'incidents': [{'id': 'incident_id'}]}
    INCIDENT_JSON = {'incident': {'id': 'incident_id'}}
    PRIORITIES_JSON = {'priorities': [{'id': 'priority_id', 'name': 'priority_name'}]}
    EVENT_JSON = {'dedup_key': 'returned_dedup_key'}
    NOTE_JSON = {'note': {'id': 'note_id'}}
    RESPONDER_JSON = {'responder_request': {
        'incident': {'id': 'incident_id'},
        'requester': {'id': 'responder_user_id'},
        'responder_request_targets': []
    }}

    @staticmethod
    def assert_mock_with_no_calls_like(mock, condition):
        calls = mock.call_args_list
        failed = []

        for index, _call in enumerate(calls, start=1):
            args, kwargs = _call
            if condition(*args, **kwargs):
                failed.append(index)

        assert not failed, (f"Failed to assert that mock was not called.\nOut of {len(calls)} calls,"
        f" calls {', '.join([f'#{idx}' for idx in failed])} failed the condition.")

    @classmethod
    def setup_mock(cls, get_mock, conditions=None):
        """Sets up a magic mock to return values based upon the conditions provided

        The "conditions" arg is an array of structures.
        Each structure is another array of exactly 3 elements:

            1) The first element can be one of three types:
                function
                regex
                string

            2) The second element is an integer, the HTTP response code

            3) The third element is a JSON dict, the response of the HTTP request

        When the magic mock is called, it will iterate through each condition to find the first
        condition that matches the given input arguments. It then sets up a mock response object
        and returns it. If all conditions are false, it mocks a 404 response.

        When conditions are omitted, it assumes some defaults that return positive cases.
        """

        if conditions is None:
            conditions = [
                ['/create_event.json', 200, cls.CREATE_EVENT_JSON],
                ['/users', 200, cls.USERS_JSON],
                ['/incidents', 200, cls.INCIDENTS_JSON],
                ['/priorities', 200, cls.PRIORITIES_JSON],
                ['/enqueue', 200, cls.EVENT_JSON],
                ['/notes', 200, cls.NOTE_JSON],
                ['/responder_requests', 200, cls.RESPONDER_JSON],
                [re.compile(r'^.*/incidents/[a-zA-Z0-9_-]+$'), 200, cls.INCIDENT_JSON],
            ]

        def _mocked_call(*args, **kwargs):
            for condition in conditions:
                matcher, status_code, response = condition

                if callable(matcher):
                    # Lambda or function
                    is_condition_match = matcher(*args, **kwargs)
                else:
                    try:
                        # I couldn't find an easy way to determine if a variable was an instance
                        # of a regex type, so this was the best I could do
                        is_condition_match = matcher.match(args[0])
                    except AttributeError:
                        # String
                        is_condition_match = args[0].endswith(matcher)

                if is_condition_match:
                    _mock_response = MagicMock()
                    _mock_response.status_code = status_code
                    _mock_response.json.return_value = response
                    return _mock_response

            _404_response = MagicMock()
            _404_response.status_code = 404
            return _404_response

        get_mock.side_effect = _mocked_call

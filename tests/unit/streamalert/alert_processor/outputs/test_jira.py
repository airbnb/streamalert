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
from unittest.mock import MagicMock, Mock, PropertyMock, patch

from streamalert.alert_processor.outputs.jira import JiraOutput
from tests.unit.streamalert.alert_processor.helpers import get_alert


@patch('streamalert.alert_processor.outputs.output_base.OutputDispatcher.MAX_RETRY_ATTEMPTS', 1)
class TestJiraOutput:
    """Test class for JiraOutput"""
    DESCRIPTOR = 'unit_test_jira'
    SERVICE = 'jira'
    OUTPUT = ':'.join([SERVICE, DESCRIPTOR])
    CREDS = {'username': 'jira@foo.bar',
             'password': 'jirafoobar',
             'url': 'jira.foo.bar',
             'project_key': 'foobar',
             'issue_type': 'Task',
             'aggregate': 'yes'}

    @patch('streamalert.alert_processor.outputs.output_base.OutputCredentialsProvider')
    def setup(self, provider_constructor):
        """Setup before each method"""
        provider = MagicMock()
        provider_constructor.return_value = provider
        provider.load_credentials = Mock(
            side_effect=lambda x: self.CREDS if x == self.DESCRIPTOR else None
        )
        self._provider = provider
        self._dispatcher = JiraOutput(None)
        self._dispatcher._base_url = self.CREDS['url']

    @patch('logging.Logger.info')
    @patch('requests.get')
    @patch('requests.post')
    def test_dispatch_issue_new(self, post_mock, get_mock, log_mock):
        """JiraOutput - Dispatch Success, New Issue"""
        # setup the request to not find an existing issue
        get_mock.return_value.status_code = 200
        get_mock.return_value.json.return_value = {'issues': []}
        # setup the auth and successful creation responses
        auth_resp = {'session': {'name': 'cookie_name', 'value': 'cookie_value'}}
        post_mock.return_value.status_code = 200
        post_mock.return_value.json.side_effect = [auth_resp, {'id': 5000}]

        assert self._dispatcher.dispatch(get_alert(), self.OUTPUT)

        log_mock.assert_called_with('Successfully sent alert to %s:%s',
                                    self.SERVICE, self.DESCRIPTOR)

    @patch('logging.Logger.info')
    @patch('requests.get')
    @patch('requests.post')
    def test_dispatch_issue_existing(self, post_mock, get_mock, log_mock):
        """JiraOutput - Dispatch Success, Existing Issue"""
        # setup the request to find an existing issue
        get_mock.return_value.status_code = 200
        existing_issues = {'issues': [{'fields': {'summary': 'Bogus'}, 'id': '5000'}]}
        get_mock.return_value.json.return_value = existing_issues
        auth_resp = {'session': {'name': 'cookie_name', 'value': 'cookie_value'}}
        # setup the auth and successful creation responses
        post_mock.return_value.status_code = 200
        post_mock.return_value.json.side_effect = [auth_resp, {'id': 5000}]

        assert self._dispatcher.dispatch(get_alert(), self.OUTPUT)

        log_mock.assert_called_with('Successfully sent alert to %s:%s',
                                    self.SERVICE, self.DESCRIPTOR)

    @patch('logging.Logger.info')
    @patch('requests.get')
    @patch('requests.post')
    def test_dispatch_issue_empty_comment(self, post_mock, get_mock, log_mock):
        """JiraOutput - Dispatch Success, Empty Comment"""
        # setup the request to find an existing issue
        get_mock.return_value.status_code = 200
        existing_issues = {'issues': [{'fields': {'summary': 'Bogus'}, 'id': '5000'}]}
        get_mock.return_value.json.return_value = existing_issues
        # setup the auth and successful creation responses
        auth_resp = {'session': {'name': 'cookie_name', 'value': 'cookie_value'}}
        type(post_mock.return_value).status_code = PropertyMock(side_effect=[200, 200, 200])
        post_mock.return_value.json.side_effect = [auth_resp, {}, {'id': 5000}]

        assert self._dispatcher.dispatch(get_alert(), self.OUTPUT)

        log_mock.assert_called_with('Successfully sent alert to %s:%s',
                                    self.SERVICE, self.DESCRIPTOR)

    @patch('requests.get')
    def test_get_comments_success(self, get_mock):
        """JiraOutput - Get Comments, Success"""
        # setup successful get comments response
        get_mock.return_value.status_code = 200
        expected_result = [{}, {}]
        get_mock.return_value.json.return_value = {'comments': expected_result}

        self._dispatcher._load_creds('jira')
        assert self._dispatcher._get_comments('5000') == expected_result

    @patch('requests.get')
    def test_get_comments_empty_success(self, get_mock):
        """JiraOutput - Get Comments, Success Empty"""
        # setup successful get comments empty response
        get_mock.return_value.status_code = 200
        get_mock.return_value.json.return_value = {}

        self._dispatcher._load_creds('jira')
        assert self._dispatcher._get_comments('5000') == []

    @patch('requests.get')
    def test_get_comments_failure(self, get_mock):
        """JiraOutput - Get Comments, Failure"""
        # setup successful get comments response
        get_mock.return_value.status_code = 400

        self._dispatcher._load_creds('jira')
        assert self._dispatcher._get_comments('5000') == []

    @patch('requests.get')
    def test_search_failure(self, get_mock):
        """JiraOutput - Search, Failure"""
        # setup successful search
        get_mock.return_value.status_code = 400

        self._dispatcher._load_creds('jira')
        assert self._dispatcher._search_jira('foobar') == []

    @patch('logging.Logger.error')
    @patch('requests.post')
    def test_auth_failure(self, post_mock, log_mock):
        """JiraOutput - Auth, Failure"""
        # setup unsuccesful auth response
        post_mock.return_value.status_code = 400
        post_mock.return_value.content = 'content'
        post_mock.return_value.json.return_value = {}

        assert not self._dispatcher.dispatch(get_alert(), self.OUTPUT)

        log_mock.assert_called_with('Failed to send alert to %s:%s', self.SERVICE, self.DESCRIPTOR)

    @patch('logging.Logger.error')
    @patch('requests.post')
    def test_auth_empty_response(self, post_mock, log_mock):
        """JiraOutput - Auth, Failure Empty Response"""
        # setup unsuccesful auth response
        post_mock.return_value.status_code = 200
        post_mock.return_value.json.return_value = {}

        assert not self._dispatcher.dispatch(get_alert(), self.OUTPUT)

        log_mock.assert_called_with('Failed to send alert to %s:%s', self.SERVICE, self.DESCRIPTOR)

    @patch('logging.Logger.error')
    @patch('requests.get')
    @patch('requests.post')
    def test_issue_creation_failure(self, post_mock, get_mock, log_mock):
        """JiraOutput - Issue Creation, Failure"""
        # setup the successful search response - no results
        get_mock.return_value.status_code = 200
        get_mock.return_value.json.return_value = {'issues': []}
        # setup successful auth response and failed issue creation
        type(post_mock.return_value).status_code = PropertyMock(side_effect=[200, 400])
        auth_resp = {'session': {'name': 'cookie_name', 'value': 'cookie_value'}}
        post_mock.return_value.content = 'some bad content'
        post_mock.return_value.json.side_effect = [auth_resp, {}]

        assert not self._dispatcher.dispatch(get_alert(), self.OUTPUT)

        log_mock.assert_called_with('Failed to send alert to %s:%s', self.SERVICE, self.DESCRIPTOR)

    @patch('logging.Logger.error')
    @patch('requests.get')
    @patch('requests.post')
    def test_issue_creation_empty_search(self, post_mock, get_mock, log_mock):
        """JiraOutput - Issue Creation, Failure Empty Search"""
        # setup the successful search response - empty response
        get_mock.return_value.status_code = 200
        get_mock.return_value.json.return_value = {}
        # setup successful auth response and failed issue creation
        type(post_mock.return_value).status_code = PropertyMock(side_effect=[200, 400])
        auth_resp = {'session': {'name': 'cookie_name', 'value': 'cookie_value'}}
        post_mock.return_value.content = 'some bad content'
        post_mock.return_value.json.side_effect = [auth_resp, {}]

        assert not self._dispatcher.dispatch(get_alert(), self.OUTPUT)

        log_mock.assert_called_with('Failed to send alert to %s:%s', self.SERVICE, self.DESCRIPTOR)

    @patch('logging.Logger.error')
    @patch('requests.get')
    @patch('requests.post')
    def test_issue_creation_empty_response(self, post_mock, get_mock, log_mock):
        """JiraOutput - Issue Creation, Failure Empty Response"""
        # setup the successful search response - no results
        get_mock.return_value.status_code = 200
        get_mock.return_value.json.return_value = {'issues': []}
        # setup successful auth response and failed issue creation - empty response
        type(post_mock.return_value).status_code = PropertyMock(side_effect=[200, 200])
        auth_resp = {'session': {'name': 'cookie_name', 'value': 'cookie_value'}}
        post_mock.return_value.json.side_effect = [auth_resp, {}]

        assert not self._dispatcher.dispatch(get_alert(), self.OUTPUT)

        log_mock.assert_called_with('Failed to send alert to %s:%s', self.SERVICE, self.DESCRIPTOR)

    @patch('logging.Logger.error')
    @patch('requests.get')
    @patch('requests.post')
    def test_comment_creation_failure(self, post_mock, get_mock, log_mock):
        """JiraOutput - Comment Creation, Failure"""
        # setup successful search response
        get_mock.return_value.status_code = 200
        existing_issues = {'issues': [{'fields': {'summary': 'Bogus'}, 'id': '5000'}]}
        get_mock.return_value.json.return_value = existing_issues
        # setup successful auth, failed comment creation, and successful issue creation
        type(post_mock.return_value).status_code = PropertyMock(side_effect=[200, 400, 200])
        auth_resp = {'session': {'name': 'cookie_name', 'value': 'cookie_value'}}
        post_mock.return_value.json.side_effect = [auth_resp, {'id': 6000}]

        assert self._dispatcher.dispatch(get_alert(), self.OUTPUT)

        log_mock.assert_called_with('Encountered an error when adding alert to existing Jira '
                                    'issue %s. Attempting to create new Jira issue.', 5000)

    @patch('logging.Logger.error')
    def test_dispatch_bad_descriptor(self, log_error_mock):
        """JiraOutput - Dispatch Failure, Bad Descriptor"""
        assert not self._dispatcher.dispatch(
            get_alert(), ':'.join([self.SERVICE, 'bad_descriptor']))

        log_error_mock.assert_called_with('Failed to send alert to %s:%s',
                                          self.SERVICE, 'bad_descriptor')

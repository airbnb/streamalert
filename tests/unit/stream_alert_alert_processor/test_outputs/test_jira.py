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
from mock import call, patch, PropertyMock
from moto import mock_s3, mock_kms
from nose.tools import assert_equal

from stream_alert.alert_processor.outputs.jira import JiraOutput
from stream_alert_cli.helpers import put_mock_creds
from tests.unit.stream_alert_alert_processor import CONFIG, FUNCTION_NAME, KMS_ALIAS, REGION
from tests.unit.stream_alert_alert_processor.helpers import (
    get_alert,
    remove_temp_secrets
)


@mock_s3
@mock_kms
class TestJiraOutput(object):
    """Test class for PhantomOutput"""
    @classmethod
    def setup_class(cls):
        """Setup the class before any methods"""
        cls.__service = 'jira'
        cls.__descriptor = 'unit_test_jira'
        cls.__dispatcher = JiraOutput(REGION, FUNCTION_NAME, CONFIG)

    @classmethod
    def teardown_class(cls):
        """Teardown the class after all methods"""
        cls.__dispatcher = None

    def _setup_dispatch(self):
        """Helper for setting up JiraOutput dispatch"""
        remove_temp_secrets()

        output_name = self.__dispatcher.output_cred_name(self.__descriptor)

        creds = {'username': 'jira@foo.bar',
                 'password': 'jirafoobar',
                 'url': 'jira.foo.bar',
                 'project_key': 'foobar',
                 'issue_type': 'Task',
                 'aggregate': 'yes'}

        put_mock_creds(output_name, creds, self.__dispatcher.secrets_bucket, REGION, KMS_ALIAS)

        return get_alert()

    @patch('logging.Logger.info')
    @patch('requests.get')
    @patch('requests.post')
    def test_dispatch_issue_new(self, post_mock, get_mock, log_mock):
        """JiraOutput dispatch success, new issue"""
        alert = self._setup_dispatch()
        # setup the request to not find an existing issue
        get_mock.return_value.status_code = 200
        get_mock.return_value.json.return_value = {'issues': []}
        # setup the auth and successful creation responses
        auth_resp = {'session': {'name': 'cookie_name', 'value': 'cookie_value'}}
        post_mock.return_value.status_code = 200
        post_mock.return_value.json.side_effect = [auth_resp, {'id': 5000}]

        self.__dispatcher.dispatch(descriptor=self.__descriptor,
                                   rule_name='rule_name',
                                   alert=alert)

        log_mock.assert_called_with('Successfully sent alert to %s', self.__service)

    @patch('logging.Logger.info')
    @patch('requests.get')
    @patch('requests.post')
    def test_dispatch_issue_existing(self, post_mock, get_mock, log_mock):
        """JiraOutput dispatch success, existing issue"""
        alert = self._setup_dispatch()
        # setup the request to find an existing issue
        get_mock.return_value.status_code = 200
        existing_issues = {'issues': [{'fields': {'summary': 'Bogus'}, 'id': '5000'}]}
        get_mock.return_value.json.return_value = existing_issues
        auth_resp = {'session': {'name': 'cookie_name', 'value': 'cookie_value'}}
        # setup the auth and successful creation responses
        post_mock.return_value.status_code = 200
        post_mock.return_value.json.side_effect = [auth_resp, {'id': 5000}]

        self.__dispatcher.dispatch(descriptor=self.__descriptor,
                                   rule_name='rule_name',
                                   alert=alert)

        log_mock.assert_called_with('Successfully sent alert to %s', self.__service)

    @patch('requests.get')
    def test_get_comments_success(self, get_mock):
        """JiraOutput get comments success"""
        # setup successful get comments response
        get_mock.return_value.status_code = 200
        get_mock.return_value.json.return_value = {'comments': [{}, {}]}

        self.__dispatcher._load_creds('jira')
        resp = self.__dispatcher._get_comments('5000')
        assert_equal(resp, [{}, {}])

    @patch('requests.get')
    def test_get_comments_failure(self, get_mock):
        """JiraOutput get comments failure"""
        # setup successful get comments response
        get_mock.return_value.status_code = 400

        self.__dispatcher._load_creds('jira')
        resp = self.__dispatcher._get_comments('5000')
        assert_equal(resp, [])

    @patch('requests.get')
    def test_search_failure(self, get_mock):
        """JiraOutput search failure"""
        # setup successful get comments response
        get_mock.return_value.status_code = 400

        self.__dispatcher._load_creds('jira')
        resp = self.__dispatcher._search_jira('foobar')
        assert_equal(resp, [])

    @patch('logging.Logger.error')
    @patch('requests.post')
    def test_auth_failure(self, post_mock, log_mock):
        """JiraOutput auth failure"""
        alert = self._setup_dispatch()

        # setup unsuccesful auth response
        post_mock.return_value.status_code = 400
        post_mock.return_value.content = '{}'
        post_mock.return_value.json.return_value = dict()

        self.__dispatcher.dispatch(descriptor=self.__descriptor,
                                   rule_name='rule_name',
                                   alert=alert)

        log_mock.assert_has_calls([call('Encountered an error while sending to %s:\n%s',
                                        'jira', '{}'),
                                   call('Failed to authenticate to Jira'),
                                   call('Failed to send alert to %s', self.__service)])

    @patch('logging.Logger.error')
    @patch('requests.get')
    @patch('requests.post')
    def test_issue_creation_failure(self, post_mock, get_mock, log_mock):
        """JiraOutput issue creation failure"""
        alert = self._setup_dispatch()
        # setup the successful search response - no results
        get_mock.return_value.status_code = 200
        get_mock.return_value.json.return_value = {'issues': []}
        # setup successful auth response and failed issue creation
        auth_resp = {'session': {'name': 'cookie_name', 'value': 'cookie_value'}}
        type(post_mock.return_value).status_code = PropertyMock(side_effect=[200, 400])
        post_mock.return_value.content = '{}'
        post_mock.return_value.json.side_effect = [auth_resp, dict()]

        self.__dispatcher.dispatch(descriptor=self.__descriptor,
                                   rule_name='rule_name',
                                   alert=alert)

        log_mock.assert_has_calls([call('Encountered an error while sending to %s:\n%s',
                                        self.__service, '{}'),
                                   call('Failed to send alert to %s', self.__service)])

    @patch('logging.Logger.error')
    @patch('requests.get')
    @patch('requests.post')
    def test_comment_creation_failure(self, post_mock, get_mock, log_mock):
        """JiraOutput comment creation failure"""
        alert = self._setup_dispatch()
        # setup successful search response
        get_mock.return_value.status_code = 200
        existing_issues = {'issues': [{'fields': {'summary': 'Bogus'}, 'id': '5000'}]}
        get_mock.return_value.json.return_value = existing_issues
        auth_resp = {'session': {'name': 'cookie_name', 'value': 'cookie_value'}}
        # setup successful auth, failed comment creation, and successful issue creation
        type(post_mock.return_value).status_code = PropertyMock(side_effect=[200, 400, 200])
        post_mock.return_value.content = '{}'
        post_mock.return_value.json.side_effect = [auth_resp, {'id': 6000}]

        self.__dispatcher.dispatch(descriptor=self.__descriptor,
                                   rule_name='rule_name',
                                   alert=alert)

        log_mock.assert_called_with('Encountered an error when adding alert to existing Jira '
                                    'issue %s. Attempting to create new Jira issue.', 5000)

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
import json
import os
from collections import OrderedDict

from streamalert.alert_processor.helpers import compose_alert
from streamalert.alert_processor.outputs.output_base import (
    OutputDispatcher, OutputProperty, OutputRequestFailure, StreamAlertOutput)
from streamalert.shared.logger import get_logger

LOGGER = get_logger(__name__)


@StreamAlertOutput
class JiraOutput(OutputDispatcher):
    """JiraOutput handles all alert dispatching for Jira"""
    __service__ = 'jira'

    DEFAULT_HEADERS = {'Content-Type': 'application/json'}
    LOGIN_ENDPOINT = 'rest/auth/1/session'
    SEARCH_ENDPOINT = 'rest/api/2/search'
    ISSUE_ENDPOINT = 'rest/api/2/issue'
    COMMENT_ENDPOINT = 'rest/api/2/issue/{}/comment'

    def __init__(self, *args, **kwargs):
        OutputDispatcher.__init__(self, *args, **kwargs)
        self._base_url = None
        self._verify_ssl = False
        self._auth_cookie = None

    @classmethod
    def get_user_defined_properties(cls):
        """Get properties that must be assigned by the user when configuring a new Jira
        output.  This should be sensitive or unique information for this use-case that needs
        to come from the user.

        Every output should return a dict that contains a 'descriptor' with a description of the
        integration being configured.

        Jira requires a username, password, URL, project key, and issue type for alert dispatching.
        These values should be masked during input and are credential requirements.

        An additional parameter 'aggregate' is used to determine if alerts are aggregated into a
        single Jira issue based on the StreamAlert rule.

        Returns:
            OrderedDict: Contains various OutputProperty items
        """
        return OrderedDict([
            ('descriptor',
             OutputProperty(description='a short and unique descriptor for this '
                            'Jira integration')),
            ('username',
             OutputProperty(description='the Jira username', mask_input=True,
                            cred_requirement=True)),
            ('password',
             OutputProperty(description='the Jira password', mask_input=True,
                            cred_requirement=True)),
            # Example: "https://jira.mywebsite.com"
            (
                'url',
                OutputProperty(
                    description='the Jira REST API base url',
                    mask_input=True,
                    input_restrictions={' '},  # include this or ":" will be invalid
                    cred_requirement=True)),
            ('project_key',
             OutputProperty(description='the Jira project key',
                            mask_input=False,
                            cred_requirement=True)),
            ('issue_type',
             OutputProperty(description='the Jira issue type',
                            mask_input=False,
                            cred_requirement=True)),
            ('aggregate',
             OutputProperty(description='the Jira aggregation behavior to aggregate '
                            'alerts by rule name (yes/no)',
                            mask_input=False,
                            cred_requirement=True)),
            # When aggregation is enabled, it will fuzzy-search any JIRA ticket that best-matches
            # the "summary ~ ..." statement, within the project key. For each matching rule,
            # instead of creating new JIRA tasks over and over, it will instead opt to append a
            # comment to a similar(ish) JIRA task.
            #
            # However, this can result in  very long-lived JIRA tickets getting tons of comments
            # appended on. This optional parameter allows users to specify an additional JQL clause
            # to filter out these older tickets, encouraging new JIRA tasks to be created from
            # time to time. It can also be used to increase the accuracy of finding the parent
            # task (maybe filtering on a component) in case you find the StreamAlert integration
            # is appending comments to unrelated issues.
            #
            # Example: A highly effective JQL suffix is "created > startOfWeek(-1w)"
            ('aggregation_additional_jql',
             OutputProperty(description='when aggregation is enabled, provide additional JQL '
                            'clause to filter out older/outdated issues',
                            mask_input=False,
                            input_restrictions={},
                            cred_requirement=True)),
            ('ssl_verify',
             OutputProperty(description='do clientside ssl cert verification (yes/no)',
                            mask_input=False,
                            cred_requirement=True)),
            # For example, if your JIRA project requires a custom field called "custom_field_1",
            # you can set the following json-encoded string in this:
            # {"custom_field_1": {"value": "FooBar"}}
            #
            # These fields are DEFAULT values. You can still override them using the
            # @jira.additional_fields publisher parameter.
            ('additional_required_issue_fields',
             OutputProperty(description='when a JIRA project has additional required fields, '
                            'provide them here, as a json-encoded string',
                            mask_input=False,
                            input_restrictions={},
                            cred_requirement=True))
        ])

    @classmethod
    def _get_default_headers(cls):
        """Class method to be used to pass the default headers"""
        return cls.DEFAULT_HEADERS.copy()

    def _get_headers(self):
        """Instance method used to pass the default headers plus the auth cookie"""
        return dict(self._get_default_headers(), **{'cookie': self._auth_cookie})

    def _search_jira(self, jql, fields=None, max_results=100, validate_query=True):
        """Search Jira for issues using a JQL query

        Args:
            jql (str): The JQL query
            fields (list): List of fields to return for each issue
            max_results (int): Maximum number of results to return
            validate_query (bool): Whether to validate the JQL query or not

        Returns:
            list: list of issues matching JQL query
        """
        search_url = os.path.join(self._base_url, self.SEARCH_ENDPOINT)
        params = {
            'jql': jql,
            'maxResults': max_results,
            'validateQuery': validate_query,
            'fields': fields
        }
        try:
            resp = self._get_request_retry(search_url,
                                           params=params,
                                           headers=self._get_headers(),
                                           verify=self._verify_ssl)
        except OutputRequestFailure:
            return []

        response = resp.json()
        return response.get('issues', []) if response else []

    def _create_comment(self, issue_id, comment):
        """Add a comment to an existing issue

        Args:
            issue_id (str): The existing issue ID or key
            comment (str): The body of the comment

        Returns:
            int: ID of the created comment or False if unsuccessful
        """
        comment_url = os.path.join(self._base_url, self.COMMENT_ENDPOINT.format(issue_id))
        try:
            resp = self._post_request_retry(comment_url,
                                            data={'body': comment},
                                            headers=self._get_headers(),
                                            verify=self._verify_ssl)
        except OutputRequestFailure:
            return False

        response = resp.json()
        return response.get('id', False) if response else False

    def _get_comments(self, issue_id):
        """Get all comments for an existing Jira issue

        Args:
            issue_id (str): The existing issue ID or key

        Returns:
            list: List of comments associated with a Jira issue
        """
        comment_url = os.path.join(self._base_url, self.COMMENT_ENDPOINT.format(issue_id))
        try:
            resp = self._get_request_retry(comment_url,
                                           headers=self._get_headers(),
                                           verify=self._verify_ssl)
        except OutputRequestFailure:
            return []

        response = resp.json()
        return response.get('comments', []) if response else []

    def _get_existing_issue(self, issue_summary, project_key, additional_jql):
        """Find an existing Jira issue based on the issue summary

        Args:
            issue_summary (str): The Jira issue summary
            project_key (str): The Jira project to search
            additional_jql (str): Additional JQL statement to filter by

        Returns:
            int: ID of the found issue or False if existing issue does not exist
        """
        jql = f'summary ~ "{issue_summary}" and project="{project_key}"{f" AND {additional_jql}" if additional_jql else ""}'

        LOGGER.debug('Aggregation using JQL: (%s)', jql)
        resp = self._search_jira(jql, fields=['id', 'summary'], max_results=1)
        jira_id = False

        try:
            jira_id = int(resp[0]['id'])
        except (IndexError, KeyError):
            LOGGER.debug('Existing Jira issue not found')

        return jira_id

    def _create_issue(self, summary, project_key, issue_type, description, additional_fields):
        """Create a Jira issue to write alerts to. Alert is written to the "description"
        field of an issue.

        Args:
            summary (str): The name of the Jira issue
            project_key (str): The Jira project key which issues will be associated with
            issue_type (str): The type of issue being created
            description (str): The body of text which describes the issue
            additional_fields (dict):
                Additional fields to set with the integration. This can vary greatly from
                project to project, so be wary of which fields are available. You can use the
                /issue/createmeta?projectKeys=CSIRT endpoint to discover which fields are available
                (and which ones are required) for your specific project.

        Returns:
            int: ID of the created issue or False if unsuccessful
        """
        issue_url = os.path.join(self._base_url, self.ISSUE_ENDPOINT)
        issue_body = {
            'fields': {
                'project': {
                    'key': project_key
                },
                'summary': summary,
                'description': description,
                'issuetype': {
                    'name': issue_type
                },
                **additional_fields
            }
        }
        try:
            resp = self._post_request_retry(issue_url,
                                            data=issue_body,
                                            headers=self._get_headers(),
                                            verify=self._verify_ssl)
        except OutputRequestFailure:
            return False

        response = resp.json()
        return response.get('id', False) if response else False

    def _establish_session(self, username, password):
        """Establish a cookie based Jira session via basic user auth.

        Args:
            username (str): The Jira username used for establishing the session
            password (str): The Jira password used for establishing the session

        Returns:
            str: Header value intended to be passed with every subsequent Jira request
                 or False if unsuccessful
        """
        login_url = os.path.join(self._base_url, self.LOGIN_ENDPOINT)
        auth_info = {'username': username, 'password': password}

        try:
            resp = self._post_request_retry(login_url,
                                            data=auth_info,
                                            headers=self._get_default_headers(),
                                            verify=self._verify_ssl)
        except OutputRequestFailure:
            LOGGER.error("Failed to authenticate to Jira")
            return False

        resp_dict = resp.json()
        return f"{resp_dict['session']['name']}={resp_dict['session']['value']}" if resp_dict else False

    def _dispatch(self, alert, descriptor):
        """Send alert to Jira

        Publishing:
            This output uses a default issue summary and sends the entire publication into the
            issue body as a {{code}} block. To override:

            - @jira.issue_summary (str):
                    Overrides the issue title that shows up at the top on the JIRA UI

            - @jira.description (str):
                    Send your own custom description. Remember: This field is in JIRA's syntax,
                    so it supports their custom markdown-like formatting and respects newline
                    characters (e.g. \n).

            - @jira.additional_fields (dict):
                    A structure of additional fields to add to Create Issue API calls. For example,
                    if you have a custom field for severity, you could specify it in this dict
                    like so:

                        {
                          "custom_field_1122": {
                            "value": "Low"
                          }
                        }


        Args:
            alert (Alert): Alert instance which triggered a rule
            descriptor (str): Output descriptor

        Returns:
            bool: True if alert was sent successfully, False otherwise
        """
        creds = self._load_creds(descriptor)
        if not creds:
            return False

        publication = compose_alert(alert, self, descriptor)

        # Presentation defaults
        default_issue_summary = f'StreamAlert {alert.rule_name}'
        default_alert_body = '{{code:JSON}}{}{{code}}'.format(
            json.dumps(
                publication,
                indent=2,
                sort_keys=True,
            ))

        # True Presentation values
        issue_summary = publication.get('@jira.issue_summary', default_issue_summary)
        description = publication.get('@jira.description', default_alert_body)

        issue_id = None
        comment_id = None

        self._base_url = creds['url']
        self._verify_ssl = creds.get('verify_ssl', '').lower() == 'yes'
        self._auth_cookie = self._establish_session(creds['username'], creds['password'])

        # Validate successful authentication
        if not self._auth_cookie:
            return False

        # If aggregation is enabled, attempt to add alert to an existing issue. If a
        # failure occurs in this block, creation of a new Jira issue will be attempted.
        if creds.get('aggregate', '').lower() == 'yes':
            issue_id = self._get_existing_issue(issue_summary, creds['project_key'],
                                                creds.get('aggregation_additional_jql', ''))
            if issue_id:
                comment_id = self._create_comment(issue_id, description)
                if comment_id:
                    LOGGER.debug('Sending alert to an existing Jira issue %s with comment %s',
                                 issue_id, comment_id)
                    return True
                LOGGER.error(
                    'Encountered an error when adding alert to existing '
                    'Jira issue %s. Attempting to create new Jira issue.', issue_id)

        # Create a new Jira issue
        required_fields_json = creds.get('additional_required_issue_fields')
        additional_required_fields = (json.loads(required_fields_json)
                                      if required_fields_json else {})

        additional_fields = {
            **additional_required_fields,
            **publication.get('@jira.additional_fields', {}),
        }
        issue_id = self._create_issue(issue_summary, creds['project_key'], creds['issue_type'],
                                      description, additional_fields)
        if issue_id:
            LOGGER.debug('Sending alert to a new Jira issue %s', issue_id)

        return bool(issue_id or comment_id)

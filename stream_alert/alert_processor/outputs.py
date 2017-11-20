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
# pylint: disable=too-many-lines
from abc import abstractmethod
import cgi
from collections import OrderedDict
from datetime import datetime
import json
import os
import uuid

import backoff
from botocore.exceptions import ClientError
import boto3

from stream_alert.alert_processor import LOGGER
from stream_alert.alert_processor.output_base import OutputProperty, StreamOutputBase
from stream_alert.shared.backoff_handlers import (
    backoff_handler,
    success_handler,
    giveup_handler
)

# STREAM_OUTPUTS will contain each subclass of the StreamOutputBase
# All included subclasses are designated using the '@output' class decorator
# The keys are the name of the service and the value is the class itself
# {cls.__service__: <cls>}

# pylint: disable=too-many-lines
STREAM_OUTPUTS = {}


def output(cls):
    """Class decorator to register all stream outputs"""
    STREAM_OUTPUTS[cls.__service__] = cls


def get_output_dispatcher(service, region, function_name, config):
    """Returns the subclass that should handle this particular service"""
    try:
        return STREAM_OUTPUTS[service](region, function_name, config)
    except KeyError:
        LOGGER.error('designated output service [%s] does not exist', service)

@output
class PagerDutyOutput(StreamOutputBase):
    """PagerDutyOutput handles all alert dispatching for PagerDuty Events API v1"""
    __service__ = 'pagerduty'

    @classmethod
    def _get_default_properties(cls):
        """Get the standard url used for PagerDuty. This value the same for everyone, so
        is hard-coded here and does not need to be configured by the user
        Returns:
            dict: Contains various default items for this output (ie: url)
        """
        return {'url': 'https://events.pagerduty.com/generic/2010-04-15/create_event.json'}

    def get_user_defined_properties(self):
        """Get properties that must be asssigned by the user when configuring a new PagerDuty
        output.  This should be sensitive or unique information for this use-case that needs
        to come from the user.
        Every output should return a dict that contains a 'descriptor' with a description of the
        integration being configured.
        PagerDuty also requires a service_key that represnts this integration. This
        value should be masked during input and is a credential requirement.
        Returns:
            OrderedDict: Contains various OutputProperty items
        """
        return OrderedDict([
            ('descriptor',
             OutputProperty(description='a short and unique descriptor for this '
                                        'PagerDuty integration')),
            ('service_key',
             OutputProperty(description='the service key for this PagerDuty integration',
                            mask_input=True,
                            cred_requirement=True))
        ])

    def dispatch(self, **kwargs):
        """Send alert to Pagerduty
        Args:
            **kwargs: consists of any combination of the following items:
                descriptor (str): Service descriptor (ie: slack channel, pd integration)
                rule_name (str): Name of the triggered rule
                alert (dict): Alert relevant to the triggered rule
        """
        creds = self._load_creds(kwargs['descriptor'])
        if not creds:
            return self._log_status(False)

        message = 'StreamAlert Rule Triggered - {}'.format(kwargs['rule_name'])
        rule_desc = kwargs['alert']['rule_description']
        details = {
            'rule_description': rule_desc,
            'record': kwargs['alert']['record']
        }
        data = {
            'service_key': creds['service_key'],
            'event_type': 'trigger',
            'description': message,
            'details': details,
            'client': 'StreamAlert'
        }

        resp = self._post_request(creds['url'], data, None, True)
        success = self._check_http_response(resp)

        return self._log_status(success)

@output
class PagerDutyOutputV2(StreamOutputBase):
    """PagerDutyOutput handles all alert dispatching for PagerDuty Events API v2"""
    __service__ = 'pagerduty-v2'

    @classmethod
    def _get_default_properties(cls):
        """Get the standard url used for PagerDuty Events API v2. This value the same for
        everyone, so is hard-coded here and does not need to be configured by the user

        Returns:
            dict: Contains various default items for this output (ie: url)
        """
        return {'url': 'https://events.pagerduty.com/v2/enqueue'}

    def get_user_defined_properties(self):
        """Get properties that must be asssigned by the user when configuring a new PagerDuty
        event output. This should be sensitive or unique information for this use-case that
        needs to come from the user.

        Every output should return a dict that contains a 'descriptor' with a description of the
        integration being configured.

        PagerDuty also requires a routing_key that represents this integration. This
        value should be masked during input and is a credential requirement.

        Returns:
            OrderedDict: Contains various OutputProperty items
        """
        return OrderedDict([
            ('descriptor',
             OutputProperty(description='a short and unique descriptor for this '
                                        'PagerDuty integration')),
            ('routing_key',
             OutputProperty(description='the routing key for this PagerDuty integration',
                            mask_input=True,
                            cred_requirement=True))
        ])

    def dispatch(self, **kwargs):
        """Send alert to Pagerduty

        Args:
            **kwargs: consists of any combination of the following items:
                descriptor (str): Service descriptor (ie: slack channel, pd integration)
                rule_name (str): Name of the triggered rule
                alert (dict): Alert relevant to the triggered rule
        """
        creds = self._load_creds(kwargs['descriptor'])
        if not creds:
            return self._log_status(False)

        summary = 'StreamAlert Rule Triggered - {}'.format(kwargs['rule_name'])

        details = {
            'rule_description': kwargs['alert']['rule_description'],
            'record': kwargs['alert']['record']
        }
        payload = {
            'summary': summary,
            'source': kwargs['alert']['log_source'],
            'severity': 'critical',
            'custom_details': details
        }
        data = {
            'routing_key': creds['routing_key'],
            'payload': payload,
            'event_action': 'trigger',
            'client': 'StreamAlert'
        }

        resp = self._post_request(creds['url'], data, None, True)
        success = self._check_http_response(resp)

        return self._log_status(success)

@output
class PagerDutyIncidentOutput(StreamOutputBase):
    """PagerDutyIncidentOutput handles all alert dispatching for PagerDuty Incidents API v2"""
    __service__ = 'pagerduty-incident'
    INCIDENTS_ENDPOINT = 'incidents'
    USERS_ENDPOINT = 'users'
    POLICIES_ENDPOINT = 'escalation_policies'
    SERVICES_ENDPOINT = 'services'

    def __init__(self, *args, **kwargs):
        StreamOutputBase.__init__(self, *args, **kwargs)
        self._base_url = None
        self._headers = None
        self._escalation_policy = None

    @classmethod
    def _get_default_properties(cls):
        """Get the standard url used for PagerDuty Incidents API v2. This value the same for
        everyone, so is hard-coded here and does not need to be configured by the user

        Returns:
            dict: Contains various default items for this output (ie: url)
        """
        return {'api': 'https://api.pagerduty.com'}

    def get_user_defined_properties(self):
        """Get properties that must be asssigned by the user when configuring a new PagerDuty
        event output. This should be sensitive or unique information for this use-case that
        needs to come from the user.

        Every output should return a dict that contains a 'descriptor' with a description of the
        integration being configured.

        PagerDuty also requires a routing_key that represents this integration. This
        value should be masked during input and is a credential requirement.

        Returns:
            OrderedDict: Contains various OutputProperty items
        """
        return OrderedDict([
            ('descriptor',
             OutputProperty(description='a short and unique descriptor for this '
                                        'PagerDuty integration')),
            ('token',
             OutputProperty(description='the token for this PagerDuty integration',
                            mask_input=True,
                            cred_requirement=True)),
            ('service_key',
             OutputProperty(description='the service key for this PagerDuty integration',
                            mask_input=True,
                            cred_requirement=True)),
            ('escalation_policy',
             OutputProperty(description='the name of the default escalation policy')),
            ('email_from',
             OutputProperty(description='valid user email from the PagerDuty '
                                        'account linked to the token',
                            cred_requirement=True))
        ])

    @staticmethod
    def _get_endpoint(base_url, endpoint):
        """Helper to get the full url for a PagerDuty Incidents endpoint.

        Args:
            base_url (str): Base URL for the API
            endpoint (str): Endpoint that we want the full URL for

        Returns:
            str: Full URL of the provided endpoint
        """
        return os.path.join(base_url, endpoint)

    def _check_exists(self, filter_str, url, target_key, get_id=True):
        """Generic method to run a search in the PagerDuty REST API and return the id
        of the first occurence from the results.

        Args:
            filter_str (str): The query filter to search for in the API
            url (str): The url to send the requests to in the API
            target_key (str): The key to extract in the returned results
            get_id (boolean): Whether to generate a dict with result and reference

        Returns:
            str: ID of the targeted element that matches the provided filter or
                 True/False whether a matching element exists or not.
        """
        params = {
            'query': '{}'.format(filter_str)
        }
        resp = self._get_request(url, params, self._headers, False)

        if not self._check_http_response(resp):
            return False

        response = resp.json()
        if not response:
            return False

        if not get_id:
            return True

        # If there are results, get the first occurence from the list
        return response[target_key][0]['id'] if target_key in response else False

    def _user_verify(self, user, get_id=True):
        """Method to verify the existance of an user with the API

        Args:
            user (str): User to query about in the API.
            get_id (boolean): Whether to generate a dict with result and reference

        Returns:
            dict or False: JSON object be used in the API call, containing the user_id
                           and user_reference. False if user is not found
        """
        return self._item_verify(user, self.USERS_ENDPOINT, 'user_reference', get_id)

    def _policy_verify(self, policy, default_policy):
        """Method to verify the existance of a escalation policy with the API

        Args:
            policy (str): Escalation policy to query about in the API
            default_policy (str): Escalation policy to use if the first one is not verified

        Returns:
            dict: JSON object be used in the API call, containing the policy_id
                  and escalation_policy_reference
        """
        verified = self._item_verify(policy, self.POLICIES_ENDPOINT, 'escalation_policy_reference')

        # If the escalation policy provided is not verified in the API, use the default
        if verified:
            return verified

        return self._item_verify(default_policy, self.POLICIES_ENDPOINT,
                                 'escalation_policy_reference')

    def _service_verify(self, service):
        """Method to verify the existance of a service with the API

        Args:
            service (str): Service to query about in the API

        Returns:
            dict: JSON object be used in the API call, containing the service_id
                  and the service_reference
        """
        return self._item_verify(service, self.SERVICES_ENDPOINT, 'service_reference')

    def _item_verify(self, item_str, item_key, item_type, get_id=True):
        """Method to verify the existance of an item with the API

        Args:
            item_str (str): Service to query about in the API
            item_key (str): Endpoint/key to be extracted from search results
            item_type (str): Type of item reference to be returned
            get_id (boolean): Whether to generate a dict with result and reference

        Returns:
            dict: JSON object be used in the API call, containing the item id
                  and the item reference, True if it just exists or False if it fails
        """
        item_url = self._get_endpoint(self._base_url, item_key)
        item_id = self._check_exists(item_str, item_url, item_key, get_id)
        if not item_id:
            LOGGER.info('%s not found in %s, %s', item_str, item_key, self.__service__)
            return False

        if get_id:
            return {'id': item_id, 'type': item_type}

        return item_id

    def _incident_assignment(self, context):
        """Method to determine if the incident gets assigned to a user or an escalation policy

        Args:
            context (dict): Context provided in the alert record

        Returns:
            tuple: assigned_key (str), assigned_value (dict to assign incident to an escalation
            policy or array of dicts to assign incident to users)
        """
        # Check if a user to assign the incident is provided
        user_to_assign = context.get('assigned_user', False)

        # If provided, verify the user and get the id from API
        if user_to_assign:
            user_assignee = self._user_verify(user_to_assign)
            # User is verified, return tuple
            if user_assignee:
                return 'assignments', [{'assignee': user_assignee}]

        # If escalation policy was not provided, use default one
        policy_to_assign = context.get('assigned_policy', self._escalation_policy)

        # Verify escalation policy, return tuple
        return 'escalation_policy', self._policy_verify(policy_to_assign, self._escalation_policy)

    def dispatch(self, **kwargs):
        """Send incident to Pagerduty Incidents API v2

        Keyword Args:
            **kwargs: consists of any combination of the following items:
                descriptor (str): Service descriptor (ie: slack channel, pd integration)
                rule_name (str): Name of the triggered rule
                alert (dict): Alert relevant to the triggered rule
                alert['context'] (dict): Provides user or escalation policy
        """
        creds = self._load_creds(kwargs['descriptor'])
        if not creds:
            return self._log_status(False)

        # Cache base_url
        self._base_url = creds['api']

        # Preparing headers for API calls
        self._headers = {
            'Authorization': 'Token token={}'.format(creds['token']),
            'Accept': 'application/vnd.pagerduty+json;version=2'
        }

        # Get user email to be added as From header and verify
        user_email = creds['email_from']
        if not self._user_verify(user_email, False):
            return self._log_status(False)

        # Add From to the headers after verifying
        self._headers['From'] = user_email

        # Cache default escalation policy
        self._escalation_policy = creds['escalation_policy']

        # Extracting context data to assign the incident
        rule_context = kwargs['alert'].get('context', {})
        if rule_context:
            rule_context = rule_context.get(self.__service__, {})

        # Incident assignment goes in this order:
        #  Provided user -> provided policy -> default policy
        assigned_key, assigned_value = self._incident_assignment(rule_context)

        # Start preparing the incident JSON blob to be sent to the API
        incident_title = 'StreamAlert Incident - Rule triggered: {}'.format(kwargs['rule_name'])
        incident_body = {
            'type': 'incident_body',
            'details': kwargs['alert']['rule_description']
        }
        # We need to get the service id from the API
        incident_service = self._service_verify(creds['service_key'])
        incident = {
            'incident': {
                'type': 'incident',
                'title': incident_title,
                'service': incident_service,
                'body': incident_body,
                assigned_key: assigned_value
            }
        }
        incidents_url = self._get_endpoint(self._base_url, self.INCIDENTS_ENDPOINT)
        resp = self._post_request(incidents_url, incident, self._headers, True)
        success = self._check_http_response(resp)

        return self._log_status(success)

@output
class PhantomOutput(StreamOutputBase):
    """PhantomOutput handles all alert dispatching for Phantom"""
    __service__ = 'phantom'
    CONTAINER_ENDPOINT = 'rest/container'
    ARTIFACT_ENDPOINT = 'rest/artifact'

    def get_user_defined_properties(self):
        """Get properties that must be asssigned by the user when configuring a new Phantom
        output.  This should be sensitive or unique information for this use-case that needs
        to come from the user.

        Every output should return a dict that contains a 'descriptor' with a description of the
        integration being configured.

        Phantom also requires a ph_auth_token that represnts an authorization token for this
        integration and a user provided url to use for alert dispatching. These values should be
        masked during input and are credential requirements.

        Returns:
            OrderedDict: Contains various OutputProperty items
        """
        return OrderedDict([
            ('descriptor',
             OutputProperty(description='a short and unique descriptor for this '
                                        'Phantom integration')),
            ('ph_auth_token',
             OutputProperty(description='the auth token for this Phantom integration',
                            mask_input=True,
                            cred_requirement=True)),
            ('url',
             OutputProperty(description='the endpoint url for this Phantom integration',
                            mask_input=True,
                            cred_requirement=True))
        ])

    def _check_container_exists(self, rule_name, container_url, headers):
        """Check to see if a Phantom container already exists for this rule

        Args:
            rule_name (str): The name of the rule that triggered the alert
            container_url (str): The constructed container url for this Phantom instance
            headers (dict): A dictionary containing header parameters

        Returns:
            int: ID of an existing Phantom container for this rule where the alerts
                will be sent or False if a matching container does not yet exists
        """
        # Limit the query to 1 page, since we only care if one container exists with
        # this name.
        params = {
            '_filter_name': '"{}"'.format(rule_name),
            'page_size': 1
        }
        resp = self._get_request(container_url, params, headers, False)
        if not self._check_http_response(resp):
            return False

        response = resp.json()

        # If the count == 0 then we know there are no containers with this name and this
        # will evaluate to False. Otherwise there is at least one item in the list
        # of 'data' with a container id we can use
        return response and response.get('count') and response.get('data')[0]['id']

    def _setup_container(self, rule_name, rule_description, base_url, headers):
        """Establish a Phantom container to write the alerts to. This checks to see
        if an appropriate containers exists first and returns the ID if so.

        Args:
            rule_name (str): The name of the rule that triggered the alert
            base_url (str): The base url for this Phantom instance
            headers (dict): A dictionary containing header parameters

        Returns:
            int: ID of the Phantom container where the alerts will be sent
                or False if there is an issue getting the container id
        """
        container_url = os.path.join(base_url, self.CONTAINER_ENDPOINT)

        # Check to see if there is a container already created for this rule name
        existing_id = self._check_container_exists(rule_name, container_url, headers)
        if existing_id:
            return existing_id

        # Try to use the rule_description from the rule as the container description
        ph_container = {'name': rule_name, 'description': rule_description}
        resp = self._post_request(container_url, ph_container, headers, False)

        if not self._check_http_response(resp):
            return False

        response = resp.json()

        return response and response.get('id')

    def dispatch(self, **kwargs):
        """Send alert to Phantom

        Args:
            **kwargs: consists of any combination of the following items:
                descriptor (str): Service descriptor (ie: slack channel, pd integration)
                rule_name (str): Name of the triggered rule
                alert (dict): Alert relevant to the triggered rule
        """
        creds = self._load_creds(kwargs['descriptor'])
        if not creds:
            return self._log_status(False)

        headers = {"ph-auth-token": creds['ph_auth_token']}
        rule_desc = kwargs['alert']['rule_description']
        container_id = self._setup_container(kwargs['rule_name'], rule_desc,
                                             creds['url'], headers)

        LOGGER.debug('sending alert to Phantom container with id %s', container_id)

        success = False
        if container_id:
            artifact = {'cef': kwargs['alert']['record'],
                        'container_id': container_id,
                        'data': kwargs['alert'],
                        'name': 'Phantom Artifact',
                        'label': 'Alert'}
            artifact_url = os.path.join(creds['url'], self.ARTIFACT_ENDPOINT)
            resp = self._post_request(artifact_url, artifact, headers, False)

            success = self._check_http_response(resp)

        return self._log_status(success)


@output
class SlackOutput(StreamOutputBase):
    """SlackOutput handles all alert dispatching for Slack"""
    __service__ = 'slack'
    # Slack recommends no messages larger than 4000 bytes. This does not account for unicode
    MAX_MESSAGE_SIZE = 4000

    def get_user_defined_properties(self):
        """Get properties that must be asssigned by the user when configuring a new Slack
        output.  This should be sensitive or unique information for this use-case that needs
        to come from the user.

        Every output should return a dict that contains a 'descriptor' with a description of the
        integration being configured.

        Slack also requires a user provided 'webhook' url that is comprised of the slack api url
        and the unique integration key for this output. This value should be should be masked
        during input and is a credential requirement.

        Returns:
            OrderedDict: Contains various OutputProperty items
        """
        return OrderedDict([
            ('descriptor',
             OutputProperty(description='a short and unique descriptor for this Slack integration '
                                        '(ie: channel, group, etc)')),
            ('url',
             OutputProperty(description='the full Slack webhook url, including the secret',
                            mask_input=True,
                            cred_requirement=True))
        ])

    @classmethod
    def _format_message(cls, rule_name, alert):
        """Format the message to be sent to slack.

        Args:
            rule_name (str): The name of the rule that triggered the alert
            alert: Alert relevant to the triggered rule

        Returns:
            dict: message with attachments to send to Slack.
                The message will look like:
                    StreamAlert Rule Triggered: rule_name
                    Rule Description:
                    This will be the docstring from the rule, sent as the rule_description

                    Record (Part 1 of 2):
                    ...
        """
        # Convert the alert we have to a nicely formatted string for slack
        alert_text = '\n'.join(cls._json_to_slack_mrkdwn(alert['record'], 0))
        # Slack requires escaping the characters: '&', '>' and '<' and cgi does just that
        alert_text = cgi.escape(alert_text)
        messages = []
        index = cls.MAX_MESSAGE_SIZE
        while alert_text != '':
            if len(alert_text) <= index:
                messages.append(alert_text)
                break

            # Find the closest line break prior to this index
            while index > 1 and alert_text[index] != '\n':
                index -= 1

            # Append the message part up until this index, and move to the next chunk
            messages.append(alert_text[:index])
            alert_text = alert_text[index+1:]

            index = cls.MAX_MESSAGE_SIZE

        header_text = '*StreamAlert Rule Triggered: {}*'.format(rule_name)
        full_message = {
            'text': header_text,
            'mrkdwn': True,
            'attachments': []
        }

        for index, message in enumerate(messages):
            title = 'Record:'
            if len(messages) > 1:
                title = 'Record (Part {} of {}):'.format(index+1, len(messages))
            rule_desc = ''
            # Only print the rule description on the first attachment
            if index == 0:
                rule_desc = alert['rule_description']
                rule_desc = '*Rule Description:*\n{}\n'.format(rule_desc)

            # Add this attachemnt to the full message array of attachments
            full_message['attachments'].append({
                'fallback': header_text,
                'color': '#b22222',
                'pretext': rule_desc,
                'title': title,
                'text': message,
                'mrkdwn_in': ['text', 'pretext']
            })

        # Return the json dict payload to be sent to slack
        return full_message

    @classmethod
    def _json_to_slack_mrkdwn(cls, json_values, indent_count):
        """Translate a json object into a more human-readable list of lines
        This will handle recursion of all nested maps and lists within the object

        Args:
            json_values: variant to be translated (could be json map, list, etc)
            indent_count (int): Number of tabs to prefix each line with

        Returns:
            list: strings that have been properly tabbed and formatted for printing
        """
        tab = '\t'
        all_lines = []
        if isinstance(json_values, dict):
            all_lines = cls._json_map_to_text(json_values, tab, indent_count)
        elif isinstance(json_values, list):
            all_lines = cls._json_list_to_text(json_values, tab, indent_count)
        else:
            all_lines.append('{}'.format(json_values))

        return all_lines

    @classmethod
    def _json_map_to_text(cls, json_values, tab, indent_count):
        """Translate a map from json (dict) into a more human-readable list of lines
        This will handle recursion of all nested maps and lists within the map

        Args:
            json_values (dict): dictionary to be iterated over and formatted
            tab (str): string value to use for indentation
            indent_count (int): Number of tabs to prefix each line with

        Returns:
            list: strings that have been properly tabbed and formatted for printing
        """
        all_lines = []
        for key, value in json_values.iteritems():
            if isinstance(value, (dict, list)) and value:
                all_lines.append('{}*{}:*'.format(tab*indent_count, key))
                all_lines.extend(cls._json_to_slack_mrkdwn(value, indent_count+1))
            else:
                new_lines = cls._json_to_slack_mrkdwn(value, indent_count+1)
                if len(new_lines) == 1:
                    all_lines.append('{}*{}:* {}'.format(tab*indent_count, key, new_lines[0]))
                elif new_lines:
                    all_lines.append('{}*{}:*'.format(tab*indent_count, key))
                    all_lines.extend(new_lines)
                else:
                    all_lines.append('{}*{}:* {}'.format(tab*indent_count, key, value))

        return all_lines

    @classmethod
    def _json_list_to_text(cls, json_values, tab, indent_count):
        """Translate a list from json into a more human-readable list of lines
        This will handle recursion of all nested maps and lists within the list

        Args:
            json_values (list): list to be iterated over and formatted
            tab (str): string value to use for indentation
            indent_count (int): Number of tabs to prefix each line with

        Returns:
            list: strings that have been properly tabbed and formatted for printing
        """
        all_lines = []
        for index, value in enumerate(json_values):
            if isinstance(value, (dict, list)) and value:
                all_lines.append('{}*[{}]*'.format(tab*indent_count, index+1))
                all_lines.extend(cls._json_to_slack_mrkdwn(value, indent_count+1))
            else:
                new_lines = cls._json_to_slack_mrkdwn(value, indent_count+1)
                if len(new_lines) == 1:
                    all_lines.append('{}*[{}]* {}'.format(tab*indent_count, index+1, new_lines[0]))
                elif new_lines:
                    all_lines.append('{}*[{}]*'.format(tab*indent_count, index+1))
                    all_lines.extend(new_lines)
                else:
                    all_lines.append('{}*[{}]* {}'.format(tab*indent_count, index+1, value))

        return all_lines

    def dispatch(self, **kwargs):
        """Send alert text to Slack

        Args:
            **kwargs: consists of any combination of the following items:
                descriptor (str): Service descriptor (ie: slack channel, pd integration)
                rule_name (str): Name of the triggered rule
                alert (dict): Alert relevant to the triggered rule
        """
        creds = self._load_creds(kwargs['descriptor'])
        if not creds:
            return self._log_status(False)

        slack_message = self._format_message(kwargs['rule_name'], kwargs['alert'])

        resp = self._post_request(creds['url'], slack_message)
        success = self._check_http_response(resp)

        return self._log_status(success)


class AWSOutput(StreamOutputBase):
    """Subclass to be inherited from for all AWS service outputs"""
    def format_output_config(self, service_config, values):
        """Format the output configuration for this AWS service to be written to disk

        AWS services are stored as a dictionary within the config instead of a list so
        we have access to the AWS value (arn/bucket name/etc) for Terraform

        Args:
            service_config (dict): The actual outputs config that has been read in
            values (OrderedDict): Contains all the OutputProperty items for this service

        Returns:
            dict{<string>: <string>}: Updated dictionary of descriptors and
                values for this AWS service needed for the output configuration
            NOTE: S3 requires the bucket name, not an arn, for this value.
                Instead of implementing this differently in subclasses, all AWSOutput
                subclasses should use a generic 'aws_value' to store the value for the
                descriptor used in configuration
        """
        return dict(service_config.get(self.__service__, {}),
                    **{values['descriptor'].value: values['aws_value'].value})

    @abstractmethod
    def dispatch(self, **kwargs):
        """Placeholder for implementation in the subclasses"""
        pass


@output
class KinesisFirehoseOutput(AWSOutput):
    """High throughput Alert delivery to AWS S3"""
    MAX_RECORD_SIZE = 1000 * 1000
    MAX_BACKOFF_ATTEMPTS = 3

    __service__ = 'aws-firehose'
    __aws_client__ = None

    def get_user_defined_properties(self):
        """Properties asssigned by the user when configuring a new Firehose output

        Every output should return a dict that contains a 'descriptor' with a description of the
        integration being configured.

        Returns:
            OrderedDict: Contains various OutputProperty items
        """
        return OrderedDict([
            ('descriptor',
             OutputProperty(
                 description='a short and unique descriptor for this Firehose Delivery Stream')),
            ('aws_value',
             OutputProperty(description='the Firehose Delivery Stream name'))
        ])

    def dispatch(self, **kwargs):
        """Send alert to a Kinesis Firehose Delivery Stream

        Keyword Args:
            descriptor (str): Service descriptor (ie: slack channel, pd integration)
            rule_name (str): Name of the triggered rule
            alert (dict): Alert relevant to the triggered rule

        Returns:
            bool: Indicates a successful or failed dispatch of the alert
        """
        @backoff.on_exception(backoff.fibo,
                              ClientError,
                              max_tries=self.MAX_BACKOFF_ATTEMPTS,
                              jitter=backoff.full_jitter,
                              on_backoff=backoff_handler,
                              on_success=success_handler,
                              on_giveup=giveup_handler)
        def _firehose_request_wrapper(json_alert, delivery_stream):
            """Make the PutRecord request to Kinesis Firehose with backoff

            Args:
                json_alert (str): The JSON dumped alert body
                delivery_stream (str): The Firehose Delivery Stream to send to

            Returns:
                dict: Firehose response in the format below
                    {'RecordId': 'string'}
            """
            return self.__aws_client__.put_record(DeliveryStreamName=delivery_stream,
                                                  Record={'Data': json_alert})

        if self.__aws_client__ is None:
            self.__aws_client__ = boto3.client('firehose', region_name=self.region)

        json_alert = json.dumps(kwargs['alert'], separators=(',', ':')) + '\n'
        if len(json_alert) > self.MAX_RECORD_SIZE:
            LOGGER.error('Alert too large to send to Firehose: \n%s...', json_alert[0:1000])
            return False

        delivery_stream = self.config[self.__service__][kwargs['descriptor']]
        LOGGER.info('Sending alert [%s] to aws-firehose:%s',
                    kwargs['rule_name'],
                    delivery_stream)

        resp = _firehose_request_wrapper(json_alert, delivery_stream)

        if resp.get('RecordId'):
            LOGGER.info('Alert [%s] successfully sent to aws-firehose:%s with RecordId:%s',
                        kwargs['rule_name'],
                        delivery_stream,
                        resp['RecordId'])

        return self._log_status(resp)


@output
class S3Output(AWSOutput):
    """S3Output handles all alert dispatching for AWS S3"""
    __service__ = 'aws-s3'

    def get_user_defined_properties(self):
        """Get properties that must be asssigned by the user when configuring a new S3
        output.  This should be sensitive or unique information for this use-case that needs
        to come from the user.

        Every output should return a dict that contains a 'descriptor' with a description of the
        integration being configured.

        S3 also requires a user provided bucket name to be used for this service output. This
        value should not be masked during input and is not a credential requirement
        that needs encrypted.

        Returns:
            OrderedDict: Contains various OutputProperty items
        """
        return OrderedDict([
            ('descriptor',
             OutputProperty(
                 description='a short and unique descriptor for this S3 bucket (ie: bucket name)')),
            ('aws_value',
             OutputProperty(description='the AWS S3 bucket name to use for this S3 configuration'))
        ])

    def dispatch(self, **kwargs):
        """Send alert to an S3 bucket

        Organizes alert into the following folder structure:
            service/entity/rule_name/datetime.json
        The alert gets dumped to a JSON string

        Args:
            **kwargs: consists of any combination of the following items:
                descriptor (str): Service descriptor (ie: slack channel, pd integration)
                rule_name (str): Name of the triggered rule
                alert (dict): Alert relevant to the triggered rule
        """
        alert = kwargs['alert']
        service = alert['source_service']
        entity = alert['source_entity']

        current_date = datetime.now()

        s3_alert = alert
        # JSON dump the alert to retain a consistent alerts schema across log types.
        # This will get replaced by a UUID which references a record in a
        # different table in the future.
        s3_alert['record'] = json.dumps(s3_alert['record'])
        alert_string = json.dumps(s3_alert)

        bucket = self.config[self.__service__][kwargs['descriptor']]

        # Prefix with alerts to account for generic non-streamalert buckets
        # Produces the following key format:
        #   alerts/dt=2017-01-25-00/kinesis_my-stream_my-rule_uuid.json
        # Keys need to be unique to avoid object overwriting
        key = 'alerts/dt={}/{}_{}_{}_{}.json'.format(
            current_date.strftime('%Y-%m-%d-%H'),
            service,
            entity,
            alert['rule_name'],
            uuid.uuid4()
        )

        LOGGER.debug('Sending alert to S3 bucket %s with key %s', bucket, key)

        client = boto3.client('s3', region_name=self.region)
        resp = client.put_object(Body=alert_string,
                                 Bucket=bucket,
                                 Key=key)

        return self._log_status(resp)


@output
class LambdaOutput(AWSOutput):
    """LambdaOutput handles all alert dispatching to AWS Lambda"""
    __service__ = 'aws-lambda'

    def get_user_defined_properties(self):
        """Get properties that must be asssigned by the user when configuring a new Lambda
        output.  This should be sensitive or unique information for this use-case that needs
        to come from the user.

        Every output should return a dict that contains a 'descriptor' with a description of the
        integration being configured.

        Sending to Lambda also requires a user provided Lambda function name and optional qualifier
        (if applicabale for the user's use case). A fully-qualified AWS ARN is also acceptable for
        this value. This value should not be masked during input and is not a credential requirement
        that needs encrypted.

        Returns:
            OrderedDict: Contains various OutputProperty items
        """
        return OrderedDict([
            ('descriptor',
             OutputProperty(description='a short and unique descriptor for this Lambda function '
                                        'configuration (ie: abbreviated name)')),
            ('aws_value',
             OutputProperty(description='the AWS Lambda function name, with the optional '
                                        'qualifier (aka \'alias\'), to use for this '
                                        'configuration (ie: output_function:qualifier)',
                            input_restrictions={' '})),
        ])

    def dispatch(self, **kwargs):
        """Send alert to a Lambda function

        The alert gets dumped to a JSON string to be sent to the Lambda function

        Args:
            **kwargs: consists of any combination of the following items:
                descriptor (str): Service descriptor (ie: slack channel, pd integration)
                rule_name (str): Name of the triggered rule
                alert (dict): Alert relevant to the triggered rule
        """
        alert = kwargs['alert']
        alert_string = json.dumps(alert['record'])
        function_name = self.config[self.__service__][kwargs['descriptor']]

        # Check to see if there is an optional qualifier included here
        # Acceptable values for the output configuration are the full ARN,
        # a function name followed by a qualifier, or just a function name:
        #   'arn:aws:lambda:aws-region:acct-id:function:function-name:prod'
        #   'function-name:prod'
        #   'function-name'
        # Checking the length of the list for 2 or 8 should account for all
        # times a qualifier is provided.
        parts = function_name.split(':')
        if len(parts) == 2 or len(parts) == 8:
            function = parts[-2]
            qualifier = parts[-1]
        else:
            function = parts[-1]
            qualifier = None

        LOGGER.debug('Sending alert to Lambda function %s', function_name)

        client = boto3.client('lambda', region_name=self.region)
        # Use the qualifier if it's available. Passing an empty qualifier in
        # with `Qualifier=''` or `Qualifier=None` does not work and thus we
        # have to perform different calls to client.invoke().
        if qualifier:
            resp = client.invoke(FunctionName=function,
                                 InvocationType='Event',
                                 Payload=alert_string,
                                 Qualifier=qualifier)
        else:
            resp = client.invoke(FunctionName=function,
                                 InvocationType='Event',
                                 Payload=alert_string)

        return self._log_status(resp)

@output
class JiraOutput(StreamOutputBase):
    """JiraOutput handles all alert dispatching for Jira"""
    __service__ = 'jira'

    DEFAULT_HEADERS = {'Content-Type': 'application/json'}
    LOGIN_ENDPOINT = 'rest/auth/1/session'
    SEARCH_ENDPOINT = 'rest/api/2/search'
    ISSUE_ENDPOINT = 'rest/api/2/issue'
    COMMENT_ENDPOINT = 'rest/api/2/issue/{}/comment'

    def __init__(self, *args, **kwargs):
        StreamOutputBase.__init__(self, *args, **kwargs)
        self._base_url = None
        self._auth_cookie = None

    def get_user_defined_properties(self):
        """Get properties that must be asssigned by the user when configuring a new Jira
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
             OutputProperty(description='the Jira username',
                            mask_input=True,
                            cred_requirement=True)),
            ('password',
             OutputProperty(description='the Jira password',
                            mask_input=True,
                            cred_requirement=True)),
            ('url',
             OutputProperty(description='the Jira url',
                            mask_input=True,
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

        resp = self._get_request(search_url,
                                 params=params,
                                 headers=self._get_headers(),
                                 verify=False)

        success = self._check_http_response(resp)
        if not success:
            return []

        return resp.json()['issues']

    def _create_comment(self, issue_id, comment):
        """Add a comment to an existing issue

        Args:
            issue_id (str): The existing issue ID or key
            comment (str): The body of the comment

        Returns:
            int: ID of the created comment or False if unsuccessful
        """
        comment_url = os.path.join(self._base_url, self.COMMENT_ENDPOINT.format(issue_id))
        resp = self._post_request(comment_url,
                                  data={'body': comment},
                                  headers=self._get_headers(),
                                  verify=False)

        success = self._check_http_response(resp)
        if not success:
            return False

        return resp.json()['id']

    def _get_comments(self, issue_id):
        """Get all comments for an existing Jira issue

        Args:
            issue_id (str): The existing issue ID or key

        Returns:
            list: List of comments associated with a Jira issue
        """
        comment_url = os.path.join(self._base_url, self.COMMENT_ENDPOINT.format(issue_id))
        resp = self._get_request(comment_url,
                                 headers=self._get_headers(),
                                 verify=False)

        success = self._check_http_response(resp)
        if not success:
            return []

        return resp.json()['comments']

    def _get_existing_issue(self, issue_summary, project_key):
        """Find an existing Jira issue based on the issue summary

        Args:
            issue_summary (str): The Jira issue summary
            project_key (str): The Jira project to search

        Returns:
            int: ID of the found issue or False if existing issue does not exist
        """
        jql = 'summary ~ "{}" and project="{}"'.format(issue_summary, project_key)
        resp = self._search_jira(jql, fields=['id', 'summary'], max_results=1)
        jira_id = False

        try:
            jira_id = int(resp[0]['id'])
        except (IndexError, KeyError):
            LOGGER.debug('Existing Jira issue not found')

        return jira_id

    def _create_issue(self, issue_name, project_key, issue_type, description):
        """Create a Jira issue to write alerts to. Alert is written to the "description"
        field of an issue.

        Args:
            issue_name (str): The name of the Jira issue
            project_key (str): The Jira project key which issues will be associated with
            issue_type (str): The type of issue being created
            description (str): The body of text which describes the issue

        Returns:
            int: ID of the created issue or False if unsuccessful
        """
        issue_url = os.path.join(self._base_url, self.ISSUE_ENDPOINT)
        issue_body = {
            'fields': {
                'project': {
                    'key': project_key
                },
                'summary': issue_name,
                'description': description,
                'issuetype': {
                    'name': issue_type
                }
            }
        }

        resp = self._post_request(issue_url,
                                  data=issue_body,
                                  headers=self._get_headers(),
                                  verify=False)

        success = self._check_http_response(resp)
        if not success:
            return False

        return resp.json()['id']

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

        resp = self._post_request(login_url,
                                  data=auth_info,
                                  headers=self._get_default_headers(),
                                  verify=False)

        success = self._check_http_response(resp)
        if not success:
            LOGGER.error("Failed to authenticate to Jira")
            return False
        resp_dict = resp.json()

        return '{}={}'.format(resp_dict['session']['name'],
                              resp_dict['session']['value'])

    def dispatch(self, **kwargs):
        """Send alert to Jira

        Args:
            **kwargs: consists of any combination of the following items:
                descriptor (str): Service descriptor (ie: slack channel, pd integration)
                rule_name (str): Name of the triggered rule
                alert (dict): Alert relevant to the triggered rule
        """
        creds = self._load_creds(kwargs['descriptor'])
        if not creds:
            return self._log_status(False)

        issue_id = None
        comment_id = None
        issue_summary = 'StreamAlert {}'.format(kwargs['rule_name'])
        alert_body = '{{code:JSON}}{}{{code}}'.format(json.dumps(kwargs['alert']))
        self._base_url = creds['url']
        self._auth_cookie = self._establish_session(creds['username'], creds['password'])

        # Validate successful authentication
        if not self._auth_cookie:
            return self._log_status(False)

        # If aggregation is enabled, attempt to add alert to an existing issue. If a
        # failure occurs in this block, creation of a new Jira issue will be attempted.
        if creds.get('aggregate', '').lower() == 'yes':
            issue_id = self._get_existing_issue(issue_summary, creds['project_key'])
            if issue_id:
                comment_id = self._create_comment(issue_id, alert_body)
                if comment_id:
                    LOGGER.debug('Sending alert to an existing Jira issue %s with comment %s',
                                 issue_id,
                                 comment_id)
                    return self._log_status(True)
                else:
                    LOGGER.error('Encountered an error when adding alert to existing '
                                 'Jira issue %s. Attempting to create new Jira issue.',
                                 issue_id)

        # Create a new Jira issue
        issue_id = self._create_issue(issue_summary,
                                      creds['project_key'],
                                      creds['issue_type'],
                                      alert_body)
        if issue_id:
            LOGGER.debug('Sending alert to a new Jira issue %s', issue_id)

        return self._log_status(issue_id or comment_id)

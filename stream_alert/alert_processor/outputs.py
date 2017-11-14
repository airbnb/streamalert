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
             OutputProperty(description='the name of the default escalation policy'))
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

    def _check_exists_get_id(self, filter_str, url, headers, target_key):
        """Generic method to run a search in the PagerDuty REST API and return the id
        of the first occurence from the results.

        Args:
            filter_str (str): The query filter to search for in the API
            url (str): The url to send the requests to in the API
            headers (dict): A dictionary containing header parameters
            target_key (str): The key to extract in the returned results

        Returns:
            str: ID of the targeted element that matches the provided filter or
                 False if a matching element does not exists.
        """
        params = {
            'query': '"{}"'.format(filter_str)
        }
        resp = self._get_request(url, params, headers, False)
        if not self._check_http_response(resp):
            return False

        response = resp.json()

        # If there are results, get the first occurence from the list
        target = response.get(target_key, False)
        if response and target:
            return target[0]['id']

        return False

    def _user_verify(self, api_url, user, headers):
        """Method to verify the existance of an user with the API

        Args:
            api_url (str): Base URL of the API
            user (str): User to query about in the API.
            headers (dict): Headers used for API authentication

        Returns:
            dict or False: JSON object be used in the API call, containing the user_id
                           and user_reference. False if user is not found
        """
        users_url = self._get_endpoint(api_url, self.USERS_ENDPOINT)
        user_id = self._check_exists_get_id(user, users_url, headers,
                                            self.USERS_ENDPOINT)
        if not user_id:
            LOGGER.info('User[%s] not found in %s', user, self.__service__)
            return False

        return {
            'id': user_id,
            'type': 'user_reference'
        }

    def _policy_verify(self, api_url, policy, headers):
        """Method to verify the existance of a escalation policy with the API

        Args:
            api_url (str): Base URL of the API
            policy (str): Escalation policy to query about in the API
            headers (dict): Headers used for API authentication

        Returns:
            dict: JSON object be used in the API call, containing the policy_id
                  and escalation_policy_reference
        """
        policies_url = self._get_endpoint(api_url, self.POLICIES_ENDPOINT)
        policy_id = self._check_exists_get_id(policy, policies_url, headers,
                                              self.POLICIES_ENDPOINT)
        if not policy_id:
            LOGGER.info('Escalation Policy[%s] not found in %s', policy, self.__service__)
            return False

        return {
            'id': policy_id,
            'type': 'escalation_policy_reference'
        }

    def _service_verify(self, api_url, service, headers):
        """Method to verify the existance of a service with the API

        Args:
            api_url (str): Base URL of the API
            service (str): Service to query about in the API
            headers (dict): Headers used for API authentication

        Returns:
            dict: JSON object be used in the API call, containing the service_id
                  and the service_reference
        """
        services_url = self._get_endpoint(api_url, self.SERVICES_ENDPOINT)
        service_id = self._check_exists_get_id(service, services_url, headers,
                                               self.SERVICES_ENDPOINT)
        if not service_id:
            LOGGER.info('Service[%s] not found in %s', service, self.__service__)
            return False

        return {
            'id': service_id,
            'type': 'service_reference'
        }

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

        # Preparing headers for API calls
        headers = {
            'Authorization': 'Token token={}'.format(creds['token']),
            'Accept': 'application/vnd.pagerduty+json;version=2'
        }

        # Extracting context data to assign the incident
        rule_context = kwargs['alert'].get('context', {})
        if rule_context:
            rule_context = rule_context[self.__service__]

        # Check if a user to assign the incident is provided
        user_to_assign = rule_context.get('assigned_user', False)

        # Incident assignment goes in this order:
        #  Provided user -> provided policy -> default policy
        if user_to_assign:
            user_assignee = self._user_verify(creds['api'], user_to_assign, headers)
            if user_assignee:
                assigned_key = 'assignments'
                assigned_value = [{
                    'assignee' : user_assignee}]
            else:
                user_to_assign = user_assignee

        policy_to_assign = creds['escalation_policy']
        if not user_to_assign and rule_context.get('assigned_policy'):
            policy_to_assign = rule_context.get('assigned_policy')

        assigned_key = 'escalation_policy'
        assigned_value = self._policy_verify(creds['api'], policy_to_assign, headers)

        # Start preparing the incident JSON blob to be sent to the API
        incident_title = 'StreamAlert Incident - Rule triggered: {}'.format(kwargs['rule_name'])
        incident_body = {
            'type': 'incident_body',
            'details': kwargs['alert']['rule_description']
        }
        # We need to get the service id from the API
        incident_service = self._service_verify(creds['api'], creds['service_key'], headers)
        incident = {
            'incident': {
                'type': 'incident',
                'title': incident_title,
                'service': incident_service,
                'body': incident_body
            },
            assigned_key: assigned_value
        }
        incidents_url = self._get_endpoint(creds['api'], self.INCIDENTS_ENDPOINT)
        resp = self._post_request(incidents_url, incident, None, True)
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

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
from collections import OrderedDict
import os

from stream_alert.alert_processor import LOGGER
from stream_alert.alert_processor.outputs.output_base import (
    OutputDispatcher,
    OutputProperty,
    OutputRequestFailure,
    StreamAlertOutput
)


@StreamAlertOutput
class PagerDutyOutput(OutputDispatcher):
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

    @classmethod
    def get_user_defined_properties(cls):
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

@StreamAlertOutput
class PagerDutyOutputV2(OutputDispatcher):
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

    @classmethod
    def get_user_defined_properties(cls):
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

@StreamAlertOutput
class PagerDutyIncidentOutput(OutputDispatcher):
    """PagerDutyIncidentOutput handles all alert dispatching for PagerDuty Incidents API v2"""
    __service__ = 'pagerduty-incident'
    INCIDENTS_ENDPOINT = 'incidents'
    USERS_ENDPOINT = 'users'
    POLICIES_ENDPOINT = 'escalation_policies'
    SERVICES_ENDPOINT = 'services'
    PRIORITIES_ENDPOINT = 'priorities'

    def __init__(self, *args, **kwargs):
        OutputDispatcher.__init__(self, *args, **kwargs)
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

    @classmethod
    def get_user_defined_properties(cls):
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

    def _priority_verify(self, context):
        """Method to verify the existance of a incident priority with the API

        Args:
            context (dict): Context provided in the alert record

        Returns:
            dict: JSON object be used in the API call, containing the priority id
                  and the priority reference, empty if it fails or it does not exist
        """
        if not context:
            return dict()

        priority_name = context.get('incident_priority', False)
        if not priority_name:
            return dict()

        priorities_url = self._get_endpoint(self._base_url, self.PRIORITIES_ENDPOINT)
        resp = self._get_request(priorities_url, {}, self._headers, False)

        if not self._check_http_response(resp):
            return dict()

        response = resp.json()
        if not response:
            return dict()

        priorities = response.get('priorities', [])

        if not priorities:
            return dict()

        # If the requested priority is in the list, get the id
        priority_id = next(
            (item for item in priorities if item["name"] == priority_name), {}).get('id', False)

        # If the priority id is found, compose the JSON
        if priority_id:
            return {'id': priority_id, 'type': 'priority_reference'}

        return dict()

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
            LOGGER.error('Could not verify header From: %s, %s', user_email, self.__service__)
            return self._log_status(False)

        # Add From to the headers after verifying
        self._headers['From'] = user_email

        # Cache default escalation policy
        self._escalation_policy = creds['escalation_policy']

        # Extracting context data to assign the incident
        rule_context = kwargs['alert'].get('context', {})
        if rule_context:
            rule_context = rule_context.get(self.__service__, {})

        # Use the priority provided in the context, use it or the incident will be low priority
        incident_priority = self._priority_verify(rule_context)

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
                'priority': incident_priority,
                'body': incident_body,
                assigned_key: assigned_value
            }
        }
        incidents_url = self._get_endpoint(self._base_url, self.INCIDENTS_ENDPOINT)
        resp = self._post_request(incidents_url, incident, self._headers, True)
        success = self._check_http_response(resp)

        if not self._log_status(success):
            raise OutputRequestFailure

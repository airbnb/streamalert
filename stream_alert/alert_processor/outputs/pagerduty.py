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
import backoff

from stream_alert.alert_processor.outputs.output_base import (
    OutputDispatcher,
    OutputProperty,
    OutputRequestFailure,
    StreamAlertOutput
)
from stream_alert.alert_processor.publishers import publish_alert
from stream_alert.shared.backoff_handlers import (
    backoff_handler,
    success_handler,
    giveup_handler
)
from stream_alert.shared.logger import get_logger


LOGGER = get_logger(__name__)


def events_v2_data(output_dispatcher, descriptor, alert, routing_key, with_record=True):
    """Helper method to generate the payload to create an event using PagerDuty Events API v2

    Args:
        output_dispatcher (OutputDispatcher): The output sending these data
        descriptor (str): The descriptor of the output sending these data
        alert (Alert): Alert relevant to the triggered rule
        routing_key (str): Routing key for this PagerDuty integration
        with_record (boolean): Option to add the record data or not

    Returns:
        dict: Contains JSON blob to be used as event
    """
    publication = publish_alert(alert, output_dispatcher, descriptor)

    # Presentation defaults
    default_summary = 'StreamAlert Rule Triggered - {}'.format(alert.rule_name)
    default_description = alert.rule_description
    default_record = alert.record

    # Special field that Publishers can use to customize the header
    # FIXME (derek.wang) the publication key does not adhere to the convention of __service__
    # as a prefix, since this method is overloaded between two different outputs
    summary = publication.get('pagerduty.summary', default_summary)
    details = OrderedDict()
    details['description'] = publication.get('pagerduty.description', default_description)
    if with_record:
        details['record'] = publication.get('record', default_record)

    payload = {
        'summary': summary,
        'source': alert.log_source,
        'severity': 'critical',
        'custom_details': details
    }
    return {
        'routing_key': routing_key,
        'payload': payload,
        'event_action': 'trigger',
        'client': 'StreamAlert'
    }


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
        """Get properties that must be assigned by the user when configuring a new PagerDuty
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

    def _dispatch(self, alert, descriptor):
        """Send alert to Pagerduty

        Args:
            alert (Alert): Alert instance which triggered a rule
            descriptor (str): Output descriptor

        Returns:
            bool: True if alert was sent successfully, False otherwise
        """
        creds = self._load_creds(descriptor)
        if not creds:
            return False

        publication = publish_alert(alert, self, descriptor)

        message = 'StreamAlert Rule Triggered - {}'.format(publication.get('rule_name', ''))
        details = {
            'description': publication.get('rule_description', ''),
            'record': publication.get('record', {})
        }
        data = {
            'service_key': creds['service_key'],
            'event_type': 'trigger',
            'description': message,
            'details': details,
            'client': 'StreamAlert'
        }

        try:
            self._post_request_retry(creds['url'], data, None, True)
        except OutputRequestFailure:
            return False

        return True


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
        """Get properties that must be assigned by the user when configuring a new PagerDuty
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

    def _dispatch(self, alert, descriptor):
        """Send alert to Pagerduty

        Args:
            alert (Alert): Alert instance which triggered a rule
            descriptor (str): Output descriptor

        Returns:
            bool: True if alert was sent successfully, False otherwise
        """
        creds = self._load_creds(descriptor)
        if not creds:
            return False

        data = events_v2_data(self, descriptor, alert, creds['routing_key'])

        try:
            self._post_request_retry(creds['url'], data, None, True)
        except OutputRequestFailure:
            return False

        return True


class PagerdutySearchDelay(Exception):
    """PagerdutyAlertDelay handles any delays looking up PagerDuty Incidents"""


@StreamAlertOutput
class PagerDutyIncidentOutput(OutputDispatcher):
    """PagerDutyIncidentOutput handles all alert dispatching for PagerDuty Incidents API v2"""
    __service__ = 'pagerduty-incident'
    INCIDENTS_ENDPOINT = 'incidents'
    USERS_ENDPOINT = 'users'
    POLICIES_ENDPOINT = 'escalation_policies'
    SERVICES_ENDPOINT = 'services'
    PRIORITIES_ENDPOINT = 'priorities'

    BACKOFF_MAX = 5
    BACKOFF_TIME = 5

    def __init__(self, *args, **kwargs):
        OutputDispatcher.__init__(self, *args, **kwargs)
        self._base_url = None
        self._headers = None
        self._escalation_policy_id = None

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
        """Get properties that must be assigned by the user when configuring a new PagerDuty
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
            ('service_name',
             OutputProperty(description='the service name for this PagerDuty integration',
                            cred_requirement=True)),
            ('service_id',
             OutputProperty(description='the service ID for this PagerDuty integration',
                            cred_requirement=True)),
            ('escalation_policy',
             OutputProperty(description='the name of the default escalation policy',
                            input_restrictions={},
                            cred_requirement=True)),
            ('escalation_policy_id',
             OutputProperty(description='the ID of the default escalation policy',
                            cred_requirement=True)),
            ('email_from',
             OutputProperty(description='valid user email from the PagerDuty '
                                        'account linked to the token',
                            cred_requirement=True)),
            ('integration_key',
             OutputProperty(description='the integration key for this PagerDuty integration',
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

    def _create_event(self, data):
        """Helper to create an event in the PagerDuty Events API v2

        Args:
            data (dict): JSON blob with the format of the PagerDuty Events API v2
        Returns:
            dict: Contains the HTTP response of the request to the API
        """
        url = 'https://events.pagerduty.com/v2/enqueue'
        try:
            resp = self._post_request_retry(url, data, None, False)
        except OutputRequestFailure:
            return False

        response = resp.json()
        if not response:
            return False

        return response

    @backoff.on_exception(backoff.constant,
                          PagerdutySearchDelay,
                          max_tries=BACKOFF_MAX,
                          interval=BACKOFF_TIME,
                          on_backoff=backoff_handler(),
                          on_success=success_handler(),
                          on_giveup=giveup_handler())
    def _get_event_incident_id(self, incident_key):
        """Helper to lookup an incident using the incident_key and return the id

        Args:
            incident_key (str): Incident key that indentifies uniquely an incident

        Returns:
            str: ID of the incident after look up the incident_key

        """
        params = {
            'incident_key': incident_key
        }
        incidents_url = self._get_endpoint(self._base_url, self.INCIDENTS_ENDPOINT)
        response = self._generic_api_get(incidents_url, params)

        incident = response.get('incidents', [])
        if not incident:
            raise PagerdutySearchDelay()

        return incident[0].get('id')

    def _merge_incidents(self, url, to_be_merged_id):
        """Helper to merge incidents by id using the PagerDuty REST API v2

        Args:
            url (str): The url to send the requests to in the API
            to_be_merged_id (str): ID of the incident to merge with

        Returns:
            dict: Contains the HTTP response of the request to the API
        """
        params = {
            'source_incidents': [
                {
                    'id': to_be_merged_id,
                    'type': 'incident_reference'
                }
            ]
        }
        try:
            resp = self._put_request_retry(url, params, self._headers, False)
        except OutputRequestFailure:
            return False

        response = resp.json()
        if not response:
            return False

        return response

    def _generic_api_get(self, url, params):
        """Helper to submit generic GET requests with parameters to the PagerDuty REST API v2

        Args:
            url (str): The url to send the requests to in the API

        Returns:
            dict: Contains the HTTP response of the request to the API
        """
        try:
            resp = self._get_request_retry(url, params, self._headers, False)
        except OutputRequestFailure:
            return False

        response = resp.json()
        if not response:
            return False

        return response

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
            'query': filter_str
        }
        response = self._generic_api_get(url, params)
        if not response:
            return False

        if not get_id:
            return True

        # We need the list to have elements
        target_element = response.get(target_key, [])
        if not target_element:
            return False

        # If there are results, get the first occurence from the list
        return target_element[0].get('id', False)

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

        try:
            resp = self._get_request_retry(priorities_url, {}, self._headers, False)
        except OutputRequestFailure:
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

        # If escalation policy ID was not provided, use default one
        policy_id_to_assign = context.get('assigned_policy_id', self._escalation_policy_id)

        # Assinged to escalation policy ID, return tuple
        return 'escalation_policy', {
            'id': policy_id_to_assign, 'type': 'escalation_policy_reference'}

    def _add_incident_note(self, incident_id, note):
        """Method to add a text note to the provided incident id

        Args:
            incident_id (str): ID of the incident to add the note to

        Returns:
            str: ID of the note after being added to the incident or False if it fails
        """
        notes_path = '{}/{}/notes'.format(self.INCIDENTS_ENDPOINT, incident_id)
        incident_notes_url = self._get_endpoint(self._base_url, notes_path)
        data = {
            'note': {
                'content': note
            }
        }
        try:
            resp = self._post_request_retry(incident_notes_url, data, self._headers, True)
        except OutputRequestFailure:
            return False

        response = resp.json()
        if not response:
            return False

        note_rec = response.get('note', {})

        return note_rec.get('id', False)

    def _dispatch(self, alert, descriptor):
        """Send incident to Pagerduty Incidents API v2

        Args:
            alert (Alert): Alert instance which triggered a rule
            descriptor (str): Output descriptor

        Returns:
            bool: True if alert was sent successfully, False otherwise
        """
        creds = self._load_creds(descriptor)
        if not creds:
            return False

        # Cache base_url
        self._base_url = creds['api']

        # Preparing headers for API calls
        self._headers = {
            'Accept': 'application/vnd.pagerduty+json;version=2',
            'Content-Type': 'application/json',
            'Authorization': 'Token token={}'.format(creds['token'])
        }

        # Get user email to be added as From header and verify
        user_email = creds['email_from']
        if not self._user_verify(user_email, False):
            LOGGER.error('Could not verify header From: %s, %s', user_email, self.__service__)
            return False

        # Add From to the headers after verifying
        self._headers['From'] = user_email

        # Cache default escalation policy
        self._escalation_policy_id = creds['escalation_policy_id']

        # Extracting context data to assign the incident
        publication = publish_alert(alert, self, descriptor)

        rule_context = alert.context
        if rule_context:
            rule_context = rule_context.get(self.__service__, {})

        # Presentation defaults
        default_incident_title = 'StreamAlert Incident - Rule triggered: {}'.format(
            alert.rule_name
        )
        default_incident_body = {
            'type': 'incident_body',
            'details': alert.rule_description,
        }

        # Override presentation defaults with publisher fields
        incident_title = publication.get(
            'pagerduty-incident.incident_title',
            default_incident_title
        )
        incident_body = publication.get('pagerduty-incident.incident_body', default_incident_body)

        # FIXME (derek.wang) use publisher to set priority instead of context
        # Use the priority provided in the context, use it or the incident will be low priority
        incident_priority = self._priority_verify(rule_context)

        # FIXME (derek.wang) use publisher to set priority instead of context
        # Incident assignment goes in this order:
        #  Provided user -> provided policy -> default policy
        assigned_key, assigned_value = self._incident_assignment(rule_context)

        # Using the service ID for the PagerDuty API
        incident_service = {'id': creds['service_id'], 'type': 'service_reference'}
        incident_data = {
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

        try:
            incident = self._post_request_retry(incidents_url, incident_data, self._headers, True)
        except OutputRequestFailure:
            incident = False

        if not incident:
            LOGGER.error('Could not create main incident, %s', self.__service__)
            return False

        # Extract the json blob from the response, returned by self._post_request_retry
        incident_json = incident.json()
        if not incident_json:
            return False

        # Extract the incident id from the incident that was just created
        incident_id = incident_json.get('incident', {}).get('id')

        # Create alert to hold all the incident details
        with_record = rule_context.get('with_record', True)
        event_data = events_v2_data(self, descriptor, alert, creds['integration_key'], with_record)
        event = self._create_event(event_data)
        if not event:
            LOGGER.error('Could not create incident event, %s', self.__service__)
            return False

        # Lookup the incident_key returned as dedup_key to get the incident id
        incident_key = event.get('dedup_key')

        if not incident_key:
            LOGGER.error('Could not get incident key, %s', self.__service__)
            return False

        # Keep that id to be merged later with the created incident
        event_incident_id = self._get_event_incident_id(incident_key)

        # Merge the incident with the event, so we can have a rich context incident
        # assigned to a specific person, which the PagerDuty REST API v2 does not allow
        merging_url = '{}/{}/merge'.format(incidents_url, incident_id)
        merged = self._merge_incidents(merging_url, event_incident_id)

        # Add a note to the combined incident to help with triage
        if not merged:
            LOGGER.error('Could not add note to incident, %s', self.__service__)
        else:
            merged_id = merged.get('incident', {}).get('id')
            note = rule_context.get('note', 'Creating SOX Incident')
            self._add_incident_note(merged_id, note)

        return True

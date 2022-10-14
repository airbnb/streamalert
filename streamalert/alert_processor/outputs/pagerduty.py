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
# pylint: disable=too-many-lines
from collections import OrderedDict

import backoff

from streamalert.alert_processor.helpers import compose_alert
from streamalert.alert_processor.outputs.output_base import (
    OutputDispatcher, OutputProperty, OutputRequestFailure, StreamAlertOutput)
from streamalert.shared.backoff_handlers import (backoff_handler,
                                                 giveup_handler,
                                                 success_handler)
from streamalert.shared.logger import get_logger

LOGGER = get_logger(__name__)

# https://support.pagerduty.com/docs/dynamic-notifications
SEVERITY_CRITICAL = 'critical'
SEVERITY_ERROR = 'error'
SEVERITY_WARNING = 'warning'
SEVERITY_INFO = 'info'
SEVERITY_UNKNOWN = 'unknown'  # empty string and any string not in the above defaults to "unknown"


class PagerdutySearchDelay(Exception):
    """PagerdutyAlertDelay handles any delays looking up PagerDuty Incidents"""


class EventsV2DataProvider:
    """This class is meant to be mixed-into pagerduty outputs that integrate with v2 of the API

    This is called the CommonEventFormat (PD-CEF). Documentation can be found here:
    https://support.pagerduty.com/docs/pd-cef
    """
    def events_v2_data(self, alert, descriptor, routing_key, with_record=True):
        """Helper method to generate the payload to create an event using PagerDuty Events API v2

        (!) NOTE: this method will not work unless this class is mixed into an OutputDispatcher

        Publishing:
            By default the pagerduty event is setup with a blob of data comprising the rule
            description and the record in the custom details. You can customize behavior with
            the following fields:

            - @pagerduty-v2:summary (str):
                    Modifies the title of the event

            - @pagerduty-v2.custom_details (dict):
                    Fills out the pagerduty customdetails with this structure.

                    (!) NOTE: Due to PagerDuty's UI, it is extremely hard to read very deeply
                        nested JSON dicts. It is also extremely hard to read large blobs of data.
                        Try to collapse deeply nested structures into single-level keys, and
                        try to truncate blobs of data.

            - @pagerduty-v2:severity (string):
                    By default the severity of alerts are "critical". You can override this with
                    any of the following:
                    'info', 'warning', 'error', 'critical'

        Args:
            descriptor (str): The descriptor of the output sending these data
            alert (Alert): Alert relevant to the triggered rule
            routing_key (str): Routing key for this PagerDuty integration
            with_record (boolean): Option to add the record data or not

        Returns:
            dict: Contains JSON blob to be used as event
        """
        publication = compose_alert(alert, self, descriptor)

        # Presentation defaults
        default_summary = f'StreamAlert Rule Triggered - {alert.rule_name}'
        default_custom_details = OrderedDict()
        default_custom_details['description'] = alert.rule_description
        if with_record:
            default_custom_details['record'] = alert.record
        default_severity = SEVERITY_CRITICAL

        # Special field that Publishers can use to customize the header
        summary = publication.get('@pagerduty-v2.summary', default_summary)
        details = publication.get('@pagerduty-v2.custom_details', default_custom_details)
        severity = publication.get('@pagerduty-v2.severity', default_severity)
        client_url = publication.get('@pagerduty-v2.client_url', None)
        images = self._standardize_images(publication.get('@pagerduty-v2.images', []))
        links = self._standardize_links(publication.get('@pagerduty-v2.links', []))
        component = publication.get('@pagerduty-v2.component', None)
        group = publication.get('@pagerduty-v2.group', None)
        alert_class = publication.get('@pagerduty-v2.class', None)

        # We namespace the dedup_key by the descriptor, preventing situations where a single
        # alert sending to multiple PagerDuty services from having colliding dedup_keys, which
        # would PROBABLY be ok (because of segregated environments) but why take the risk?
        dedup_key = f'{descriptor}:{alert.alert_id}'

        # Structure: https://v2.developer.pagerduty.com/docs/send-an-event-events-api-v2
        return {
            'routing_key': routing_key,
            'event_action': 'trigger',

            # Passing a dedup_key will ensure that only one event is ever created. Any subsequent
            # request with the same dedup_key + routing_key + event_action will simply return
            # the original result.
            # Once the alert is resolved, the dedup_key can be re-used.
            # https://v2.developer.pagerduty.com/docs/events-api-v2#alert-de-duplication
            'dedup_key': dedup_key,
            'payload': {
                'summary': summary,
                'source': alert.log_source,
                'severity': severity,
                'custom_details': details,

                # When provided, must be in valid ISO 8601 format
                # 'timestamp': '',
                'component': component,
                'group': group,
                'class': alert_class,
            },
            'client': 'StreamAlert',
            'client_url': client_url,
            'images': images,
            'links': links,
        }

    @staticmethod
    def _standardize_images(images):
        """Strips invalid images out of the images argument

        Images should be dicts with 3 keys:
            - src: The full http URL of the image
            - href: A URL that the image opens when clicked (Optional)
            - alt: Alt text (Optional)
        """
        if not isinstance(images, list):
            return []

        return [
            {
                # Notably, if href is provided but is an invalid URL, the entire image will
                # be entirely omitted from the incident... beware.
                'src': image['src'],
                'href': image['href'] if 'href' in image else '',
                'alt': image['alt'] if 'alt' in image else '',
            } for image in images if isinstance(image, dict) and 'src' in image
        ]

    @staticmethod
    def _standardize_links(links):
        """Strips invalid links out of the links argument

        Images should be dicts with 2 keys:
           - href: A URL of the link
           - text: Text of the link (Optional: Defaults to the href if no text given)
        """
        return [{
            'href': link['href'],
            'text': link['text'] if 'text' in link else link['href'],
        } for link in links
                if isinstance(link, dict) and 'href' in link] if isinstance(links, list) else []


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
        return {'url': PagerDutyEventsV1ApiClient.EVENTS_V1_API_ENDPOINT}

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
            # A version 4 UUID expressed as a 32 digit hexadecimal number. This is the
            # integration key for an integration on a given service and can be found on
            # the pagerduty integrations UI.
            ('service_key',
             OutputProperty(description='the service key for this PagerDuty integration',
                            mask_input=True,
                            cred_requirement=True))
        ])

    def _dispatch(self, alert, descriptor):
        """Send alert to Pagerduty

        Publishing:
            This output can be override with the following fields:

            - @pagerduty.description (str):
                    The provided string will be rendered as the event's title.

            - @pagerduty.details (dict):
                    By default this output renders rule description and rule record in a deeply
                    nested json structure. You can override this with your own dict.

                    (!) NOTE: Due to PagerDuty's UI, it is extremely hard to read very deeply
                        nested JSON dicts. It is also extremely hard to read large blobs of data.
                        Try to collapse deeply nested structures into single-level keys, and
                        try to truncate blobs of data.

            - @pagerduty.client_url (str):
                    A URL. It should be a link to the same alert in a different service.
                    When given, there will be a "view in streamalert" link given at the bottom.
                    Currently this 'streamalert' string is hardcoded into the api client
                    as the 'client' field.

                    This is not included in the default implementation.

            - @pagerduty.contexts (list[dict]):
                    This field can be used to automatically attach images and links to the incident
                    event. This should be a list of dicts. Each dict should follow ONE OF these
                    formats:

                    Link:
                        {
                            'type': 'link',
                            'href': 'https://streamalert.io/',
                            'text': 'Link Text'
                        }

                    Image embed
                        {
                            'type': 'image',
                            'src': 'https://streamalert.io/en/stable/_images/sa-complete-arch.png',
                        }

                    This is not included in the default implementation.

        Args:
            alert (Alert): Alert instance which triggered a rule
            descriptor (str): Output descriptor

        Returns:
            bool: True if alert was sent successfully, False otherwise
        """
        creds = self._load_creds(descriptor)
        if not creds:
            return False

        # Presentation defaults
        default_description = f'StreamAlert Rule Triggered - {alert.rule_name}'
        default_details = {
            'description': alert.rule_description,
            'record': alert.record,
        }
        default_contexts = []
        default_client_url = ''

        # Override presentation with publisher
        publication = compose_alert(alert, self, descriptor)
        description = publication.get('@pagerduty.description', default_description)
        details = publication.get('@pagerduty.details', default_details)
        client_url = publication.get('@pagerduty.client_url', default_client_url)
        contexts = publication.get('@pagerduty.contexts', default_contexts)
        contexts = self._strip_invalid_contexts(contexts)

        http = JsonHttpProvider(self)
        client = PagerDutyEventsV1ApiClient(creds['service_key'], http, api_endpoint=creds['url'])

        return client.send_event(description, details, contexts, client_url)

    @staticmethod
    def _strip_invalid_contexts(contexts):
        """When an array of contexts, will return a new array containing only valid ones."""
        if not isinstance(contexts, list):
            LOGGER.warning('Invalid pagerduty.contexts provided: Not an array')
            return []

        def is_valid_context(context):
            if 'type' not in context:
                return False

            if context['type'] == 'link':
                if 'href' not in context or 'text' not in context:
                    return False
            elif context['type'] == 'image':
                if 'src' not in context:
                    return False
            else:
                return False

            return True

        def standardize_context(context):
            if context['type'] == 'link':
                return {
                    'type': 'link',
                    'href': context['href'],
                    'text': context['text'],
                }
            return {
                'type': 'image',
                'src': context['src'],
            }

        return [standardize_context(x) for x in contexts if is_valid_context(x)]


@StreamAlertOutput
class PagerDutyOutputV2(OutputDispatcher, EventsV2DataProvider):
    """PagerDutyOutput handles all alert dispatching for PagerDuty Events API v2"""
    __service__ = 'pagerduty-v2'

    @classmethod
    def _get_default_properties(cls):
        """Get the standard url used for PagerDuty Events API v2. This value the same for
        everyone, so is hard-coded here and does not need to be configured by the user

        Returns:
            dict: Contains various default items for this output (ie: url)
        """
        return {'url': PagerDutyEventsV2ApiClient.EVENTS_V2_API_ENQUEUE_ENDPOINT}

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

        Publishing:
            @see EventsV2DataProvider for more details

        Args:
            alert (Alert): Alert instance which triggered a rule
            descriptor (str): Output descriptor

        Returns:
            bool: True if alert was sent successfully, False otherwise
        """
        creds = self._load_creds(descriptor)
        if not creds:
            return False

        data = self.events_v2_data(alert, descriptor, creds['routing_key'])

        http = JsonHttpProvider(self)
        client = PagerDutyEventsV2ApiClient(http, enqueue_endpoint=creds['url'])

        result = client.enqueue_event(data)

        return result is not False


@StreamAlertOutput
class PagerDutyIncidentOutput(OutputDispatcher, EventsV2DataProvider):
    """PagerDutyIncidentOutput handles all alert dispatching for PagerDuty Incidents REST API

    In addition to creating an Alert through the EventsV2 API, this output will then find the
    PagerDuty Incident that is created and automatically reassign, add more details, set priority,
    add a note, and attach any additional responders to the incident.


    Context:
        - assigned_user (string):
                Email address of user to assign the incident to. If omitted will default to
                the service's default escalation policy. If the email address is not
                associated with a user in PagerDuty, it will log a warning and default to
                the service's escalation policy.

        - with_record (bool):
                True to include the entire record in the Alert's payload. False to omit it.
                Will be superseded by certain @pagerduty-v2 fields.

        - note (bool):
                A text note that is added to the Incident. Will be superseded by publisher
                fields (see below).

        - responders (list<string>):
                A list of email addresses of users to add as Requested Responders. If any
                email address is not associated with a user in PagerDuty, it will be omitted
                and a warning will be logged.

        - responder_message (string)
                Text string that shows up in Response Request messages sent to requested
                responders.


    Publishing:
        This output has a more complex workflow. The magic publisher fields for @pagerduty-v2
        ALSO are respected by this output.

        - @pagerduty-incident.incident_title (str):
                The provided string will show up in the PagerDuty incident's title.

                The child Alert's
                title is controlled by other publisher magic fields.

        - @pagerduty-incident.note (str):
                Due to legacy reasons, this PagerDuty services adds a note containing
                "Creating SOX Incident" to the final PagerDuty incident. Providing a string
                to this magic field will override that behavior.

        - @pagerduty-incident.urgency (str):
                Either "low" or "high". By default urgency is "high" for all incidents.


        - @pagerduty-incident.incident_body (str):
                @deprecated
                This is a legacy field that no longer serves any functionality. It populates
                a field on the PagerDuty Incident that is never visible.


        @see Also EventsV2DataProvider for more details
    """
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
        return {'api': PagerDutyRestApiClient.REST_API_BASE_URL}

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
            # The REST API Access Token. This needs to be generated through the PagerDuty console.
            # Unlike the routing key this token is EXTREMELY IMPORTANT NOT TO LOSE as it grants
            # access to all resources on PagerDuty, whereas the routing key only allows
            # the generation of new events.
            ('token',
             OutputProperty(description='the token for this PagerDuty integration',
                            mask_input=True,
                            cred_requirement=True)),
            ('service_name',
             OutputProperty(description='the service name for this PagerDuty integration',
                            cred_requirement=True)),
            # The service ID is the unique resource ID of a PagerDuty service, created through
            # the UI. You can find the service id by looking at the URL:
            # - www.pagerduty.com/services/PDBBCC9
            #
            # In the above case, the service id is 'PDBBCC9'
            ('service_id',
             OutputProperty(description='the service ID for this PagerDuty integration',
                            cred_requirement=True)),
            ('escalation_policy',
             OutputProperty(description='the name of the default escalation policy',
                            input_restrictions={},
                            cred_requirement=True)),
            # The escalation policy ID is the unique resource ID of a PagerDuty escalation policy,
            # created through the UI. You can find it on the URL:
            # - www.pagerduty.com/escalation_policies#PDBBBB0
            #
            # In the above case, the escalation policy id is PDBBBB0
            ('escalation_policy_id',
             OutputProperty(description='the ID of the default escalation policy',
                            cred_requirement=True)),
            # This must exactly match the email address of a user on the PagerDuty account.
            ('email_from',
             OutputProperty(description='valid user email from the PagerDuty '
                            'account linked to the token',
                            cred_requirement=True)),
            # A version 4 UUID expressed as a 32 digit hexadecimal number. This is the same
            # as the routing key that is used in the v2 Events API.
            ('integration_key',
             OutputProperty(description='the integration key for this PagerDuty integration',
                            cred_requirement=True))
        ])

    def _dispatch(self, alert, descriptor):
        """Send incident to Pagerduty Incidents REST API v2

        Args:
            alert (Alert): Alert instance which triggered a rule
            descriptor (str): Output descriptor

        Returns:
            bool: True if alert was sent successfully, False otherwise
        """
        creds = self._load_creds(descriptor)
        if not creds:
            return

        work = WorkContext(self, creds)
        return work.run(alert, descriptor)


class WorkContext:
    """Class encapsulating a bunch of self-contained, interdependent PagerDuty work.

    Because PagerDuty work involves a lot of steps that share a lot of data, we carved this
    section out.
    """
    BACKOFF_MAX = 5
    BACKOFF_TIME = 5

    def __init__(self, output_dispatcher, credentials):
        self._output = output_dispatcher
        self._credentials = credentials

        self._email_from = self._credentials['email_from']
        self._default_escalation_policy_id = self._credentials['escalation_policy_id']
        self._incident_service = self._credentials['service_id']

        http = JsonHttpProvider(output_dispatcher)
        self._api_client = PagerDutyRestApiClient(self._credentials['token'],
                                                  self._credentials['email_from'],
                                                  http,
                                                  url=self._credentials['api'])
        self._events_client = PagerDutyEventsV2ApiClient(http)

        # We cache the API User because we may use it multiple times
        self._api_user = None

    def run(self, alert, descriptor):
        """Sets up an assigned incident."""
        if not self._verify_user_exists():
            return False

        # Extracting context data to assign the incident
        rule_context = alert.context
        if rule_context:
            rule_context = rule_context.get(self._output.__service__, {})

        publication = compose_alert(alert, self._output, descriptor)

        # Create alert to hold all the incident details
        event = self._create_base_alert_event(alert, descriptor, rule_context)
        if not event:
            LOGGER.error('[%s] Could not create incident event', self._output.__service__)
            return False

        # Create an incident to house the alert
        incident = self._update_base_incident(event, alert, publication, rule_context)
        if not incident:
            LOGGER.error('[%s] Failed to update container incident for event',
                         self._output.__service__)
            return False

        incident_id = incident.get('id', False)
        if not incident_id:
            LOGGER.error('[%s] Incident is missing "id"??', self._output.__service__)
            return False

        # At this point, both the incident and the relevant alert event have been successfully
        # created.
        #
        # All of the code above this line is considered idempotent and can be called repeatedly
        # without adverse side effects. Code BELOW this line is neither atomic nor idempotent, so
        # we will not retry if any of the below code fails. Instead, we log an error and make a
        # best-effort attempt to attach an error note to the PagerDuty incident, signalling that
        # it was not setup properly.
        #
        # In the fateful event the alert gets stuck ANYWAY, the easiest solution is to destroy the
        # associated record on the DynamoDB table.
        errors = []

        # Add responder requests
        responders = rule_context.get('responders', [])
        if responders and not isinstance(responders, list):
            responders = [responders]

        if responders:
            # The message shows up in the email
            default_message = 'An incident was reported that requires your attention.'
            responder_message = rule_context.get('responder_message', default_message)

            for responder_email in responders:
                result = self._add_incident_response_request(incident_id, responder_email,
                                                             responder_message)
                if not result:
                    error = f'[{self._output.__service__}] Failed to request a responder ({responder_email}) on incident ({incident_id})'

                    LOGGER.error(error)
                    errors.append(error)

        # Add a note to the incident
        note = self._add_incident_note(incident_id, publication, rule_context)
        if not note:
            error = f'[{self._output.__service__}] Failed to add note to incident ({incident_id})'

            LOGGER.error(error)
            errors.append(error)

        # If something went wrong, we can't throw an error anymore; log it on the Incident
        if errors:
            self._add_instability_note(incident_id, errors)

        return True

    def _add_instability_note(self, incident_id, errors):
        error_section = '\n'.join([f'- {err}' for err in errors])
        instability_note = '''
StreamAlert failed to correctly setup this incident. Please contact your StreamAlert administrator.

Errors:
{}
        '''.format(error_section).strip()
        self._api_client.add_note(incident_id, instability_note)

    def _update_base_incident(self, event, alert, publication, rule_context):
        """Given an event, will find the container incident and update it.

        In PagerDuty's REST API design, Incidents are designed to behave like containers for many
        alerts. Unlike alerts, Incidents can be given custom assignments and escalation policies.

        When an alert is created through the EventsV2 API, PagerDuty automatically creates an
        incident to contain it. The Incident resource that is created is given an "incident_key"
        that is identical to the "dedup_key" of the Event.

        Returns the updated incident as a JSON dict. Returns False if anything goes wrong.
        """
        incident_key = event.get('dedup_key')
        if not incident_key:
            LOGGER.error('[%s] Event created is missing its "dedup_key"? %s',
                         self._output.__service__, event)
            return False

        event_incident_id = self._get_incident_id_from_event_incident_key(incident_key)
        if not event_incident_id:
            LOGGER.error('[%s] Failed to retrieve Event Incident Id from dedup_key (%s)',
                         self._output.__service__, incident_key)
            return False

        incident_data = self._construct_incident_put_request_data(alert, publication, rule_context)

        return self._api_client.modify_incident(event_incident_id, incident_data)

    def _construct_incident_put_request_data(self, alert, publication, rule_context):
        """Builds the payload for an HTTP PUT /incidents/:incident_id request

        Returns it as a JSON dict
        """

        # Presentation defaults
        default_incident_title = f'StreamAlert Incident - Rule triggered: {alert.rule_name}'

        default_incident_body = alert.rule_description
        default_urgency = None  # Assumes the default urgency on the service referenced

        # Override presentation defaults with publisher fields
        incident_title = publication.get('@pagerduty-incident.incident_title',
                                         default_incident_title)
        incident_body = publication.get('@pagerduty-incident.incident_body', default_incident_body)
        incident_urgency = publication.get('@pagerduty-incident.urgency', default_urgency)

        # https://api-reference.pagerduty.com/#!/Incidents/post_incidents
        incident_data = {
            'incident': {
                'type': 'incident',
                'title': incident_title,
                'service': {
                    'id': self._incident_service,
                    'type': 'service_reference'
                },
                'body': {
                    'type': 'incident_body',
                    # Notably, the incident body is basically useless and doesn't show up on the
                    # UI if the Incident has an alert attached to it.
                    'details': incident_body,
                },

                # The incident_key behaves very similarly to the deduplication key, but subsequent
                # requests to create a second incident with the same incident_key will return an
                # HTTP 400 instead of returning the original result.
                # https://v2.developer.pagerduty.com/docs/incident-creation-api#making-a-request
                #
                # The incident_key is a super bizarre field.
                #
                # AS-FAR-AS-I-CAN-TELL it functions something like this:
                #
                # - If you create an incident with incident_key A, any subsequent requests to
                #   create another incident with the same incident_key will return an HTTP 400
                # - If you create an event using EventsV2 API (with or without a dedup_key), the
                #   associated incident_key of the incident that is automatically created from
                #   the event will be the same as the dedup_key
                # - If you create an event with EventsV2 API and attempt to then create an incident
                #   with an incident_key that is the same as the dedup_key, instead of returning
                #   an HTTP 400, it will return the incident that was originally created from the
                #   EventsV2 API... "idempotently".
                #
                # 'incident_key': '',
            }
        }

        if incident_priority := self._get_standardized_priority(rule_context):
            incident_data['incident']['priority'] = incident_priority

        if assignments := self._get_incident_assignments(rule_context):
            incident_data['incident']['assignments'] = assignments
        else:
            # Important detail;
            #   'assignments' and 'escalation_policy' seem to be exclusive. If you send both, the
            #   'escalation_policy' seems to supersede any custom assignments you have.
            escalation_policy = self._get_incident_escalation_policy(rule_context)
            incident_data['incident']['escalation_policy'] = escalation_policy

        # Urgency, if provided, must always be 'high' or 'low' or the API will error
        if incident_urgency:
            if incident_urgency in ['low', 'high']:
                incident_data['incident']['urgency'] = incident_urgency
            else:
                LOGGER.warning('[%s] Invalid pagerduty incident urgency: "%s"',
                               self._output.__service__, incident_urgency)

        return incident_data

    def _get_incident_assignments(self, rule_context):
        assignments = False
        if user_to_assign := rule_context.get('assigned_user', False):
            user = self._api_client.get_user_by_email(user_to_assign)
            if user and user.get('id'):
                assignments = [{
                    'assignee': {
                        'id': user.get('id'),
                        'type': 'user_reference',
                    }
                }]
            else:
                LOGGER.warning('[%s] Assignee (%s) could not be found in PagerDuty',
                               self._output.__service__, user_to_assign)
        return assignments

    def _get_incident_escalation_policy(self, rule_context):
        # If escalation policy ID was not provided, use default one
        policy_id_to_assign = rule_context.get('assigned_policy_id',
                                               self._default_escalation_policy_id)
        # Assigned to escalation policy ID, return tuple
        return {'id': policy_id_to_assign, 'type': 'escalation_policy_reference'}

    def _create_base_alert_event(self, alert, descriptor, rule_context):
        """Creates an alert on REST API v2

        Returns the JSON representation of the ENQUEUE RESPONSE. This actually does not return
        either the alert nor the incident itself, but rather a small acknowledgement structure
        containing a "dedup_key". This key can be used to find the incident that is created.

        This method is idempotent. The calls out to PagerDuty will create a new alert+incident,
        or return the existing one if this method has already been called.

        Returns False if event was not created.
        """
        with_record = rule_context.get('with_record', True)
        event_data = self._output.events_v2_data(alert,
                                                 descriptor,
                                                 self._credentials['integration_key'],
                                                 with_record=with_record)

        return self._events_client.enqueue_event(event_data)

    def _add_incident_response_request(self, incident_id, responder_email, message):
        responder = self._api_client.get_user_by_email(responder_email)
        if not responder:
            LOGGER.error('Could not verify if requested incident responder "%s" exists',
                         responder_email)
            return False

        return bool(
            self._api_client.request_responder(incident_id, self._api_user.get('id'), message,
                                               responder.get('id')))

    def _add_incident_note(self, incident_id, publication, rule_context):
        """Adds a note to the incident, when applicable.

        Returns:
            bool: True if the note was created or no note needed to be created, False on error.
        """

        # Add a note to the combined incident to help with triage
        default_incident_note = 'Creating SOX Incident'  # For reverse compatibility reasons
        incident_note = publication.get('@pagerduty-incident.note',
                                        rule_context.get('note', default_incident_note))

        return bool(self._api_client.add_note(incident_id,
                                              incident_note)) if incident_note else True

    @backoff.on_exception(backoff.constant,
                          PagerdutySearchDelay,
                          max_tries=BACKOFF_MAX,
                          interval=BACKOFF_TIME,
                          on_backoff=backoff_handler(),
                          on_success=success_handler(),
                          on_giveup=giveup_handler())
    def _get_incident_id_from_event_incident_key(self, incident_key):
        """Queries the API to get the incident id from an incident key

        When creating an EVENT from the events-v2 API, events are created alongside an incident,
        but only an incident_key is returned, which is not the same as the incident's REST API
        resource id.

        (!) WARNING: This method can sometimes fail even if an event was successfully created.
            Pagerduty can sometimes experience a small amount of "lag time" between when an
            Event is created and when its containing Incident is searchable via this API.
            Therefore, all code that calls this method must account for the possibility that this
            method can be inconsistent with the state of the "real world", and should retry as
            appropriate.
        """
        if not incident_key:
            return False

        if event_incident := self._api_client.get_incident_by_key(incident_key):
            return event_incident.get('id')
        raise PagerdutySearchDelay('Received no PagerDuty response')

    def _verify_user_exists(self):
        """Verifies that the 'email_from' provided in the creds is valid and exists."""
        user = self._api_client.get_user_by_email(self._email_from)

        if not user:
            LOGGER.error('Could not verify header From: %s, %s', self._email_from,
                         self._output.__service__)
            return False

        self._api_user = user

        return True

    def _get_standardized_priority(self, context):
        """Method to verify the existence of a incident priority with the API

        Uses the priority provided in the context. When omitted the incident defaults to low
        priority.

        Args:
            context (dict): Context provided in the alert record

        Returns:
            dict|False: JSON object be used in the API call, containing the priority id
                        and the priority reference, False if it fails or it does not exist
        """
        if not context:
            return False

        # FIXME (derek.wang) use publisher to set priority instead of context
        priority_name = context.get('incident_priority', False)
        if not priority_name:
            return False

        if priorities := self._api_client.get_priorities():
            return {
                'id': priority_id,
                'type': 'priority_reference'
            } if (priority_id := next(
                (item for item in priorities
                 if item["name"] == priority_name), {}).get('id', False)) else False
        return False


# pylint: disable=protected-access
class JsonHttpProvider:
    """Wraps and re-uses the HTTP implementation on the output dispatcher.

    Intended to de-couple the ApiClient classes from the OutputDispatcher. It re-uses some
    HTTP implementation that's baked into the OutputDispatcher. It is safe to ignore the
    breach-of-abstraction violations here.
    """
    def __init__(self, output_dispatcher):
        self._output_dispatcher = output_dispatcher

    def get(self, url, params, headers=None, verify=False):
        """Returns the JSON response of the given request, or FALSE on failure"""
        try:
            result = self._output_dispatcher._get_request_retry(url, params, headers, verify)
        except OutputRequestFailure as e:
            LOGGER.error('Encountered HTTP error on GET %s: %s', url, e.response)
            return False

        response = result.json()
        return response or False

    def post(self, url, data, headers=None, verify=False):
        """Returns the JSON response of the given request, or FALSE on failure"""
        try:
            result = self._output_dispatcher._post_request_retry(url, data, headers, verify)
        except OutputRequestFailure as e:
            LOGGER.error('Encountered HTTP error on POST %s: %s', url, e.response)
            return False

        response = result.json()
        return response or False

    def put(self, url, params, headers=None, verify=False):
        """Returns the JSON response of the given request, or FALSE on failure"""
        try:
            result = self._output_dispatcher._put_request_retry(url, params, headers, verify)
        except OutputRequestFailure as e:
            LOGGER.error('Encountered HTTP error on PUT %s: %s', url, e.response)
            return False

        response = result.json()
        return response or False


class SslVerifiable:
    """Mixin for tracking whether or not this is an SSL verifiable.

    Mix this into API client types of classes.

    The idea is to only do host ssl certificate verification on the very first time a unique
    host is hit, since the handshake process is slow. Subsequent requests to the same host
    within the current request can void certificate verification to speed things up.
    """
    def __init__(self):
        self._host_ssl_verified = False

    def _should_do_ssl_verify(self):
        """Returns whether or not the client should perform SSL host cert verification"""
        return not self._host_ssl_verified

    def _update_ssl_verified(self, response):
        """
        Args:
            response (dict|bool): A return value from JsonHttpProvider

        Returns:
            dict|bool: Simply returns the response as-is
        """
        if response is not False:
            self._host_ssl_verified = True

        return response


class PagerDutyRestApiClient(SslVerifiable):
    """API Client class for the PagerDuty REST API

    API Documentation can be found here: https://v2.developer.pagerduty.com/docs/rest-api
    """

    REST_API_BASE_URL = 'https://api.pagerduty.com'

    def __init__(self, authorization_token, user_email, http_provider, url=None):
        super().__init__()

        self._authorization_token = authorization_token
        self._user_email = user_email
        self._http_provider = http_provider  # type: JsonHttpProvider
        self._base_url = url or self.REST_API_BASE_URL

    def get_user_by_email(self, user_email):
        """Fetches a pagerduty user by an email address.

        Returns false on failure or if no matching user is found.
        """
        response = self._http_provider.get(self._get_users_url(), {
            'query': user_email,
        },
                                           self._construct_headers(omit_email=True),
                                           verify=self._should_do_ssl_verify())
        self._update_ssl_verified(response)

        if not response:
            return False

        users = response.get('users', [])

        return users[0] if users else False

    def get_incident_by_key(self, incident_key):
        """Fetches an incident resource given its key

        Returns False on failure or if no matching incident is found.
        """
        incidents = self._http_provider.get(
            self._get_incidents_url(),
            {
                'incident_key': incident_key  # Beware: this key is intentionally not "query"
            },
            headers=self._construct_headers(),
            verify=self._should_do_ssl_verify())
        self._update_ssl_verified(incidents)

        if not incidents:
            return False

        incidents = incidents.get('incidents', [])

        return incidents[0] if incidents else False

    def get_priorities(self):
        """Returns a list of all valid priorities"""
        priorities = self._http_provider.get(self._get_priorities_url(),
                                             None,
                                             headers=self._construct_headers(),
                                             verify=self._should_do_ssl_verify())
        self._update_ssl_verified(priorities)

        return priorities.get('priorities', []) if priorities else False

    def get_escalation_policy_by_id(self, escalation_policy_id):
        """Given an escalation policy id, returns the resource

        Returns False on failure or if no escalation policy exists with that id
        """
        escalation_policies = self._http_provider.get(self._get_escalation_policies_url(), {
            'query': escalation_policy_id,
        },
                                                      headers=self._construct_headers(),
                                                      verify=self._should_do_ssl_verify())
        self._update_ssl_verified(escalation_policies)

        if not escalation_policies:
            return False

        escalation_policies = escalation_policies.get('escalation_policies', [])

        return escalation_policies[0] if escalation_policies else False

    def modify_incident(self, incident_id, incident_data):
        """Modifies an existing Incident

        Returns the incident json representation on success, or False on failure.

        Reference: https://api-reference.pagerduty.com/#!/Incidents/post_incidents

        Args:
            incident_data (dict)

        Returns:
            dict
        """
        incident = self._http_provider.put(self._get_incident_url(incident_id),
                                           incident_data,
                                           headers=self._construct_headers(),
                                           verify=self._should_do_ssl_verify())
        self._update_ssl_verified(incident)

        return incident.get('incident', False) if incident else False

    def add_note(self, incident_id, note):
        """Method to add a text note to the provided incident id

        Returns the note json representation on success, or False on failure.

        Reference: https://api-reference.pagerduty.com/#!/Incidents/post_incidents_id_notes

        Args:
            incident_id (str): ID of the incident to add the note to

        Returns:
            str: ID of the note after being added to the incident or False if it fails
        """
        note = self._http_provider.post(self._get_incident_notes_url(incident_id),
                                        {'note': {
                                            'content': note,
                                        }},
                                        self._construct_headers(),
                                        verify=self._should_do_ssl_verify())
        self._update_ssl_verified(note)

        return note.get('note', False) if note else False

    def request_responder(self, incident_id, requester_user_id, message, responder_user_id):
        # Be very careful with this API endpoint, there are several things you will need to know:
        #
        # 1) The requester_id MUST match the user associated with the API token
        # 2) Both the requester_id and the responder id must have pagerduty accounts. If EITHER
        #    of them don't, this API endpoint actually exhibits strange behavior; instead of
        #    returning an HTTP 400 with a useful error message, it will return an HTTP 404.
        # 3) You cannot add a requester to an incident that is resolved, it will also 404.
        responder_request = self._http_provider.post(
            self._get_incident_responder_requests_url(incident_id), {
                'requester_id':
                requester_user_id,
                'message':
                message,
                'responder_request_targets': [{
                    'responder_request_target': {
                        'id': responder_user_id,
                        'type': 'user_reference',
                    }
                }]
            },
            self._construct_headers(),
            verify=self._should_do_ssl_verify())
        self._update_ssl_verified(responder_request)

        return responder_request.get('responder_request', False) if responder_request else False

    def _construct_headers(self, omit_email=False):
        """Returns a dict containing all headers to send for PagerDuty requests

        PagerDuty performs validation on the email provided in the From: header. PagerDuty will
        error if the requested email does not exist. In one specific case, we do not want this to
        happen; when we are querying for the existence of a user with this email.
        """
        headers = {
            'Accept': 'application/vnd.pagerduty+json;version=2',
            'Authorization': f'Token token={self._authorization_token}',
            'Content-Type': 'application/json'
        }

        if not omit_email:
            headers['From'] = self._user_email

        return headers

    def _get_escalation_policies_url(self):
        return f'{self._base_url}/escalation_policies'

    def _get_priorities_url(self):
        return f'{self._base_url}/priorities'

    def _get_incidents_url(self):
        return f'{self._base_url}/incidents'

    def _get_incident_url(self, incident_id):
        return '{incidents_url}/{incident_id}'.format(incidents_url=self._get_incidents_url(),
                                                      incident_id=incident_id)

    def _get_incident_notes_url(self, incident_id):
        return f'{self._get_incident_url(incident_id)}/notes'

    def _get_incident_responder_requests_url(self, incident_id):
        return '{incident_url}/responder_requests'.format(
            incident_url=self._get_incident_url(incident_id))

    def _get_users_url(self):
        return f'{self._base_url}/users'


class PagerDutyEventsV2ApiClient(SslVerifiable):
    """Service for finding URLs of various resources on the Events v2 API

    Documentation on Events v2 API: https://v2.developer.pagerduty.com/docs/events-api-v2
    """

    EVENTS_V2_API_ENQUEUE_ENDPOINT = 'https://events.pagerduty.com/v2/enqueue'

    def __init__(self, http_provider, enqueue_endpoint=None):
        super().__init__()

        self._http_provider = http_provider  # type: JsonHttpProvider
        self._enqueue_endpoint = enqueue_endpoint or self.EVENTS_V2_API_ENQUEUE_ENDPOINT

    def enqueue_event(self, event_data):
        """Enqueues a new event.

        Returns the event json representation on success, or False on failure.

        Note: For API v2, all authentication information is baked directly into the event_data,
        rather than being provided in the headers.
        """
        event = self._http_provider.post(self._get_event_enqueue_v2_url(),
                                         event_data,
                                         headers=None,
                                         verify=self._should_do_ssl_verify())
        self._update_ssl_verified(event)

        return event

    def _get_event_enqueue_v2_url(self):
        return self._enqueue_endpoint or f'{self.EVENTS_V2_API_ENQUEUE_ENDPOINT}'


class PagerDutyEventsV1ApiClient(SslVerifiable):
    """Service for finding URLs of various resources on the Events v1 API

    API Documentation can be found here: https://v2.developer.pagerduty.com/docs/events-api
    """

    EVENTS_V1_API_ENDPOINT = 'https://events.pagerduty.com/generic/2010-04-15/create_event.json'

    EVENT_TYPE_TRIGGER = 'trigger'
    EVENT_TYPE_ACKNOWLEDGE = 'acknowledge'
    EVENT_TYPE_RESOLVE = 'resolve'

    CLIENT_STREAMALERT = 'streamalert'

    def __init__(self, service_key, http_provider, api_endpoint=None):
        super().__init__()

        self._service_key = service_key
        self._http_provider = http_provider  # type: JsonHttpProvider
        self._api_endpoint = api_endpoint or self.EVENTS_V1_API_ENDPOINT

    def send_event(self, incident_description, incident_details, contexts, client_url=''):
        """
        Args:
            incident_description (str): The title of the alert
            incident_details (dict): Arbitrary JSON object that is rendered in custom details field
            contexts (array): Array of context dicts, which can be used to embed links or images.
            client_url (string): An external URL that appears as a link on the event.

        Return:
            dict: The JSON representation of the created event
        """
        # Structure of body: https://v2.developer.pagerduty.com/docs/trigger-events
        data = {
            'service_key': self._service_key,
            'event_type': self.EVENT_TYPE_TRIGGER,
            'description': incident_description,
            'details': incident_details,
            'client': self.CLIENT_STREAMALERT,
            'client_url': client_url,
            'contexts': contexts,
        }
        result = self._http_provider.post(self._api_endpoint,
                                          data,
                                          headers=None,
                                          verify=self._should_do_ssl_verify())
        self._update_ssl_verified(result)

        return result

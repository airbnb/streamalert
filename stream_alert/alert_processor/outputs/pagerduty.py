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
from collections import OrderedDict
import backoff

from stream_alert.alert_processor.helpers import compose_alert
from stream_alert.alert_processor.outputs.output_base import (
    OutputDispatcher,
    OutputProperty,
    OutputRequestFailure,
    StreamAlertOutput
)
from stream_alert.shared.backoff_handlers import (
    backoff_handler,
    success_handler,
    giveup_handler
)
from stream_alert.shared.logger import get_logger


LOGGER = get_logger(__name__)

# https://support.pagerduty.com/docs/dynamic-notifications
SEVERITY_CRITICAL = 'critical'
SEVERITY_ERROR = 'error'
SEVERITY_WARNING = 'warning'
SEVERITY_INFO = 'info'
SEVERITY_UNKNOWN = 'unknown'  # empty string and any string not in the above defaults to "unknown"


class PagerdutySearchDelay(Exception):
    """PagerdutyAlertDelay handles any delays looking up PagerDuty Incidents"""


class EventsV2DataProvider(object):
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
        default_summary = 'StreamAlert Rule Triggered - {}'.format(alert.rule_name)
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

        # Structure: https://v2.developer.pagerduty.com/docs/send-an-event-events-api-v2
        return {
            'routing_key': routing_key,
            'event_action': 'trigger',

            # Beware of providing this; when this is provided, even if empty string, this will
            # cause the dedup_key to be bound to the ALERT, not the incident. The implication
            # is that the incident will no longer be searchable with incident_key=dedup_key
            # 'dedup_key': '',
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
            }
            for image in images
            if isinstance(image, dict) and 'src' in image
        ]

    @staticmethod
    def _standardize_links(links):
        """Strips invalid links out of the links argument

        Images should be dicts with 2 keys:
           - href: A URL of the link
           - text: Text of the link (Optional: Defaults to the href if no text given)
        """
        if not isinstance(links, list):
            return []

        return [
            {
                'href': link['href'],
                'text': link['text'] if 'text' in link else link['href'],
            }
            for link in links
            if isinstance(link, dict) and 'href' in link
        ]


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
        default_description = 'StreamAlert Rule Triggered - {}'.format(alert.rule_name)
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
            if not 'type' in context:
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

        if result is False:
            return False

        return True


@StreamAlertOutput
class PagerDutyIncidentOutput(OutputDispatcher, EventsV2DataProvider):
    """PagerDutyIncidentOutput handles all alert dispatching for PagerDuty Incidents REST API

    In addition to using the REST API, this PagerDuty implementation also performs automatic
    assignment of the incident, based upon context parameters.

    context = {
      'assigned_user': 'somebody@somewhere.somewhere',
      'with_record': True|False,
      'note': 'String goes here'
    }
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

        Context:

            - with_record (bool):
            - note (bool):

        Publishing:
            This output has a more complex workflow. The magic publisher fields for @pagerduty-v2
            ALSO are respected by this output.

            - @pagerduty-incident.incident_title (str):
                    The provided string will override the PARENT INCIDENT's title. The child Alert's
                    title is controlled by other publisher magic fields.

            - @pagerduty-incident.incident_body (str):
                    This is text that shows up in the body of the newly created incident.

                    (!) NOTE: Due to the way incidents are merged, this text is almost never
                              displayed properly on PagerDuty's UI. The only instance where it
                              shows up correctly is when incident merging fails and the newly
                              created incident does not have an alert attached to it.

            - @pagerduty-incident.note (str):
                    Due to legacy reasons, this PagerDuty services adds a note containing
                    "Creating SOX Incident" to the final PagerDuty incident. Providing a string
                    to this magic field will override that behavior.

            - @pagerduty-incident.urgency (str):
                    Either "low" or "high". By default urgency is "high" for all incidents.


            In addition, the final event that is merged into the parent incident can be customized
            as well.
            @see EventsV2DataProvider for more details


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


class WorkContext(object):
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
        self._api_client = PagerDutyRestApiClient(
            self._credentials['token'],
            self._credentials['email_from'],
            http,
            url=self._credentials['api']
        )
        self._events_client = PagerDutyEventsV2ApiClient(http)

    def run(self, alert, descriptor):
        """Sets up an assigned incident.

        FIXME (derek.wang):
            This work routine is a large, non-atomic set of jobs that can sometimes partially fail.
            Partial failures can have side effects on PagerDuty, including the creation of
            incomplete or partially complete alerts. Because the Alert Processor will automatically
            retry the entire routine from scratch, this can cause partial alerts to get created
            redundantly forever. The temporary solution is to delete the erroneous record from
            DynamoDB manually, but in the future we should consider writing back state into the
            DynamoDB alert record to track the steps involved in "fulfilling" the dispatch of this
            alert.
        """
        if not self.verify_user_exists():
            return False

        # Extracting context data to assign the incident
        rule_context = alert.context
        if rule_context:
            rule_context = rule_context.get(self._output.__service__, {})

        publication = compose_alert(alert, self._output, descriptor)

        incident = self._create_base_incident(alert, publication, rule_context)
        incident_id = incident.get('id')
        if not incident or not incident_id:
            LOGGER.error('[%s] Could not create main incident', self._output.__service__)
            return False

        # Create alert to hold all the incident details
        event = self._create_base_alert_event(alert, descriptor, rule_context)
        if not event:
            LOGGER.error('[%s] Could not create incident event', self._output.__service__)
            return False

        # FIXME (derek.wang), see above
        #   At this point, both the incident and the relevant alert event have been successfully
        #   created. Any further work that fails the dispatch call will cause the alert to retry
        #   and redundantly create more incidents and alert events.
        #   Therefore, the hack is to simply let further failures go by always returning True.
        #   The tradeoff is that incidents can be created on pagerduty in an incomplete state,
        #   but this is easier to manage than StreamAlert redundantly creating hundreds (or more!)
        #   redundant alerts.
        stable = True

        # Merge the incident with the event, so we can have a rich context incident
        # assigned to a specific person, which the PagerDuty REST API v2 does not allow
        merged_incident = self._merge_event_into_incident(incident, event)
        if not merged_incident:
            LOGGER.error(
                '[%s] Failed to merge alert [%s] into [%s]',
                self._output.__service__,
                event.get('dedup_key'),
                incident_id
            )
            stable = False

        if merged_incident:
            note = self._add_incident_note(incident, publication, rule_context)
            if not note:
                LOGGER.error(
                    '[%s] Failed to add note to incident (%s)',
                    self._output.__service__,
                    incident_id
                )
                stable = False

        # If something went wrong, we can't throw an error anymore; log it on the Incident
        if not stable:
            self._add_instability_note(incident_id)

        return True

    def _add_instability_note(self, incident_id):
        instability_note = '''
StreamAlert failed to correctly setup this incident. Please contact your StreamAlert administrator.
        '''.strip()
        self._api_client.add_note(incident_id, instability_note)

    def _create_base_incident(self, alert, publication, rule_context):
        """Creates a container incident for this alert

        In PagerDuty's REST API design, Incidents are designed to behave like containers for many
        alerts. Unlike alerts, which must obey service escalation policies, Incidents can be given
        custom assignments.

        Returns the newly created incident as a JSON dict. Returns False if anything goes wrong.
        """

        # Presentation defaults
        default_incident_title = 'StreamAlert Incident - Rule triggered: {}'.format(alert.rule_name)
        default_incident_body = alert.rule_description
        default_urgency = None  # Assumes the default urgency on the service referenced

        # Override presentation defaults with publisher fields
        incident_title = publication.get(
            '@pagerduty-incident.incident_title',
            default_incident_title
        )
        incident_body = publication.get('@pagerduty-incident.incident_body', default_incident_body)
        incident_urgency = publication.get('@pagerduty-incident.urgency', default_urgency)

        # FIXME (derek.wang) use publisher to set priority instead of context
        # Use the priority provided in the context, use it or the incident will be low priority
        incident_priority = self.get_standardized_priority(rule_context)

        # FIXME (derek.wang) use publisher to set priority instead of context
        assigned_key, assigned_value = self.get_incident_assignment(rule_context)

        # https://api-reference.pagerduty.com/#!/Incidents/post_incidents
        incident_data = {
            'incident': {
                'type': 'incident',
                'title': incident_title,
                'service': {
                    'id': self._incident_service,
                    'type': 'service_reference'
                },
                'priority': incident_priority,
                'incident_key': '',
                'body': {
                    'type': 'incident_body',
                    'details': incident_body,
                },
                assigned_key: assigned_value
            }
        }

        # Urgency, if provided, must always be 'high' or 'low' or the API will error
        if incident_urgency:
            if incident_urgency in ['low', 'high']:
                incident_data['incident']['urgency'] = incident_urgency
            else:
                LOGGER.warn(
                    '[%s] Invalid pagerduty incident urgency: "%s"',
                    self._output.__service__,
                    incident_urgency
                )

        return self._api_client.create_incident(incident_data)

    def _create_base_alert_event(self, alert, descriptor, rule_context):
        """Creates an alert on REST API v2

        Returns the JSON representation of the ENQUEUE RESPONSE. This actually does not return
        either the alert nor the incident itself, but rather a small acknowledgement structure
        containing a "dedup_key". This key can be used to find the incident that is created.

        Returns False if event was not created.
        """
        with_record = rule_context.get('with_record', True)
        event_data = self._output.events_v2_data(
            alert,
            descriptor,
            self._credentials['integration_key'],
            with_record
        )

        return self._events_client.enqueue_event(event_data)

    def _merge_event_into_incident(self, incident, event):
        """Merges the given event into the incident.

        Returns the final, merged incident as a JSON dict. Returns False if anything goes wrong.
        """
        # Extract the incident id from the incident that was just created
        incident_id = incident.get('id')
        if not incident_id:
            LOGGER.error('[%s] Incident missing Id?', self._output.__service__)
            return False

        # Lookup the incident_key returned as dedup_key to get the incident id
        incident_key = event.get('dedup_key')
        if not incident_key:
            LOGGER.error('[%s] Event missing dedup_key', self._output.__service__)
            return False

        # Keep that id to be merged later with the created incident
        event_incident_id = self.get_incident_id_from_event_incident_key(incident_key)
        if not event_incident_id:
            LOGGER.error(
                '[%s] Failed to retrieve Event Incident Id from dedup_key (%s)',
                self._output.__service__,
                incident_key
            )
            return False

        # Merge the incident with the event, so we can have a rich context incident
        # assigned to a specific person, which the PagerDuty REST API v2 does not allow
        return self._api_client.merge_incident(incident_id, event_incident_id)

    def _add_incident_note(self, incident, publication, rule_context):
        """Adds a note to the incident, when applicable.

        Returns:
            bool: True if the note was created or no note needed to be created, False on error.
        """

        # Add a note to the combined incident to help with triage
        merged_id = incident.get('id')
        if not merged_id:
            LOGGER.error('[%s] Merged incident missing Id?', self._output.__service__)
            return False

        default_incident_note = 'Creating SOX Incident'  # For reverse compatibility reasons
        incident_note = publication.get(
            '@pagerduty-incident.note',
            rule_context.get(
                'note',
                default_incident_note
            )
        )

        if not incident_note:
            # Simply return early without adding a note; no need to add a blank one
            return True

        return bool(self._api_client.add_note(merged_id, incident_note))


    @backoff.on_exception(backoff.constant,
                          PagerdutySearchDelay,
                          max_tries=BACKOFF_MAX,
                          interval=BACKOFF_TIME,
                          on_backoff=backoff_handler(),
                          on_success=success_handler(),
                          on_giveup=giveup_handler())
    def get_incident_id_from_event_incident_key(self, incident_key):
        """Queries the API to get the incident id from an incident key

        When creating an EVENT from the events-v2 API, events are created alongside an incident,
        but only an incident_key is returned, which is not the same as the incident's REST API
        resource id.
        """
        if not incident_key:
            return False

        event_incident = self._api_client.get_incident_by_key(incident_key)
        if not event_incident:
            raise PagerdutySearchDelay('Received no PagerDuty response')

        return event_incident.get('id')

    def verify_user_exists(self):
        """Verifies that the 'email_from' provided in the creds is valid and exists."""
        user = self._api_client.get_user_by_email(self._email_from)

        if not user:
            LOGGER.error(
                'Could not verify header From: %s, %s',
                self._email_from,
                self._output.__service__
            )
            return False

        return True

    def get_standardized_priority(self, context):
        """Method to verify the existence of a incident priority with the API

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

        priorities = self._api_client.get_priorities()

        if not priorities:
            return dict()

        # If the requested priority is in the list, get the id
        priority_id = next(
            (item for item in priorities if item["name"] == priority_name), {}
        ).get('id', False)

        # If the priority id is found, compose the JSON
        if priority_id:
            return {'id': priority_id, 'type': 'priority_reference'}

        return dict()

    def get_incident_assignment(self, context):
        """Method to determine if the incident gets assigned to a user or an escalation policy

        Incident assignment goes in this order:
          Provided user -> provided policy -> default escalation policy

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
            user = self._api_client.get_user_by_email(user_to_assign)
            if user and user.get('id'):
                return 'assignments', [{'assignee': {
                    'id': user.get('id'),
                    'type': 'user_reference',
                }}]

        # If escalation policy ID was not provided, use default one
        policy_id_to_assign = context.get(
            'assigned_policy_id',
            self._default_escalation_policy_id
        )

        # Assigned to escalation policy ID, return tuple
        return 'escalation_policy', {
            'id': policy_id_to_assign, 'type': 'escalation_policy_reference'}


# pylint: disable=protected-access
class JsonHttpProvider(object):
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
        except OutputRequestFailure:
            return False

        response = result.json()
        if not response:
            return False

        return response

    def post(self, url, data, headers=None, verify=False):
        """Returns the JSON response of the given request, or FALSE on failure"""
        try:
            result = self._output_dispatcher._post_request_retry(url, data, headers, verify)
        except OutputRequestFailure:
            return False

        response = result.json()
        if not response:
            return False

        return response

    def put(self, url, params, headers=None, verify=False):
        """Returns the JSON response of the given request, or FALSE on failure"""
        try:
            result = self._output_dispatcher._put_request_retry(url, params, headers, verify)
        except OutputRequestFailure:
            return False

        response = result.json()
        if not response:
            return False

        return response


class SslVerifiable(object):
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
        super(PagerDutyRestApiClient, self).__init__()

        self._authorization_token = authorization_token
        self._user_email = user_email
        self._http_provider = http_provider  # type: JsonHttpProvider
        self._base_url = url if url else self.REST_API_BASE_URL

    def get_user_by_email(self, user_email):
        """Fetches a pagerduty user by an email address.

        Returns false on failure or if no matching user is found.
        """
        response = self._http_provider.get(
            self._get_users_url(),
            {
                'query': user_email,
            },
            self._construct_headers(omit_email=True),
            verify=self._should_do_ssl_verify()
        )
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
            verify=self._should_do_ssl_verify()
        )
        self._update_ssl_verified(incidents)

        if not incidents:
            return False

        incidents = incidents.get('incidents', [])

        return incidents[0] if incidents else False

    def get_priorities(self):
        """Returns a list of all valid priorities"""
        priorities = self._http_provider.get(
            self._get_priorities_url(),
            None,
            headers=self._construct_headers(),
            verify=self._should_do_ssl_verify()
        )
        self._update_ssl_verified(priorities)

        if not priorities:
            return False

        return priorities.get('priorities', [])

    def get_escalation_policy_by_id(self, escalation_policy_id):
        """Given an escalation policy id, returns the resource

        Returns False on failure or if no escalation policy exists with that id
        """
        escalation_policies = self._http_provider.get(
            self._get_escalation_policies_url(),
            {
                'query': escalation_policy_id,
            },
            headers=self._construct_headers(),
            verify=self._should_do_ssl_verify()
        )
        self._update_ssl_verified(escalation_policies)

        if not escalation_policies:
            return False

        escalation_policies = escalation_policies.get('escalation_policies', [])

        return escalation_policies[0] if escalation_policies else False

    def merge_incident(self, parent_incident_id, merged_incident_id):
        """Given two incident ids, notifies PagerDuty to merge them into a single incident

        Returns the json representation of the merged incident, or False on failure.
        """
        data = {
            'source_incidents': [
                {
                    'id': merged_incident_id,
                    'type': 'incident_reference'
                }
            ]
        }
        merged_incident = self._http_provider.put(
            self._get_incident_merge_url(parent_incident_id),
            data,
            headers=self._construct_headers(),
            verify=self._should_do_ssl_verify()
        )
        self._update_ssl_verified(merged_incident)

        if not merged_incident:
            return False

        return merged_incident.get('incident', False)

    def create_incident(self, incident_data):
        """Creates a new incident

        Returns the incident json representation on success, or False on failure.

        Reference: https://api-reference.pagerduty.com/#!/Incidents/post_incidents

        (!) FIXME (derek.wang)
                  The legacy implementation utilizes this POST /incidents endpoint to create
                  incidents and merge them with events created through the events-v2 API, but
                  the PagerDuty API documentation explicitly says to NOT use the REST API
                  to create incidents. Research if our use of the POST /incidents endpoint is
                  incorrect.
                  Reference: https://v2.developer.pagerduty.com/docs/getting-started

        Args:
            incident_data (dict)

        Returns:
            dict
        """
        incident = self._http_provider.post(
            self._get_incidents_url(),
            incident_data,
            headers=self._construct_headers(),
            verify=self._should_do_ssl_verify()
        )
        self._update_ssl_verified(incident)

        if not incident:
            return False

        return incident.get('incident', False)

    def add_note(self, incident_id, note):
        """Method to add a text note to the provided incident id

        Returns the note json representation on success, or False on failure.

        Reference: https://api-reference.pagerduty.com/#!/Incidents/post_incidents_id_notes

        Args:
            incident_id (str): ID of the incident to add the note to

        Returns:
            str: ID of the note after being added to the incident or False if it fails
        """
        note = self._http_provider.post(
            self._get_incident_notes_url(incident_id),
            {
                'note': {
                    'content': note,
                }
            },
            self._construct_headers(),
            verify=self._should_do_ssl_verify()
        )
        self._update_ssl_verified(note)

        if not note:
            return False

        return note.get('note', False)

    def _construct_headers(self, omit_email=False):
        """Returns a dict containing all headers to send for PagerDuty requests

        PagerDuty performs validation on the email provided in the From: header. PagerDuty will
        error if the requested email does not exist. In one specific case, we do not want this to
        happen; when we are querying for the existence of a user with this email.
        """
        headers = {
            'Accept': 'application/vnd.pagerduty+json;version=2',
            'Authorization': 'Token token={}'.format(self._authorization_token),
            'Content-Type': 'application/json',
        }
        if not omit_email:
            headers['From'] = self._user_email

        return headers

    def _get_escalation_policies_url(self):
        return '{base_url}/escalation_policies'.format(base_url=self._base_url)

    def _get_priorities_url(self):
        return '{base_url}/priorities'.format(base_url=self._base_url)

    def _get_incidents_url(self):
        return '{base_url}/incidents'.format(base_url=self._base_url)

    def _get_incident_url(self, incident_id):
        return '{incidents_url}/{incident_id}'.format(
            incidents_url=self._get_incidents_url(),
            incident_id=incident_id
        )

    def _get_incident_merge_url(self, incident_id):
        return '{incident_url}/merge'.format(incident_url=self._get_incident_url(incident_id))

    def _get_incident_notes_url(self, incident_id):
        return '{incident_url}/notes'.format(incident_url=self._get_incident_url(incident_id))

    def _get_users_url(self):
        return '{base_url}/users'.format(base_url=self._base_url)


class PagerDutyEventsV2ApiClient(SslVerifiable):
    """Service for finding URLs of various resources on the Events v2 API

    Documentation on Events v2 API: https://v2.developer.pagerduty.com/docs/events-api-v2
    """

    EVENTS_V2_API_ENQUEUE_ENDPOINT = 'https://events.pagerduty.com/v2/enqueue'

    def __init__(self, http_provider, enqueue_endpoint=None):
        super(PagerDutyEventsV2ApiClient, self).__init__()

        self._http_provider = http_provider  # type: JsonHttpProvider
        self._enqueue_endpoint = (
            enqueue_endpoint if enqueue_endpoint else self.EVENTS_V2_API_ENQUEUE_ENDPOINT
        )

    def enqueue_event(self, event_data):
        """Enqueues a new event.

        Returns the event json representation on success, or False on failure.

        Note: For API v2, all authentication information is baked directly into the event_data,
        rather than being provided in the headers.
        """
        event = self._http_provider.post(
            self._get_event_enqueue_v2_url(),
            event_data,
            headers=None,
            verify=self._should_do_ssl_verify()
        )
        self._update_ssl_verified(event)

        return event

    def _get_event_enqueue_v2_url(self):
        if self._enqueue_endpoint:
            return self._enqueue_endpoint

        return '{}'.format(self.EVENTS_V2_API_ENQUEUE_ENDPOINT)


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
        super(PagerDutyEventsV1ApiClient, self).__init__()

        self._service_key = service_key
        self._http_provider = http_provider #  type: JsonHttpProvider
        self._api_endpoint = api_endpoint if api_endpoint else self.EVENTS_V1_API_ENDPOINT

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
        result = self._http_provider.post(
            self._api_endpoint,
            data,
            headers=None,
            verify=self._should_do_ssl_verify()
        )
        self._update_ssl_verified(result)

        return result

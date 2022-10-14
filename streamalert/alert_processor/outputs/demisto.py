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
from collections import OrderedDict

from streamalert.alert_processor.helpers import compose_alert
from streamalert.alert_processor.outputs.output_base import (
    OutputDispatcher, OutputProperty, OutputRequestFailure, StreamAlertOutput)
from streamalert.shared.logger import get_logger

LOGGER = get_logger(__name__)


@StreamAlertOutput
class DemistoOutput(OutputDispatcher):
    """DemistoOutput handles all alert dispatching to Demisto"""
    __service__ = 'demisto'

    @classmethod
    def get_user_defined_properties(cls):
        """Gets Output configuration properties.

        Get properties that must be assigned by the user when configuring a new Demisto
        output.  This should be sensitive or unique information for this use-case that needs
        to come from the user.

        Returns:
          OrderedDict: Contains various OutputProperty items
        """
        return OrderedDict([
            ('descriptor',
             OutputProperty(description='a short and unique descriptor for this'
                            ' demisto output')),
            ('url',
             OutputProperty(description='URL to the Demisto server [https://hostname]',
                            mask_input=False,
                            input_restrictions={' '},
                            cred_requirement=True)),
            ('token',
             OutputProperty(description='Demisto API token', mask_input=True,
                            cred_requirement=True)),
        ])

    def _dispatch(self, alert, descriptor):
        """Send a new Incident to Demisto

        Publishing:
            Demisto offers a suite of default incident values. You can override any of the
            following:

            - @demisto.incident_type (str):

            - @demisto.severity (str):
                    Controls the severity of the incident. Any of the following:
                    'info', 'informational', 'low', 'med', 'medium', 'high', 'critical', 'unknown'

            - @demisto.owner (str):
                    Controls which name shows up under the owner. This can be any name, even of
                    users that are not registered on Demisto. Incidents can be filtered by name.

            - @demisto.details (str):
                    A string that briefly describes the nature of the incident and how to respond.

            - @demisto.incident_name (str):
                    Incident name shows up as the title of the Incident.

            - @demisto.label_data (dict):
                    By default, this output sends the entire publication into the Demisto labels
                    section, where the label names are the keys of the publication and the label
                    values are the values of the publication.

                    For deeply nested dictionary publications, the label names become the full path
                    of all nest dictionary keys, concatenated with periods (".").

                    By providing this override field, you can send a different dict of data to
                    Demisto, other than the entire publication. Just like in the default case,
                    if this provided dict is deeply nested, the keys will be flattened.


        Args:
            alert (Alert): Alert instance which triggered a rule
            descriptor (str): Output descriptor

        Returns:
            bool: True if alert was sent successfully, False otherwise
        """
        creds = self._load_creds(descriptor)
        if not creds:
            return False

        request = DemistoRequestAssembler.assemble(alert, compose_alert(alert, self, descriptor))
        integration = DemistoApiIntegration(creds, self)

        LOGGER.debug('Sending alert to Demisto: %s', creds['url'])

        try:
            integration.send(request)
            return True
        except OutputRequestFailure as e:
            LOGGER.exception('Failed to create Demisto incident: %s.', e)
            return False


class DemistoApiIntegration:
    """Bridge class to reduce coupling between DemistoOutput and whatever client we use."""
    def __init__(self, creds, dispatcher):
        self._creds = creds
        self._dispatcher = dispatcher

    def send(self, request):
        """Sends the given DemistoCreateIncidentRequest with the current integration.

        Returns:
            void: Returns void if the request is successful. Raises an exception on error.

        Raises:
            requests.exceptions.RequestException
        """
        request_data = {
            'type': request.incident_type,
            'name': request.incident_name,
            'owner': request.owner,
            'playbook': request.playbook,
            'severity': request.severity,
            'labels': request.labels,
            'customFields': request.custom_fields,
            'details': request.details,
        }
        if request.create_investigation:
            request_data['createInvestigation'] = True

        create_incident_endpoint = f"{self._creds['url']}/incident"

        #pylint: disable=protected-access
        # This is somewhat of a breach in abstraction, but is acceptable as-is for now.
        self._dispatcher._post_request_retry(create_incident_endpoint,
                                             data=request_data,
                                             headers={
                                                 'Accept': 'application/json',
                                                 'Content-type': 'application/json',
                                                 'Authorization': self._creds['token'],
                                             },
                                             verify=False)


class DemistoCreateIncidentRequest:
    """Encapsulation of a request to Demisto to create an incident."""
    SEVERITY_UNKNOWN = 0
    SEVERITY_INFORMATIONAL = 0.5
    SEVERITY_LOW = 1
    SEVERITY_MEDIUM = 2
    SEVERITY_HIGH = 3
    SEVERITY_CRITICAL = 4

    def __init__(self,
                 incident_name='Unnamed StreamAlert Alert',
                 incident_type='Unclassified',
                 playbook='',
                 severity=SEVERITY_UNKNOWN,
                 owner='StreamAlert',
                 details='Details not specified.',
                 create_investigation=False):
        # Default request parameters
        self._incident_name = str(incident_name)

        # Incident type maps to the Demisto incident "type". It comes from a discrete set that
        # is defined on the Demisto account configuration. If the provided incident type does not
        # exactly match one in the configured set, it will appear on the Demisto UI as
        # "Unclassified".
        self._incident_type = str(incident_type)

        # The playbook to assign to the case.
        self._playbook = playbook

        # Severity is an integer. Use the constants above.
        self._severity = severity

        # The Owner appears verbatim on the Incident list, regardless of whether the owner
        # exists or not.
        self._owner = str(owner)

        # An array of Dicts, with keys "type" and "value".
        self._labels = []

        # A string that appears in the details section.
        self._details = str(details)

        # FIXME: (!) Demisto currently does not seem to render these fields properly on their UI.
        self._custom_fields = {}

        # When set to True, the creation of this incident will also trigger the creation of an
        # investigation. This will cause playbooks to trigger automatically.
        self._create_investigation = bool(create_investigation)

    def add_label(self, label, value):
        # Demisto rejects non-string values; so type-cast everything to strings first
        self._labels.append({
            "type": str(label),
            "value": str(value),
        })
        self._labels.sort(key=lambda x: x["type"])

    @property
    def incident_name(self):
        return self._incident_name

    @property
    def incident_type(self):
        return self._incident_type

    @property
    def playbook(self):
        return self._playbook

    @property
    def severity(self):
        return self._severity

    @property
    def owner(self):
        return self._owner

    @property
    def labels(self):
        return self._labels

    @property
    def details(self):
        return self._details

    @property
    def custom_fields(self):
        return self._custom_fields

    @property
    def create_investigation(self):
        return self._create_investigation

    @classmethod
    def map_severity_string_to_severity_value(cls, severity_string):
        if not isinstance(severity_string, str):
            return cls.SEVERITY_UNKNOWN

        lc_severity_string = severity_string.lower()
        if lc_severity_string in {'info', 'informational'}:
            return cls.SEVERITY_INFORMATIONAL
        if lc_severity_string == 'low':
            return cls.SEVERITY_LOW
        if lc_severity_string in {'med', 'medium'}:
            return cls.SEVERITY_MEDIUM
        if lc_severity_string == 'high':
            return cls.SEVERITY_HIGH
        if lc_severity_string == 'critical':
            return cls.SEVERITY_CRITICAL

        return cls.SEVERITY_UNKNOWN


class DemistoRequestAssembler:
    """Factory class for DemistoCreateIncidentRequest objects"""
    @staticmethod
    def assemble(alert, alert_publication):
        """
        Args:
            alert (Alert): Instance of the alert
            alert_publication (Dict): Published alert data of the alert that triggered a rule

        Returns:
            DemistoCreateIncidentRequest
        """
        # Default presentation values
        default_incident_name = alert.rule_name
        default_incident_type = 'Unclassified'
        default_playbook = 'Unknown'
        default_severity = 'unknown'
        default_owner = 'StreamAlert'
        default_details = alert.rule_description
        default_label_data = alert_publication

        # Special keys that publishers can use to modify default presentation
        incident_type = alert_publication.get('@demisto.incident_type', default_incident_type)
        playbook = alert_publication.get('@demisto.playbook', default_playbook)
        severity = DemistoCreateIncidentRequest.map_severity_string_to_severity_value(
            alert_publication.get('@demisto.severity', default_severity))
        owner = alert_publication.get('@demisto.owner', default_owner)
        details = alert_publication.get('@demisto.details', default_details)
        incident_name = alert_publication.get('@demisto.incident_name', default_incident_name)
        label_data = alert_publication.get('@demisto.label_data', default_label_data)

        request = DemistoCreateIncidentRequest(
            incident_name=incident_name,
            incident_type=incident_type,
            severity=severity,
            owner=owner,
            details=details,
            playbook=playbook,
            create_investigation=True  # Important: Trigger workbooks automatically
        )

        # The alert is a nested JSON structure which does not render well on
        # Demisto's UI; flatten it into a series of discrete key-values.
        def enumerate_fields(record, path=''):
            if isinstance(record, list):
                for index, item in enumerate(record):
                    enumerate_fields(item, f'{path}[{index}]')

            elif isinstance(record, dict):
                for key in record:
                    enumerate_fields(
                        record[key],
                        '{prefix}{key}'.format(
                            prefix=f'{path}.' if path else '',  # Omit first period
                            key=key))

            else:
                request.add_label(path, record)

        enumerate_fields(label_data)

        return request

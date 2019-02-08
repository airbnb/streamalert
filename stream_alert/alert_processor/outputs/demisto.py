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
import json

from stream_alert.alert_processor.outputs.output_base import (
    OutputDispatcher,
    OutputProperty,
    StreamAlertOutput,
    OutputRequestFailure)
from stream_alert.shared.logger import get_logger

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
             OutputProperty(description='Demisto API token',
                            mask_input=True,
                            cred_requirement=True)),
        ])

    def _dispatch(self, alert, descriptor):
        """Send a new Incident to Demisto

        Args:
            alert (Alert): Alert instance which triggered a rule
            descriptor (str): Output descriptor

        Returns:
            bool: True if alert was sent successfully, False otherwise
        """
        creds = self._load_creds(descriptor)
        if not creds:
            return False

        request = DemistoRequestAssembler.assemble(alert.publish_for(self, descriptor), descriptor)
        integration = DemistoApiIntegration(creds, self)

        LOGGER.debug('Sending alert to Demisto: %s', creds['url'])

        try:
            integration.send(request)
            return True
        except OutputRequestFailure as e:
            LOGGER.exception('Failed to create Demisto incident: %s.', e)
            return False


class DemistoApiIntegration(object):
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
            'severity': request.severity,
            'labels': request.labels,
            'customFields': request.custom_fields,
            'details': request.details,
        }
        if request.create_investigation:
            request_data['createInvestigation'] = True

        create_incident_endpoint = '{}/incident'.format(self._creds['url'])

        #pylint: disable=protected-access
        # This is somewhat of a breach in abstraction, but is acceptable as-is for now.
        self._dispatcher._post_request_retry(
            create_incident_endpoint,
            data=request_data,
            headers={
                'Accept': 'application/json',
                'Content-type': 'application/json',
                'Authorization': self._creds['token'],
            },
            verify=False
        )


class DemistoCreateIncidentRequest(object):
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


class DemistoRequestAssembler(object):
    """Factory class for DemistoCreateIncidentRequest objects"""

    @staticmethod
    def assemble(alert_publication, descriptor):
        """
        Args:
            alert_publication (Dict): Published alert data of the alert that triggered a rule
            descriptor (str): Output descriptor

        Returns:
            DemistoCreateIncidentRequest
        """

        request = DemistoCreateIncidentRequest(
            incident_name=alert_publication.get('rule_name', 'Unnamed StreamAlert Alert'),
            details=alert_publication.get('rule_description', 'Details not specified.'),
            create_investigation=True  # Important: Trigger workbooks automatically
        )

        # The alert record/context are nested JSON structure which does not render well on
        # Demisto's UI; flatten it into a series of discrete key-values.
        def enumerate_fields(record, path):
            if isinstance(record, list):
                for index, item in enumerate(record):
                    enumerate_fields(item, path + '[{}]'.format(index))

            elif isinstance(record, dict):
                for key in record:
                    enumerate_fields(record[key], path + '.{}'.format(key))

            else:
                request.add_label(path, record)

        enumerate_fields(alert_publication.get('record', {}), 'record')
        enumerate_fields(alert_publication.get('context', {}), 'context')

        # Add on alert-specific fields
        request.add_label('alert.record', json.dumps(alert_publication.get('record', {})))
        request.add_label('alert.source', alert_publication.get('log_source', ''))
        request.add_label('alert.alert_id', alert_publication.get('id', ''))
        request.add_label('alert.cluster', alert_publication.get('cluster', ''))
        request.add_label('alert.log_type', alert_publication.get('log_type', ''))
        request.add_label('alert.source_entity', alert_publication.get('source_entity', ''))
        request.add_label('alert.source_service', alert_publication.get('source_service', ''))
        request.add_label('alert.rule_name', alert_publication.get('rule_name', ''))
        request.add_label('alert.descriptor', descriptor)

        return request

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

from .demisto_api_client import DemistoClient

from stream_alert.alert_processor.outputs.output_base import (
    OutputDispatcher,
    OutputProperty,
    StreamAlertOutput
)
from stream_alert.shared.logger import get_logger
from requests.exceptions import RequestException

LOGGER = get_logger(__name__)


@StreamAlertOutput
class DemistoOutput(OutputDispatcher):
    """DemistoOutput handles all alert dispatching to Demisto"""
    __service__ = 'demisto'

    @classmethod
    def get_user_defined_properties(cls):
        """Get properties that must be assigned by the user when configuring a new Demisto
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
        if not alert.context:
            LOGGER.error('[%s] Alert must contain context to run actions', self.__service__)
            return False

        creds = self._load_creds(descriptor)
        if not creds:
            return False

        request = DemistoRequestAssembler.assemble(alert, descriptor)
        integration = DemistoApiIntegration(creds)

        try:
            integration.send(request)
            return True
        except RequestException as e:
            LOGGER.error('Failed to create Demisto incident: %s.', e)
            return False


class DemistoApiIntegration(object):
    """Bridge pattern to reduce coupling between DemistoOutput and the
       DemistoClient implementation
    """

    def __init__(self, creds):
        self._demisto_api_client = DemistoClient(creds['token'], creds['url'])

    def send(self, request):
        """Sends the given DemistoCreateIncidentRequest with the current integration.

        Returns:
            void: Returns void if the request is successful. Raises an exception on error.

        Raises:
            requests.exceptions.RequestException
        """
        response = self._demisto_api_client.CreateIncident(
            request._incident_name,
            request._incident_type,
            request._severity,
            request._owner,
            request._labels,
            request._details,
            request._custom_fields,
            createInvestigation=request._create_investigation
        )
        response.raise_for_status()


class DemistoCreateIncidentRequest(object):
    """Encapsulation of a request to Demisto to create an incident."""
    SEVERITY_UNKNOWN = 0
    SEVERITY_INFORMATIONAL = 0.5
    SEVERITY_LOW = 1
    SEVERITY_MEDIUM = 2
    SEVERITY_HIGH = 3
    SEVERITY_CRITICAL = 4

    def __init__(self):
        # Default request parameters
        self._incident_name = 'Unnamed StreamAlert Alert'

        # Incident type maps to the Demisto incident "type". It comes from a discrete set that
        # is defined on the Demisto account configuration. If the provided incident type does not
        # exactly match one in the configured set, it will appear on the Demisto UI as
        # "Unclassified".
        self._incident_type = 'Unclassified'

        # Severity is an integer. Use the constants above.
        self._severity = self.SEVERITY_UNKNOWN

        # The Owner appears verbatim on the Incident list, regardless of whether the owner
        # exists or not.
        self._owner = 'StreamAlert'

        # An array of Dicts, with keys "type" and "value".
        self._labels = []

        # A string that appears in the details section.
        self._details = 'Details not specified.'

        # FIXME: (!) Demisto currently does not seem to render these fields properly on their UI.
        self._custom_fields = {}

        # When set to True, the creation of this incident will also trigger the creation of an
        # investigation. This will cause playbooks to trigger automatically.
        self._create_investigation = False

    def add_label(self, label, value):
        self._labels.append({
            "type": label,
            "value": value,
        })
        self._labels.sort(key=lambda x: x["type"])


class DemistoRequestAssembler(object):
    """Convenience service used solely to construct instances of DemistoCreateIncidentRequest
       from a given alert and Output descriptor
    """

    @staticmethod
    def assemble(alert, descriptor):
        """
        Args:
            alert (Alert): Alert instance which triggered a rule
            descriptor (str): Output descriptor

        Returns:
            DemistoCreateIncidentRequest
        """

        request = DemistoCreateIncidentRequest()

        request._incident_name = alert.rule_name
        request._details = alert.rule_description

        # The alert record/context are nested JSON structure which does not render well on
        # Demisto's UI; flatten it into a series of discrete key-values.
        def enumerate_fields(record, path):
            if type(record) is list:
                for index in range(len(record)):
                    enumerate_fields(record[index], path + '.[{}]'.format(index))

            elif type(record) is dict:
                for key in record:
                    enumerate_fields(record[key], path + '.{}'.format(key))

            else:
                request.add_label(path, record)

        enumerate_fields(alert.record, 'record')
        enumerate_fields(alert.context, 'context')

        # Add on alert-specific fields
        request.add_label('alert.record', json.dumps(alert.record))
        request.add_label('alert.source', alert.log_source)
        request.add_label('alert.alert_id', alert.alert_id)
        request.add_label('alert.cluster', alert.cluster)
        request.add_label('alert.log_type', alert.log_type)
        request.add_label('alert.source_entity', alert.source_entity)
        request.add_label('alert.source_service', alert.source_service)
        request.add_label('alert.rule_name', alert.rule_name)
        request.add_label('alert.descriptor', descriptor)

        # Trigger workbooks automatically
        request._create_investigation = True

        return request

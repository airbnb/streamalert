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
             OutputProperty(description='URL to the CB Response server [https://hostname]',
                            mask_input=False,
                            input_restrictions={' '},
                            cred_requirement=True)),
            ('token',
             OutputProperty(description='API token (if unknown, leave blank)',
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

        # descriptor
        #
        # The rule output should look something like:
        # - demisto:[Some Incident Type]
        # - demisto:[Some Incident Type]-[Severity]
        #
        # FIXME (derek.wang) remember to configure a full list over in outputs.json....
        #
        # "severity" is optional. If it's present and valid, we'll try to map it to a severity.
        # Otherwise we default to 0, which is "unknown".

        client = DemistoClient(creds['token'], creds['url'])

        incident_name = 'StreamAlert Rule Triggered - {}'.format(alert.rule_name)
        incident_type = descriptor
        severity = 0  # FIXME (derek.wang) Look above

        # The Owner appears verbatim on the Incident list, regardless of whether the owner
        # exists or not
        owner = 'Derek Wang'  # FIXME (derek.wang) Hardcoded here for testing purposes

        # Seems like a pretty reasonable place to put it, instead of in the tags which is pretty bad
        details = alert.rule_description

        # Fan out the record structure into individual dot-delimited tags
        label_fields = {}
        def enumerate_fields(record, path, fields):
            if type(record) is list:
                for index in range(len(record)):
                    enumerate_fields(record[index], path + '.[{}]'.format(index), fields)

            elif type(record) is dict:
                for key in record:
                    enumerate_fields(record[key], path + '.{}'.format(key), fields)

            else:
                fields[path] = record

        enumerate_fields(alert.record, 'record', label_fields)
        enumerate_fields(alert.context, 'context', label_fields)

        labels = []
        labels.append({
            "type": "record",
            "value": json.dumps(alert.record),
        })
        for key in label_fields:
            labels.append({
                "type": key,
                "value": label_fields[key]
            })

        response = client.CreateIncident(
            incident_name,
            # We directly map the descriptor over to the incident type. If the descriptor is
            # unrecognized on the Demisto server, it will simply default to "Unknown"
            incident_type,
            # Always use 0 - "unknown"
            # 0.5 - "Informational
            # 1 - "Low"
            # 2 - "Medium"
            # 3 - "High"
            #
            severity,
            owner,
            # This is where we put all of our garbage
            labels,
            details,
            {
                "alertsource": "demisto"
            },
            createInvestigation=False
        )

        if 200 <= response.status_code < 300:
            return True

        print(response.content)

        return False

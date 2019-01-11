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
        """Get properties that must be assigned by the user when configuring a new CarbonBlack
        output.  This should be sensitive or unique information for this use-case that needs
        to come from the user.

        Returns:
          OrderedDict: Contains various OutputProperty items
        """
        return OrderedDict([
            ('descriptor',
             OutputProperty(description='a short and unique descriptor for this'
                                        ' carbonblack output')),
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
        """Send ban hash command to CarbonBlack

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

        client = DemistoClient(creds['token'], creds['url'])

        LOGGER.error('vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv')

        LOGGER.error('TK: {}, URL: {}'.format(creds['token'], creds['url']))

        LOGGER.error(client.SearchIncidents(0, 100, ''))
        LOGGER.error('^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^')

        # client.CreateIncident(
        #     'incident-name',
        #     'incident-type',
        #     0,
        #     'owner',
        #     [
        #         {
        #             "type": "label",
        #             "value": "demisto"
        #         },
        #     ],
        #     'details',
        #     {
        #         "alertsource": "demisto"
        #     },
        #     createInvestigation=True
        # )

        return False

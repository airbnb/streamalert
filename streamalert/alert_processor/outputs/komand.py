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
from streamalert.alert_processor.outputs.output_base import (OutputDispatcher,
                                                             OutputProperty,
                                                             StreamAlertOutput)
from streamalert.shared.logger import get_logger

LOGGER = get_logger(__name__)


@StreamAlertOutput
class KomandOutput(OutputDispatcher):
    """KomandOutput handles all alert dispatching for Komand"""
    __service__ = 'komand'

    @classmethod
    def get_user_defined_properties(cls):
        """Get properties that must be assigned by the user when configuring a new Komand
        output.  This should be sensitive or unique information for this use-case that needs
        to come from the user.

        Every output should return a dict that contains a 'descriptor' with a description of the
        integration being configured.

        Returns:
            OrderedDict: Contains various OutputProperty items
        """
        return OrderedDict([
            ('descriptor',
             OutputProperty(description='a short and unique descriptor for this '
                            'Komand integration')),
            ('komand_auth_token',
             OutputProperty(description='the auth token for this Komand integration. '
                            'Example: 00000000-0000-0000-0000-000000000000',
                            mask_input=True,
                            cred_requirement=True)),
            ('url',
             OutputProperty(description='the endpoint url for this Komand integration. '
                            'Example: https://YOUR-KOMAND-HOST.com/v2/triggers/GUID/events',
                            mask_input=True,
                            cred_requirement=True))
        ])

    def _dispatch(self, alert, descriptor):
        """Send alert to Komand

        Publishing:
            By default this output sends the current publication to Komand.
            There is no "magic" field to "override" it: Simply publish what you want to send!

        Args:
            alert (Alert): Alert instance which triggered a rule
            descriptor (str): Output descriptor

        Returns:
            bool: True if alert was sent successfully, False otherwise
        """
        creds = self._load_creds(descriptor)
        if not creds:
            return False

        headers = {'Authorization': creds['komand_auth_token']}

        LOGGER.debug('sending alert to Komand')

        publication = compose_alert(alert, self, descriptor)
        resp = self._post_request(creds['url'], {'data': publication}, headers, False)

        return self._check_http_response(resp)

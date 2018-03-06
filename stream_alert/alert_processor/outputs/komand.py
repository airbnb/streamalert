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

from stream_alert.alert_processor import LOGGER
from stream_alert.alert_processor.outputs.output_base import (
    OutputDispatcher,
    OutputProperty,
    StreamAlertOutput
)


@StreamAlertOutput
class KomandOutput(OutputDispatcher):
    """KomandOutput handles all alert dispatching for Komand"""
    __service__ = 'komand'

    @classmethod
    def get_user_defined_properties(cls):
        """Get properties that must be asssigned by the user when configuring a new Komand
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

    def dispatch(self, **kwargs):
        """Send alert to Komand

        Args:
            **kwargs: consists of any combination of the following items:
                descriptor (str): Service descriptor (ie: slack channel, pd integration)
                alert (dict): Alert relevant to the triggered rule
        """
        creds = self._load_creds(kwargs['descriptor'])
        if not creds:
            return self._log_status(False, kwargs['descriptor'])

        headers = {'Authorization': creds['komand_auth_token']}

        LOGGER.debug('sending alert to Komand')

        resp = self._post_request(creds['url'], {'data': kwargs['alert']}, headers, False)
        success = self._check_http_response(resp)
        return self._log_status(success, kwargs['descriptor'])

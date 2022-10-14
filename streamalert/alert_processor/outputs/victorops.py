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
class VictorOpsOutput(OutputDispatcher):
    """VictorOpsOutput handles all alert dispatching for VictorOps"""
    __service__ = 'victorops'
    _DEFAULT_REQUEST_TIMEOUT = 10

    # Change the default request timeout for just this output
    _DEFAULT_REQUEST_TIMEOUT = 10

    @classmethod
    def get_user_defined_properties(cls):
        """Get properties that must be assigned by the user when configuring a new VictorOps
        output.  This should be sensitive or unique information for this use-case that needs
        to come from the user.

        Every output should return a dict that contains a 'descriptor' with a description of the
        integration being configured.

        Returns:
            OrderedDict: Contains various OutputProperty items
        """
        return OrderedDict([
            ('descriptor',
             OutputProperty(description='A short and unique descriptor for this '
                            'VictorOps integration')),
            ('victorops_api_id',
             OutputProperty(description='The API Id for this VictorOps integration.',
                            mask_input=True,
                            cred_requirement=True)),
            ('victorops_api_key',
             OutputProperty(description='The API Key for this VictorOps integration.',
                            mask_input=True,
                            cred_requirement=True)),
            ('url',
             OutputProperty(description='The endpoint url for this VictorOps integration.',
                            mask_input=True,
                            cred_requirement=True)),
            ('routing_key',
             OutputProperty(description='The endpoint routing key for this VictorOps integration.',
                            mask_input=True,
                            cred_requirement=True))
        ])

    def _dispatch(self, alert, descriptor):
        """Send alert to VictorOps

        Publishing:
            By default this output sends the current publication to VictorOps.
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

        publication = compose_alert(alert, self, descriptor)

        headers = {
            'Content-Type': 'application/json',
            'X-VO-Api-Id': creds['victorops_api_id'],
            'X-VO-Api-Key': creds['victorops_api_key']
        }

        data = {
            "message_type": "CRITICAL",
            "entity_id": "streamalert/alert",
            "entity_display_name": alert.rule_name,
            "record": publication['record']
        }

        LOGGER.critical('Sending alert to VictorOps')
        url = creds['url'] + '/' + creds['routing_key']
        resp = self._post_request(url, data, headers, True)

        return self._check_http_response(resp)

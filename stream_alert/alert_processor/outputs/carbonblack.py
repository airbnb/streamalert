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

from cbapi.response import BannedHash, Binary, CbResponseAPI

from stream_alert.alert_processor.outputs.output_base import (
    OutputDispatcher,
    OutputProperty,
    StreamAlertOutput
)
from stream_alert.shared.logger import get_logger


LOGGER = get_logger(__name__)


@StreamAlertOutput
class CarbonBlackOutput(OutputDispatcher):
    """CarbonBlackOutput handles all alert dispatching for CarbonBlack"""
    __service__ = 'carbonblack'

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

        client = CbResponseAPI(**creds)

        # Get md5 hash 'value' passed from the rules engine function
        action = alert.context.get('carbonblack', {}).get('action')
        if action == 'ban':
            binary_hash = alert.context.get('carbonblack', {}).get('value')
            # The binary should already exist in CarbonBlack
            binary = client.select(Binary, binary_hash)
            # Determine if the binary is currenty listed as banned
            if binary.banned:
                # Determine if the banned action is enabled, if true exit
                if binary.banned.enabled:
                    return True
                # If the binary is banned and disabled, begin the banning hash operation
                banned_hash = client.select(BannedHash, binary_hash)
                banned_hash.enabled = True
                banned_hash.save()
            else:
                # Create a new BannedHash object to be saved
                banned_hash = client.create(BannedHash)
                # Begin the banning hash operation
                banned_hash.md5hash = binary.md5
                banned_hash.text = "Banned from StreamAlert"
                banned_hash.enabled = True
                banned_hash.save()

            return banned_hash.enabled is True
        else:
            LOGGER.error('[%s] Action not supported: %s', self.__service__, action)
            return False

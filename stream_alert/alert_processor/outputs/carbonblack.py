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

SERVICE = 'carbonblack' # corresponds to the __service__ attribute in the output
CONTEXT = {
    SERVICE: {
        'action': 'ban',
        'value': '31283037CB17FFDBC4A78A75CF70B0C8' # this is a real hash for ykgo
    }
}

@StreamAlertOutput
class CarbonBlackOutput(OutputDispatcher):
    """CarbonBlackOutput handles all alert dispatching for CarbonBlack"""
    __service__ = 'carbonblack'
    ARTIFACT_ENDPOINT = '/api/v1/banning/blacklist'

    @classmethod
    def get_user_defined_properties(self):
        """Get properties that must be asssigned by the user when configuring a new CarbonBlack
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
             OutputProperty(description='URL to the CB Response server [https://hostname]:',
                            mask_input=True,
                            cred_requirement=True)),
            ('ssl_verify',
             OutputProperty(description='Use SSL/TLS certificate validation [Y/N]:',
                            mask_input=True,
                            cred_requirement=True)),
            ('token',
             OutputProperty(description='API token (if unknown, leave blank):',
                            mask_input=True,
                            cred_requirement=True)),
        ])

    def dispatch(self, alert, descriptor):
        """Send ban hash command to CarbonBlack

        Args:
            alert (Alert): Alert instance which triggered a rule
            descriptor (str): Output descriptor

        Returns:
            bool: True if alert was sent successfully, False otherwise
        """
        creds = self._load_creds(descriptor)
        if not creds:
            return self._log_status(False, descriptor)

        client = CbResponseAPI(**creds)

        # Get md5 hash 'value' from streamalert's rule processor
        if CONTEXT[SERVICE].get('action') == 'ban':
            binary_hash = CONTEXT[SERVICE].get('value')
            # The binary should already exist in CarbonBlack
            binary = client.select(Binary, binary_hash)

            # Determine if the binary is banned
            if binary.banned:
                # If the binary is banned and enabled, exit
                if binary.banned.enabled:
                    return

                # If the binary is banned and disabled, begin banning hash operation
                banned_hash = client.select(BannedHash, binary_hash)
                banned_hash.enabled = True
                banned_hash.save()
            else:
                # Create a new BannedHash object to be saved
                banned_hash = client.create(BannedHash)
                # Banning hash operation
                banned_hash.md5hash = binary.md5
                banned_hash.text = "Banned from StreamAlert"
                banned_hash.enabled = True
                banned_hash.save()
        else:
            print 'unsupported action'

    self._log_status(boolean)

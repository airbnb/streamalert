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
import logging

from streamalert.classifier.payload.payload_base import (PayloadRecord,
                                                         RegisterInput,
                                                         StreamPayload)
from streamalert.shared.logger import get_logger

LOGGER = get_logger(__name__)
LOGGER_DEBUG_ENABLED = LOGGER.isEnabledFor(logging.DEBUG)


@RegisterInput
class SnsPayload(StreamPayload):
    """SnsPayload class"""
    @classmethod
    def service(cls):
        return 'sns'

    def _pre_parse(self):
        """Pre-parsing method for SNS records

        Extracts the SNS message payload from the record.

        Yields:
            Instances of PayloadRecord back to the caller containing the current log data
        """
        LOGGER.debug('Pre-parsing record from SNS. MessageId: %s, EventSubscriptionArn: %s',
                     self.raw_record['Sns']['MessageId'], self.raw_record['EventSubscriptionArn'])

        yield PayloadRecord(self.raw_record['Sns']['Message'])

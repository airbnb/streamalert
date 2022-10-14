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
import base64
import logging
import zlib

from streamalert.classifier.payload.payload_base import (PayloadRecord,
                                                         RegisterInput,
                                                         StreamPayload)
from streamalert.shared.logger import get_logger

LOGGER = get_logger(__name__)
LOGGER_DEBUG_ENABLED = LOGGER.isEnabledFor(logging.DEBUG)


@RegisterInput
class KinesisPayload(StreamPayload):
    """KinesisPayload class"""
    @classmethod
    def service(cls):
        return 'kinesis'

    def _pre_parse(self):
        """Pre-parsing method for Kinesis records

        Decodes the base64 payload from within the record, and attempts to decompress
        the data. If the data is not compressed, this falls back on the original content.

        Yields:
            Instances of PayloadRecord back to the caller containing the current log data
        """
        LOGGER.debug('Pre-parsing record from Kinesis. eventID: %s, eventSourceARN: %s',
                     self.raw_record['eventID'], self.raw_record['eventSourceARN'])

        # Kinesis records have to potential to be gzipped, so try to decompress
        record = base64.b64decode(self.raw_record['kinesis']['data'])
        try:
            record = zlib.decompress(record, 47)
        except zlib.error:
            pass

        yield PayloadRecord(record)

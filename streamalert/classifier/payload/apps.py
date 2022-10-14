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
from streamalert.classifier.payload.payload_base import (PayloadRecord,
                                                         RegisterInput,
                                                         StreamPayload)
from streamalert.shared import CLASSIFIER_FUNCTION_NAME as FUNCTION_NAME
from streamalert.shared.metrics import MetricLogger


@RegisterInput
class AppPayload(StreamPayload):
    """StreamAlertAppPayload class"""
    @classmethod
    def service(cls):
        return 'streamalert_app'

    def _pre_parse(self):
        """Pre-parsing method for incoming app records

        This iterates over all the incoming logs in the 'logs' list.

        Yields:
            Instances of PayloadRecord back to the caller containing the current log data
        """
        for data in self.raw_record['logs']:
            yield PayloadRecord(data)

        MetricLogger.log_metric(FUNCTION_NAME, MetricLogger.TOTAL_STREAMALERT_APP_RECORDS,
                                len(self.raw_record['logs']))

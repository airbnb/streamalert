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
from stream_alert.classifier.payload.payload_base import (
    PayloadRecord,
    RegisterInput,
    StreamPayload
)
from stream_alert.shared import CLASSIFIER_FUNCTION_NAME as FUNCTION_NAME
from stream_alert.shared.metrics import MetricLogger


@RegisterInput
class AppPayload(StreamPayload):
    """StreamAlertAppPayload class"""

    @classmethod
    def service(cls):
        return 'stream_alert_app'

    def pre_parse(self):
        """Pre-parsing method for incoming app records that iterates over all the
        incoming logs in the 'logs' list.

        Yields:
            Instances of `self` back to the caller with the proper
                `pre_parsed_record` set to the current log data. This conforms
                to the interface of returning a generator, providing the ability
                to support multiple records like this.
        """
        for data in self.raw_record['logs']:
            yield PayloadRecord(data)

        MetricLogger.log_metric(FUNCTION_NAME, MetricLogger.TOTAL_STREAM_ALERT_APP_RECORDS,
                                len(self.raw_record['logs']))

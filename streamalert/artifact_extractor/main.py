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
from streamalert.artifact_extractor.artifact_extractor import ArtifactExtractor
from streamalert.shared.logger import get_logger


LOGGER = get_logger(__name__)


def handler(event, _):
    """Main Lambda handler function for Artifact Extractor

    Args:
        event (dict): This lambda function receives event like the following:
        {
          'records': [
            {
              'recordId': '12345678901230000000',
              'data': 'eyJyeXhpYXMiOiJZZXMiLCJtZXNzYWdlIjoiaGVsbG8gd29ybGQhIiwiZXZlbnRfZG==',
              'approximateArrivalTimestamp': 1583275634682
            }
          ],
          'region': 'us-east-1',
          'deliveryStreamArn': 'arn:aws:firehose:us-east-1:123456788901:deliverystream/aaaaa',
          'invocationId': '12345678-1234-5678-9000-124560291657'
        }

    Returns:
        dict: Return transformed records (although we don't transform the data) back is necessary
            and firehose will deliver those records to S3 for historical search.

            The lambda handler is intended to return an event like this:
            {
              'records': [
                {
                  'result': 'Ok',
                  'recordId': '12345678901230000000',
                  'data': '{"blah":"blah"}'
                }
              ]
            }
    """
    try:
        return ArtifactExtractor(
            event['region'],
            event['deliveryStreamArn']
        ).run(event.get('records', []))
    except Exception:
        # FIXME: (Optional) Add retry for Timeout exceptions. If the Lambda function invocation
        # fails because of a network timeout or the lambda invocation limit, Kinesis Data Firehose
        # retries the invocation three times by default. If the invocation does not succeed, Kinesis
        # Data Firehose then skips that batch of records. The skipped records are treated as
        # unsuccessfully processed records.
        # https://docs.aws.amazon.com/firehose/latest/dev/data-transformation.html
        LOGGER.exception('Invocation event: %s', event)
        raise

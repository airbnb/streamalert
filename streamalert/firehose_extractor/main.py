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
import json
import re

import boto3

from streamalert.shared.logger import get_logger
from streamalert.shared.normalize import Normalizer

LOGGER = get_logger(__name__)


def handler(event, _):
    """Main Lambda handler function for firehose extractor

    This lambda function receives events like the following:

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

    The lambda handler is intended to return an event like this:

    {
      'records': [
        {
          'recordId': '12345678901230000000',
          'data': '{"blah":"blah"}',
          'result': 'Ok'
        }
      ]
    }

    """
    try:
        return FirehoseExtractor(
            event['region'],
            event['deliveryStreamArn']
        ).run_extractions(event.get('records', []))
    except Exception:
        LOGGER.exception('Invocation event: %s', json.dumps(event))
        raise


class FirehoseExtractor:
    STREAM_ARN_REGEX = re.compile(r".*streamalert_data_(?P<source_type>.*)")

    def __init__(self, region, delivery_stream_arn):
        self._queue = ArtifactQueue()
        self._region = region

        self._delivery_stream_arn = delivery_stream_arn
        self._source_type = self.get_source_type(delivery_stream_arn)

    def run_extractions(self, records):
        LOGGER.info('Starting Firehose Extractions')

        returned_records = []
        for record in records:
            input_record = InputRecord(record, self.source_type)

            for artifact in input_record.artifacts:
                self._queue.enqueue(artifact)

            returned_records.append(input_record.output_record)

        self._queue.flush()

        LOGGER.info('Finished Firehose Extractions. Processed %d records.', len(records))

        return {
            'records': returned_records
        }

    @property
    def source_type(self):
        return self._source_type

    @classmethod
    def get_source_type(cls, delivery_stream_arn):
        # Can derive from the incoming firehose, which always has the format:
        # "${var.use_prefix ? "${var.prefix}_" : ""}streamalert_data_${var.log_name}"
        match = cls.STREAM_ARN_REGEX.search(delivery_stream_arn)
        if not match:
            return '?'
        else:
            return match.groups('source_type')[0]


class InputRecord:
    """Encapsulation of a single data record.

    These show up in Athena as individual rows in the query results.
    """

    def __init__(self, record_data, source_type):
        self._record_id = record_data['recordId']

        data = base64.b64decode(record_data['data'])
        self._record_data = json.loads(data)

        self._source_type = source_type

    @property
    def data(self):
        """
        Returns the python dict
        """
        return self._record_data

    @property
    def firehose_record_id(self):
        return self._record_id

    @property
    def artifacts(self):
        artifacts = []
        if Normalizer.NORMALIZATION_KEY in self.data:

            # FIXME (ryxias) remove this hack.
            # Add a record_id for correlation
            import uuid

            custom_record_id = str(uuid.uuid4())
            self._record_data[Normalizer.NORMALIZATION_KEY]['_record_id'] = custom_record_id
            LOGGER.debug('- Appending custom record_id: %s', custom_record_id)

            for normalized_type, values_list in self.data[Normalizer.NORMALIZATION_KEY].items():
                # FIXME (ryxias) remove
                if normalized_type == '_record_id':
                    continue

                for value in values_list:
                    artifacts.append(Artifact(
                        normalized_type,
                        value,
                        self._source_type,
                        custom_record_id
                    ))

        return artifacts

    @property
    def output_record(self):
        LOGGER.debug('Generating output record using data: %s  -->', self.data)
        return {
            'result': 'Ok',
            'data': base64.b64encode(jsondumpfirehose(self.data)).decode('utf-8'),
            'recordId': self.firehose_record_id
        }


class Artifact:
    """Encapsulation of a single Artifact that is extracted from an input record."""

    def __init__(self, normalized_type, value, source_type, record_id):
        self._type = normalized_type
        self._value = value
        self._function = 'not_specified'
        self._source_type = source_type

        # This is the StreamAlert normalization record id, not the firehose one
        self._record_id = record_id

    @property
    def record(self):
        return {
            'Data': jsondumpfirehose({
                'type': self._type,
                'value': self._value,
                'function': self._function,
                'source_type': self._source_type,
                'record_id': self._record_id,
            }).decode('utf-8')
        }


class ArtifactQueue:
    BUFFER_LIMIT = 500
    BUFFER_SIZE_LIMIT = 6000000

    def __init__(self):
        self._buffer = []
        self._client = boto3.client('firehose', region_name='us-east-1')

    def enqueue(self, artifact):
        """
        Params:
            artifact (Artifact):
        """
        self._buffer.append(artifact.record)

    def flush(self):
        putRecordsToFirehoseStream(
            'ryxias20200212_test_artifacts',
            self._buffer,
            self._client,
            attemptsMade=0,
            maxAttempts=20
        )

    def _flush_if_necessary(self):
        """# FIXME"""


def jsondumpfirehose(item):
    """
    Returns the given python dict item as a json-encoded string data, usable by Firehose

    Firehose has a subtle gotcha which requires you to manually insert a newline character
    at the end of every json encoded record. Failure to do so will cause the delivered records
    within the S3 objects to be smashed together and not be parseable by Athena.

    @see https://stackoverflow.com/questions/56044001/aws-firehose-newline-character
    """

    # FIXME (ryxias) refactor to use jsonlines
    return (json.dumps(item, separators=(',', ':')) + '\n').encode('utf-8')


# This code is COPY PASTED from AWS Blueprint
#
# REMEMBER: https://docs.aws.amazon.com/firehose/latest/APIReference/API_PutRecordBatch.html
#   put_record_batch has the following limits:
#   - 500 records
#   - each record can be 1 KB
#   - total max size 4 MB
def putRecordsToFirehoseStream(streamName, records, client, attemptsMade, maxAttempts):
    failedRecords = []
    codes = []
    errMsg = ''
    # if put_record_batch throws for whatever reason, response['xx'] will error out, adding a check for a valid
    # response will prevent this
    response = None
    try:
        response = client.put_record_batch(DeliveryStreamName=streamName, Records=records)
    except Exception as e:
        failedRecords = records
        errMsg = str(e)

    # if there are no failedRecords (put_record_batch succeeded), iterate over the response to gather results
    if not failedRecords and response and response['FailedPutCount'] > 0:
        for idx, res in enumerate(response['RequestResponses']):
            # (if the result does not have a key 'ErrorCode' OR if it does and is empty) => we do not need to re-ingest
            if 'ErrorCode' not in res or not res['ErrorCode']:
                continue

            codes.append(res['ErrorCode'])
            failedRecords.append(records[idx])

        errMsg = 'Individual error codes: ' + ','.join(codes)

    if len(failedRecords) > 0:
        if attemptsMade + 1 < maxAttempts:
            print(
                'Some records failed while calling PutRecordBatch to Firehose stream, retrying. %s' % (
                    errMsg))
            putRecordsToFirehoseStream(streamName, failedRecords, client, attemptsMade + 1,
                                       maxAttempts)
        else:
            raise RuntimeError(
                'Could not put records after %s attempts. %s' % (str(maxAttempts), errMsg))

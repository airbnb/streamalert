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
from os import environ as env
import uuid

from streamalert.shared.firehose import FirehoseClient
from streamalert.shared import ARTIFACT_EXTRACTOR_NAME, config
from streamalert.shared.metrics import MetricLogger
from streamalert.shared.normalize import Normalizer
from streamalert.shared.logger import get_logger


LOGGER = get_logger(__name__)

RECORD_ID_KEY = 'streamalert_record_id'

class Artifact:
    """Encapsulation of a single Artifact that is extracted from an input record."""

    def __init__(self, function, record_id, source_type, normalized_type, value):
        """Create a new Artifact based on normalized information

        Args:
            function (str): Describes how this field is used in the record, or what it means.
            record_id (str): Currently it is reserved for future support. It will come from the
                record processed by classifier. This field is very useful for cross reference back
                to the original record in the future. It will be "None" if no "record_id"
                information when searching artifacts in Athena.
            source_type (str): The original source of the artifact(s) extracted from a record.
                e.g. osquery_differential, cloudwatch_cloudtrail
            normalized_type (str): Normalized types in a record processed by classifier.
            value (str): This is the true value of the type. E.g, a record of type “ip_address”
                could have a value of “50.50.50.50”
        """
        # Enforce all fields are strings in a Artifact to prevent type corruption in Parquet format
        self._function = str(function)
        self._record_id = str(record_id)
        self._source_type = str(source_type)
        self._type = str(normalized_type)
        self._value = str(value)

    @property
    def record(self):
        """Generate an artifact

        Returns:
            dict: A dictionary contains artifact information.
        """
        return {
            'function': self._function,
            RECORD_ID_KEY: self._record_id,
            'source_type': self._source_type,
            'type': self._type,
            'value': self._value,
        }


class FirehoseRecord:
    """Encapsulation of single Firehose record and/or normalized artifacts"""

    def __init__(self, firehose_record, source_type):
        """Create a new Firehose record contains original data and may extract multiple artifacts if
        original data was normalized in the classifier.
        The transformed data (insert a record_id only) which will be returned back to source
        firehose for historical search. And the artifacts, if any, will be sent to a dedicated
        firehose with simplified schema and land in streamalert data bucket for historical search
        as well.

        Args:
            firehose_record (dict): the record passed to lambda from source firehose. It has
                following format,

                {
                  'recordId': '12345678901230000000',
                  'data': 'eyJyeXhpYXMiOiJZZXMiLCJtZXNzYWdlIjoiaGVsbG8gd29ybGQhIiwiZXZlbnRfZG==',
                  'approximateArrivalTimestamp': 1583275634682
                }

            source_type (str): The original source of the artifact(s) extracted from a record.
                e.g. osquery_differential, cloudwatch_cloudtrail
        """
        self._firehose_record_id = firehose_record['recordId']
        self._firehose_data = firehose_record['data']
        self._decoded_record = json.loads(base64.b64decode(self._firehose_data))
        self._source_type = source_type

    @property
    def artifacts(self):
        """Extract all artifacts from a record

        Returns:
            list: A list of Artifacts from a normalized record.
        """
        artifacts = []

        if not self._decoded_record.get(Normalizer.NORMALIZATION_KEY):
            # Return an empty list if the record doesn't have normalization information.
            return artifacts

        if not self._source_type:
            # Return immediately if can not identify source_type. a.k.a do not extract artifacts.
            return artifacts

        #
        # normalized information in the record will be similar to
        # {
        #     'record': {
        #         'region': 'us-east-1',
        #         'detail': {
        #             'awsRegion': 'us-west-2'
        #         }
        #     },
        #     'streamalert_normalization': {
        #         'region': [
        #             {
        #                 'values': ['region_name'],
        #                 'function': 'AWS region'
        #             },
        #             {
        #                 'values': ['region_name'],
        #                 'function': 'AWS region'
        #             }
        #         ]
        #     }
        # }
        #
        record_id = self._decoded_record.get(RECORD_ID_KEY) or str(uuid.uuid4())
        for key, values in self._decoded_record[Normalizer.NORMALIZATION_KEY].items():
            for value in values:
                for val in value.get('values', []):
                    artifacts.append(Artifact(
                        function=value.get('function'),
                        record_id=record_id,
                        source_type=self._source_type,
                        normalized_type=key,
                        value=val
                    ))

        # Add a new key "streamalert_record_id" to "streamalert_normalization" field. This new key
        # will be helpful tracing back to the original record when searching in "artifacts" table.
        self._decoded_record[Normalizer.NORMALIZATION_KEY][RECORD_ID_KEY] = record_id

        return artifacts

    @property
    def transformed_record(self):
        """Create a transformed record with required fields. The transformed record will be sent
        back to source Firehose and land in the S3 bucket for historical search. All transformed
        records from Lambda must contain the following parameters, or Kinesis Data Firehose rejects
        them and treats that as a data transformation failure.
        https://docs.aws.amazon.com/firehose/latest/dev/data-transformation.html

        recordId: The record ID is passed from source Firehose to Lambda during the invocation. The
            transformed record must contain the same record ID. Any mismatch between the ID of the
            original record and the ID of the transformed record is treated as a data transformation
            failure.

        result: The status of the data transformation of the record. The possible values are: Ok,
            Dropped, and ProcessingFailed. The purpose of ArtifactExtractor lambda is to extract
            artifacts and it should not change the data. So the result will alway be 'Ok'.

        data: The transformed data payload, base64-encoded. The transformed data payload includes a
            new key "streamalert_record_id" and it's the only difference from original data payload.

        Returns:
            dict: A dictionary with required fields 'result', 'data' and 'recordId'.
        """
        return {
            'recordId': self._firehose_record_id,
            'result': 'Ok',
            'data': base64.b64encode(self._json_serializer()).decode('utf-8')
        }

    def _json_serializer(self):
        """Serialize a transformed record to a JSON formatted string

        Returns:
            str: a JSON formatted string with a newline appened.
        """
        return (json.dumps(self._decoded_record, separators=(',', ':')) + '\n').encode('utf-8')

class ArtifactExtractor:
    """ArtifactExtractor class will extract normalized artifacts from batch of records from source
    Firehose and return the original records back to Firehose where thoese records will be delivered
    to S3 bucket for historical search. The artifacts will be sent a Firehose dedicated to artifacts
    delivery to the same S3 bucket.

    The main purpose of this class is to build the artifacts inventory without interrupting current
    historical search pipeline. So it will return the original records.

    To be noted here, most likely the ArtifactExtractor lambda function needs at least
    3 times of max(buffer size of firehoses where the artifacts extracted from). Because it has many
    data copy actions.
    """

    STREAM_ARN_REGEX = re.compile(r".*streamalert_(?P<source_type>.*)")

    _config = None
    _firehose_client = None

    def __init__(self, region, src_firehose_arn):
        self._region = region
        self._src_firehose_arn = src_firehose_arn
        self._dst_firehose_arn = env.get('DESTINATION_FIREHOSE_STREAM_NAME')
        self._artifacts = list()
        self._source_type = self._get_source_type()

        ArtifactExtractor._config = ArtifactExtractor._config or config.load_config(validate=True)

        ArtifactExtractor._firehose_client = (
            ArtifactExtractor._firehose_client or FirehoseClient.get_client(
                prefix=self.config['global']['account']['prefix'],
                artifact_extractor_config=self.config['lambda'].get('artifact_extractor_config', {})
            )
        )

    @property
    def config(self):
        return ArtifactExtractor._config

    @property
    def firehose(self):
        return ArtifactExtractor._firehose_client

    def run(self, records):
        LOGGER.debug('Extracting artifacts from %d %s logs', len(records), self._source_type)

        transformed_records = []
        for record in records:
            # Extract artifacts, if any, and generate a transformed record with required parameters.
            firehose_record = FirehoseRecord(record, self._source_type)

            for artifact in firehose_record.artifacts:
                self._artifacts.append(artifact.record)

            transformed_records.append(firehose_record.transformed_record)

        LOGGER.debug('Extracted %d artifact(s)', len(self._artifacts))

        MetricLogger.log_metric(
            ARTIFACT_EXTRACTOR_NAME,
            MetricLogger.EXTRACTED_ARTIFACTS,
            len(self._artifacts)
        )

        self.firehose.send_artifacts(self._artifacts, self._dst_firehose_arn)

        return {
            'records': transformed_records
        }

    def _get_source_type(self):
        """Extract source type from source firehose arn which follows naming convention
        *_streamalert_<log_name>. The <log_name> is the source type.

        Please note the log_name may be hashed out if the firehose stream name is too long, but it
        is rare.

        Returns:
            str: The original source of the artifact(s) extracted from a record,
                e.g. osquery_differential, cloudwatch_cloudtrail
        """
        match = self.STREAM_ARN_REGEX.search(self._src_firehose_arn)
        if not match:
            LOGGER.warning(
                'No valid source type found from firehose arn %s', self._src_firehose_arn
            )
            # return early without result if source type is invalid
            return

        return match.groups('source_type')[0]

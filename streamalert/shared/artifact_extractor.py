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
import re
import uuid

from streamalert.shared import CLASSIFIER_FUNCTION_NAME, config
from streamalert.shared.firehose import FirehoseClient
from streamalert.shared.logger import get_logger
from streamalert.shared.metrics import MetricLogger
from streamalert.shared.normalize import CONST_ARTIFACTS_FLAG, Normalizer

LOGGER = get_logger(__name__)


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
    def artifact(self):
        """Generate an artifact

        Returns:
            dict: A dictionary contains artifact information.
        """
        return {
            'function': self._function,
            Normalizer.RECORD_ID_KEY: self._record_id,
            'source_type': self._source_type,
            'type': self._type,
            'value': self._value,
        }


class ArtifactExtractor:
    """ArtifactExtractor class will extract artifacts from "streamalert_normalization" field in the
    records. The extracted artfiacts will be saved in the S3 bucket via a dedicated Firehose
    delivery stream and searchable from "artifacts" table in Athena.
    """

    STREAM_ARN_REGEX = re.compile(r".*streamalert_(?P<source_type>.*)")

    _config = None
    _firehose_client = None

    def __init__(self, artifacts_fh_stream_name):
        self._dst_firehose_stream_name = artifacts_fh_stream_name
        self._artifacts = []

        ArtifactExtractor._config = ArtifactExtractor._config or config.load_config(validate=True)

        ArtifactExtractor._firehose_client = (
            ArtifactExtractor._firehose_client
            or FirehoseClient.get_client(prefix=self.config['global']['account']['prefix'],
                                         artifact_extractor_config=self.config['global'].get(
                                             'infrastructure', {}).get('artifact_extractor', {})))

    @property
    def config(self):
        return ArtifactExtractor._config

    @property
    def firehose(self):
        return ArtifactExtractor._firehose_client

    @staticmethod
    def _extract_artifacts(source_type, records):
        """Extract all artifacts from a record

        Returns:
            list: A list of Artifacts from a normalized record.

        normalized information in the record will be similar to
        {
            'record': {
                'region': 'us-east-1',
                'detail': {
                    'awsRegion': 'us-west-2'
                }
            },
            'streamalert_normalization': {
                'region': [
                    {
                        'values': ['region_name'],
                        'function': 'AWS region'
                    },
                    {
                        'values': ['region_name'],
                        'function': 'AWS region',
                        'send_to_artifacts': False
                    }
                ]
            }
        }
        """
        artifacts = []

        for record in records:
            if not record.get(Normalizer.NORMALIZATION_KEY):
                continue

            record_id = (record[Normalizer.NORMALIZATION_KEY].get(Normalizer.RECORD_ID_KEY)
                         or str(uuid.uuid4()))
            for key, values in record[Normalizer.NORMALIZATION_KEY].items():
                if key == Normalizer.RECORD_ID_KEY:
                    continue

                for value in values:
                    # Skip the normalized value is SNED_TO_ARTIFACTS_FLAG set to "false", which is
                    # default to "true".
                    if not value.get(CONST_ARTIFACTS_FLAG, True):
                        continue

                    for val in value.get('values', []):
                        artifacts.append(
                            Artifact(
                                function=value.get('function'),
                                record_id=record_id,
                                # source_type=self._source_type,
                                source_type=source_type,
                                normalized_type=key,
                                value=val))

        return artifacts

    def run(self, categorized_records):
        """Run extract artifacts logic and send artifacts to the Firehose for retention

        Args:
            categorized_records (dict): A dictionary contains log source type and records with
            following format
                {
                    'log_type_01_sub_type_01': [{'key': 'value'}],
                    'log_type_01_sub_type_02': [{'key': 'value'}],
                    'log_type_02_sub_type_01': [{'key': 'value'}],
                    'log_type_02_sub_type_02': [{'key': 'value'}]
                }
        """

        for source_type, records in categorized_records.items():
            LOGGER.debug('Extracting artifacts from %d %s logs', len(records), source_type)
            for artifact in self._extract_artifacts(source_type, records):
                self._artifacts.append(artifact.artifact)

        LOGGER.debug('Extracted %d artifact(s)', len(self._artifacts))

        MetricLogger.log_metric(CLASSIFIER_FUNCTION_NAME, MetricLogger.EXTRACTED_ARTIFACTS,
                                len(self._artifacts))

        self.firehose.send_artifacts(self._artifacts, self._dst_firehose_stream_name)

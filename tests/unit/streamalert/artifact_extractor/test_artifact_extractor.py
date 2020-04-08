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
import os

from mock import call, Mock, patch
from nose.tools import assert_equal

from streamalert.artifact_extractor.artifact_extractor import (
    Artifact,
    ArtifactExtractor
)
from streamalert.classifier.clients import FirehoseClient
from tests.unit.streamalert.artifact_extractor.helpers import (
    native_firehose_records,
    transformed_firehose_records,
    generate_artifacts,
)


class TestArtifact:
    """Test Artifact class"""

    def test_record(self): # pylint: disable=no-self-use
        """Artifact - Test record property in the Artifact class"""
        artifact = Artifact(
            normalized_type='test_normalized_type',
            value='test_value',
            source_type='test_source_type',
            record_id='test_record_id'
        )
        expected_result = {
            'function': 'not_specified',
            'record_id': 'test_record_id',
            'source_type': 'test_source_type',
            'type': 'test_normalized_type',
            'value': 'test_value'
        }

        assert_equal(artifact.record, expected_result)


class TestArtifactExtractor:
    """Test ArtifactExtractor class """
    # pylint: disable=attribute-defined-outside-init,protected-access,no-self-use

    @patch.dict(os.environ, {'DESTINATION_FIREHOSE_ARN': 'unit_test_dst_fh_arn'})
    def setup(self):
        """Setup before each method"""
        with patch('boto3.client'):
            ArtifactExtractor._firehose_client = FirehoseClient(prefix='unit-test')

        self._artifact_extractor = ArtifactExtractor(
            'us-east-1', 'prefix_streamalert_unit_test'
        )

    def teardown(self):
        """Teardown after each method"""
        ArtifactExtractor._firehose_client = None

    @patch('streamalert.artifact_extractor.artifact_extractor.LOGGER')
    def test_run_zero_artifact(self, logger_mock):
        """ArtifactExtractor - Test run method extract zero artifact"""
        result = self._artifact_extractor.run(native_firehose_records())
        logger_mock.assert_has_calls([
            call.debug('Extracting artifacts from %d %s logs', 2, 'unit_test'),
            call.debug('Extracted %d artifact(s)', 0)
        ])

        expected_result = transformed_firehose_records()
        assert_equal(result, expected_result)

    @patch.object(FirehoseClient, '_send_batch')
    @patch('streamalert.artifact_extractor.artifact_extractor.LOGGER')
    def test_run(self, logger_mock, send_batch_mock):
        """ArtifactExtractor - Test run method extract artifacts"""
        result = self._artifact_extractor.run(native_firehose_records(normalized=True))

        logger_mock.assert_has_calls([
            call.debug('Extracting artifacts from %d %s logs', 2, 'unit_test'),
            call.debug('Extracted %d artifact(s)', 6)
        ])

        send_batch_mock.assert_called_with(
            'unit_test_dst_fh_arn',
            generate_artifacts()
        )

        expected_result = transformed_firehose_records(normalized=True)
        assert_equal(result, expected_result)

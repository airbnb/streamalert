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
from unittest.mock import call, patch

from streamalert.shared.artifact_extractor import Artifact, ArtifactExtractor
from streamalert.shared.firehose import FirehoseClient
from tests.unit.streamalert.shared.test_utils import (
    MOCK_RECORD_ID, generate_artifacts, generate_categorized_records)


class TestArtifact:
    """Test Artifact class"""

    def test_record(self):  # pylint: disable=no-self-use
        """Artifact - Test record property in the Artifact class"""
        artifact = Artifact(
            normalized_type='test_normalized_type',
            value='test_value',
            source_type='test_source_type',
            record_id='test_record_id',
            function=None
        )
        expected_result = {
            'function': 'None',
            'streamalert_record_id': 'test_record_id',
            'source_type': 'test_source_type',
            'type': 'test_normalized_type',
            'value': 'test_value'
        }

        assert artifact.artifact == expected_result


class TestArtifactExtractor:
    """Test ArtifactExtractor class """
    # pylint: disable=attribute-defined-outside-init,protected-access,no-self-use

    def setup(self):
        """Setup before each method"""
        with patch('boto3.client'):
            ArtifactExtractor._firehose_client = FirehoseClient(prefix='unit-test')

        self._artifact_extractor = ArtifactExtractor('unit_test_dst_fh_arn')

    def teardown(self):
        """Teardown after each method"""
        ArtifactExtractor._firehose_client = None

    @patch('streamalert.shared.artifact_extractor.LOGGER')
    def test_run_zero_artifact(self, logger_mock):
        """ArtifactExtractor - Test run method extract zero artifact"""
        self._artifact_extractor.run(generate_categorized_records())
        logger_mock.assert_has_calls([
            call.debug('Extracting artifacts from %d %s logs', 2, 'log_type_01_sub_type_01'),
            call.debug('Extracted %d artifact(s)', 0)
        ])

        assert self._artifact_extractor._artifacts == []

    @patch('uuid.uuid4')
    @patch.object(FirehoseClient, '_send_batch')
    @patch('streamalert.shared.artifact_extractor.LOGGER')
    def test_run(self, logger_mock, send_batch_mock, uuid_mock):
        """ArtifactExtractor - Test run method extract artifacts"""
        uuid_mock.return_value = MOCK_RECORD_ID
        self._artifact_extractor.run(generate_categorized_records(normalized=True))

        logger_mock.assert_has_calls([
            call.debug('Extracting artifacts from %d %s logs', 2, 'log_type_01_sub_type_01'),
            call.debug('Extracted %d artifact(s)', 6)
        ])

        send_batch_mock.assert_called_with(
            'unit_test_dst_fh_arn',
            generate_artifacts(firehose_records=True),
            'classifier'
        )

        assert self._artifact_extractor._artifacts == generate_artifacts()

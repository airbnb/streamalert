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

from mock import call, patch
from nose.tools import assert_equal

# from streamalert.artifact_extractor.artifact_extractor import ArtifactExtractor
from streamalert.artifact_extractor.main import ArtifactExtractor, handler
from streamalert.shared.firehose import FirehoseClient

from tests.unit.streamalert.artifact_extractor.helpers import (
    native_firehose_records,
    transformed_firehose_records,
    generate_artifacts,
    MOCK_RECORD_ID,
)


class TestArtifactExtractorHandler:
    """Test Artifact Extractor lambda function handler"""
    # pylint: disable=attribute-defined-outside-init,protected-access,no-self-use

    @patch.dict(os.environ, {'DESTINATION_FIREHOSE_STREAM_NAME': 'unit_test_dst_fh_arn'})
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

    @patch.dict(os.environ, {'DESTINATION_FIREHOSE_STREAM_NAME': 'unit_test_dst_fh_arn'})
    @patch('streamalert.artifact_extractor.artifact_extractor.LOGGER')
    def test_handler_zero_artifact(self, logger_mock):
        """ArtifactExtractor - Test handler extracts zero artifact"""
        event = {
            'records': native_firehose_records(),
            'region': 'us-east-1',
            'deliveryStreamArn': (
                'arn:aws:firehose:us-east-1:123456788901:prefix_streamalert_unit_test'
            ),
            'invocationId': '12345678-1234-5678-9000-124560291657'
        }
        result = handler(event, 'bala')

        logger_mock.assert_has_calls([
            call.debug('Extracting artifacts from %d %s logs', 2, 'unit_test'),
            call.debug('Extracted %d artifact(s)', 0)
        ])

        expected_result = transformed_firehose_records()
        assert_equal(result, expected_result)

    @patch('uuid.uuid4')
    @patch.dict(os.environ, {'DESTINATION_FIREHOSE_STREAM_NAME': 'unit_test_dst_fh_arn'})
    @patch.object(FirehoseClient, '_send_batch')
    @patch('streamalert.artifact_extractor.artifact_extractor.LOGGER')
    def test_handler(self, logger_mock, send_batch_mock, uuid_mock):
        """ArtifactExtractor - Test handler"""
        uuid_mock.return_value = MOCK_RECORD_ID
        event = {
            'records': native_firehose_records(normalized=True),
            'region': 'us-east-1',
            'deliveryStreamArn': (
                'arn:aws:firehose:us-east-1:123456788901:prefix_streamalert_unit_test'
            ),
            'invocationId': '12345678-1234-5678-9000-124560291657'
        }
        result = handler(event, 'bala')

        logger_mock.assert_has_calls([
            call.debug('Extracting artifacts from %d %s logs', 2, 'unit_test'),
            call.debug('Extracted %d artifact(s)', 6)
        ])

        send_batch_mock.assert_called_with(
            'unit_test_dst_fh_arn',
            generate_artifacts(),
            'artifact_extractor'
        )

        expected_result = transformed_firehose_records(normalized=True)
        assert_equal(result, expected_result)

    @patch.dict(os.environ, {'DESTINATION_FIREHOSE_STREAM_NAME': 'unit_test_dst_fh_arn'})
    @patch('streamalert.artifact_extractor.artifact_extractor.LOGGER')
    def test_handler_invalid_source_type(self, logger_mock):
        """ArtifactExtractor - Test handler with invalid source type from firehose arn"""
        event = {
            'records': native_firehose_records(),
            'region': 'us-east-1',
            'deliveryStreamArn': (
                'arn:aws:firehose:us-east-1:123456788901:firehose-deliverystream'
            ),
            'invocationId': '12345678-1234-5678-9000-124560291657'
        }
        handler(event, 'bala')

        logger_mock.assert_has_calls([
            call.warning(
                'No valid source type found from firehose arn %s',
                'arn:aws:firehose:us-east-1:123456788901:firehose-deliverystream'
            )
        ])

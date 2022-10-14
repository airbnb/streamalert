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
import json

from streamalert_cli.config import CLIConfig
from streamalert_cli.terraform import artifact_extractor


class TestTerraformArtifactExtractor:
    """Test class for test generating Artifact Extractor terrform modules"""

    def __init__(self):
        """Init config for the test cases"""
        self.config = CLIConfig(config_path='tests/unit/conf')

    def test_generate_artifact_extractor(self):
        """CLI - Terraform generate artifact extractor"""
        result = artifact_extractor.generate_artifact_extractor(self.config)
        assert result is None

        self.config['global']['infrastructure']['artifact_extractor'] = {
            'enabled': True,
            'firehose_buffer_size': 128,
            'firehose_buffer_interval': 900
        }

        self.config['global']['infrastructure']['firehose']['enabled_logs'] = {
            'unit_test:type_1',
            'unit_test:type_2'
        }

        self.config['logs']['unit_test:type_1'] = {
            'schema': {},
            'configuration': {
                'normalization': {
                    'normalized_type': ['original_key1', 'original_key2']
                }
            }
        }
        self.config['logs']['unit_test:type_2'] = {
            'schema': {}
        }

        result = artifact_extractor.generate_artifact_extractor(self.config)
        expected_result = {
            'module': {
                'artifact_extractor': {
                    'source': './modules/tf_artifact_extractor',
                    'account_id': '12345678910',
                    'prefix': 'unit-test',
                    'region': 'us-west-1',
                    'glue_catalog_db_name': 'unit-test_streamalert',
                    'glue_catalog_table_name': 'artifacts',
                    's3_bucket_name': 'unit-test-streamalert-data',
                    'stream_name': 'unit_test_streamalert_artifacts',
                    'buffer_size': 128,
                    'buffer_interval': 900,
                    'kms_key_arn': '${aws_kms_key.server_side_encryption.arn}',
                    'schema': [
                        ['function', 'string'],
                        ['source_type', 'string'],
                        ['streamalert_record_id', 'string'],
                        ['type', 'string'],
                        ['value', 'string']
                    ]
                }
            }
        }

        # FIMME: not sure why assert_equal between result (defaultdict) and expected_result (dict)
        # fails.
        assert json.dumps(result) == json.dumps(expected_result)

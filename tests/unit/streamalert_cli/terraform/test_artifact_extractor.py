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

from nose.tools import assert_equal, assert_is_none

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
        assert_is_none(result)

        self.config['lambda']['artifact_extractor_config'] = {
            'enabled': True,
            'memory': 128,
            'timeout': 300
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
                    'function_role_id': '${module.artifact_extractor_lambda.role_id}',
                    'function_alias_arn': '${module.artifact_extractor_lambda.function_alias_arn}',
                    'glue_catalog_db_name': 'unit-test_streamalert',
                    'glue_catalog_table_name': 'artifacts',
                    's3_bucket_name': 'unit-test-streamalert-data',
                    'stream_name': 'unit_test_streamalert_artifacts',
                    'buffer_size': 128,
                    'buffer_interval': 900,
                    'kms_key_arn': '${aws_kms_key.server_side_encryption.arn}',
                    'schema': [
                        ['function', 'string'],
                        ['record_id', 'string'],
                        ['source_type', 'string'],
                        ['type', 'string'],
                        ['value', 'string']
                    ]
                },
                'artifact_extractor_lambda': {
                    'source': './modules/tf_lambda',
                    'function_name': 'unit-test_streamalert_artifact_extractor',
                    'description': 'Unit-Test Streamalert Artifact Extractor',
                    'handler': 'streamalert.artifact_extractor.main.handler',
                    'memory_size_mb': 128,
                    'timeout_sec': 300,
                    'environment_variables': {
                        'ENABLE_METRICS': '0',
                        'LOGGER_LEVEL': 'info',
                        'DESTINATION_FIREHOSE_STREAM_NAME': 'unit_test_streamalert_artifacts'
                    },
                    'tags': {}
                }
            }
        }

        # FIMME: not sure why assert_equal between result (defaultdict) and expected_result (dict)
        # fails.
        # assert_equal(result, expected_result)
        assert_equal(json.dumps(result), json.dumps(expected_result))


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
from streamalert.shared import ARTIFACT_EXTRACTOR_NAME
from streamalert.shared.config import artifact_extractor_enabled, firehose_data_bucket
from streamalert.shared.firehose import FirehoseClient
from streamalert.shared.utils import get_database_name
from streamalert_cli.athena.helpers import generate_artifacts_table_schema
from streamalert_cli.terraform.common import infinitedict
from streamalert_cli.terraform.lambda_module import generate_lambda

# FIXME: Should we provide custom artifacs table name?
DEFAULT_ARTIFACTS_TABLE_NAME = 'artifacts'

def generate_artifact_extractor(config):
    """Generate Terraform for the Artifact Extractor Lambda function
    Args:
        config (dict): The loaded config from the 'conf/' directory
    Returns:
        dict: Artifact Extractor Terraform definition to be marshaled to JSON
    """
    result = infinitedict()

    if not artifact_extractor_enabled(config):
        return

    ae_config = config['lambda']['artifact_extractor_config']
    stream_name = FirehoseClient.artifacts_firehose_stream_name(config)

    # Set variables for the artifact extractor module
    result['module']['artifact_extractor'] = {
        'source': './modules/tf_artifact_extractor',
        'account_id': config['global']['account']['aws_account_id'],
        'prefix': config['global']['account']['prefix'],
        'region': config['global']['account']['region'],
        'function_role_id': '${module.artifact_extractor_lambda.role_id}',
        'function_alias_arn': '${module.artifact_extractor_lambda.function_alias_arn}',
        'glue_catalog_db_name': get_database_name(config),
        'glue_catalog_table_name': ae_config.get('table_name', DEFAULT_ARTIFACTS_TABLE_NAME),
        's3_bucket_name': firehose_data_bucket(config),
        'stream_name': stream_name,
        'buffer_size': ae_config.get('firehose_buffer_size', 128),
        'buffer_interval': ae_config.get('firehose_buffer_interval', 900),
        'kms_key_arn': '${aws_kms_key.server_side_encryption.arn}',
        'schema': generate_artifacts_table_schema()
    }

    # Set variables for the Lambda module
    result['module']['artifact_extractor_lambda'] = generate_lambda(
        '{}_streamalert_{}'.format(config['global']['account']['prefix'], ARTIFACT_EXTRACTOR_NAME),
        'streamalert.artifact_extractor.main.handler',
        ae_config,
        config,
        # Only pass Firehose stream name. Firehose client will translate it to full ARN
        environment={
            'DESTINATION_FIREHOSE_STREAM_NAME': stream_name
        }
    )

    return result

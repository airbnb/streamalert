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
from streamalert.shared import ATHENA_PARTITIONER_NAME
from streamalert.shared.config import (athena_partition_buckets_tf,
                                       athena_query_results_bucket)
from streamalert_cli.terraform.common import (infinitedict,
                                              s3_access_logging_bucket)
from streamalert_cli.terraform.lambda_module import generate_lambda


def generate_athena(config):
    """Generate Athena Terraform.

    Args:
        config (dict): The loaded config from the 'conf/' directory

    Returns:
        dict: Athena dict to be marshalled to JSON
    """
    result = infinitedict()

    prefix = config['global']['account']['prefix']
    athena_config = config['lambda']['athena_partitioner_config']

    data_buckets = athena_partition_buckets_tf(config)
    database = athena_config.get('database_name', f'{prefix}_streamalert')

    results_bucket_name = athena_query_results_bucket(config)

    queue_name = athena_config.get('queue_name',
                                   f'{prefix}_streamalert_athena_s3_notifications').strip()

    logging_bucket, _ = s3_access_logging_bucket(config)

    # Set variables for the athena partitioner's IAM permissions
    result['module']['athena_partitioner_iam'] = {
        'source': './modules/tf_athena',
        'account_id': config['global']['account']['aws_account_id'],
        'prefix': prefix,
        's3_logging_bucket': logging_bucket,
        'database_name': database,
        'queue_name': queue_name,
        'athena_data_buckets': data_buckets,
        'results_bucket': results_bucket_name,
        'lambda_timeout': athena_config['timeout'],
        'kms_key_id': '${aws_kms_key.server_side_encryption.key_id}',
        'function_role_id': '${module.athena_partitioner_lambda.role_id}',
        'function_name': '${module.athena_partitioner_lambda.function_name}',
        'function_alias_arn': '${module.athena_partitioner_lambda.function_alias_arn}',
    }

    # Set variables for the Lambda module
    result['module']['athena_partitioner_lambda'] = generate_lambda(
        f'{prefix}_streamalert_{ATHENA_PARTITIONER_NAME}',
        'streamalert.athena_partitioner.main.handler',
        athena_config,
        config,
        tags={'Subcomponent': 'AthenaPartitioner'})

    return result

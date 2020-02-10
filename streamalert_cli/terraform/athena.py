"""
Copyright 2017-present, Airbnb Inc.

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
from streamalert_cli.terraform.common import infinitedict


def generate_athena(config):
    """Generate Athena Terraform.

    Args:
        config (dict): The loaded config from the 'conf/' directory

    Returns:
        dict: Athena dict to be marshalled to JSON
    """
    athena_dict = infinitedict()
    athena_config = config['global']['infrastructure']['athena']

    prefix = config['global']['account']['prefix']
    database = athena_config.get('database_name', '{}_streamalert'.format(prefix))

    results_bucket_name = athena_config.get(
        'results_bucket',
        '{}.streamalert.athena-results'.format(prefix)
    ).strip()

    athena_dict['module']['streamalert_athena'] = {
        's3_logging_bucket': config['global']['s3_access_logging']['logging_bucket'],
        'source': './modules/tf_athena',
        'database_name': database,
        'results_bucket': results_bucket_name,
        'kms_key_id': '${aws_kms_key.server_side_encryption.key_id}',
        'prefix': prefix
    }

    return athena_dict

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
from streamalert.shared import FIREHOSE_EXTRACTOR_NAME
from streamalert_cli.manage_lambda.package import FirehoseExtractorPackage
from streamalert_cli.terraform.common import infinitedict
from streamalert_cli.terraform.lambda_module import generate_lambda


def generate_firehose_extractor(config):
    """Generate Terraform for the Firehose Extractor
    Args:
        config (dict): The loaded config from the 'conf/' directory
    Returns:
        dict: Firehose Extractor Terraform definition to be marshaled to JSON
    """
    result = infinitedict()

    # Set variables for the firehose extractor's IAM permissions
    result['module']['firehose_extractor_iam'] = {
        'source': './modules/tf_firehose_extractor_iam',
        'role_id': '${module.firehose_extractor_lambda.role_id}',

        # FIXME (ryxias) FIX THIS
        'artifact_firehose_arn': "arn:aws:firehose:us-east-1:009715504418:deliverystream/ryxias20200212_test_artifacts",
    }

    # Set variables for the Lambda module
    result['module']['firehose_extractor_lambda'] = generate_lambda(
        '{}_streamalert_{}'.format(
            config['global']['account']['prefix'],
            FIREHOSE_EXTRACTOR_NAME
        ),
        FirehoseExtractorPackage.package_name + '.zip',
        FirehoseExtractorPackage.lambda_handler,
        config['lambda']['firehose_extractor_config'],
        config,
        environment={}
    )

    return result

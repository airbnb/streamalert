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
from streamalert.shared import ALERT_MERGER_NAME
from streamalert_cli.terraform.common import infinitedict
from streamalert_cli.terraform.lambda_module import generate_lambda


def generate_alert_merger(config):
    """Generate Terraform for the Alert Merger
    Args:
        config (dict): The loaded config from the 'conf/' directory
    Returns:
        dict: Alert Merger Terraform definition to be marshaled to JSON
    """
    prefix = config['global']['account']['prefix']

    result = infinitedict()

    # Set variables for the alert merger's IAM permissions
    result['module']['alert_merger_iam'] = {
        'source': './modules/tf_alert_merger_iam',
        'account_id': config['global']['account']['aws_account_id'],
        'region': config['global']['account']['region'],
        'prefix': config['global']['account']['prefix'],
        'role_id': '${module.alert_merger_lambda.role_id}'
    }

    # Set variables for the Lambda module
    result['module']['alert_merger_lambda'] = generate_lambda(
        f"{config['global']['account']['prefix']}_streamalert_{ALERT_MERGER_NAME}",
        'streamalert.alert_merger.main.handler',
        config['lambda']['alert_merger_config'],
        config,
        environment={
            'ALERTS_TABLE': f'{prefix}_streamalert_alerts',
            'ALERT_PROCESSOR': f'{prefix}_streamalert_alert_processor',
            'ALERT_PROCESSOR_TIMEOUT_SEC': config['lambda']['alert_processor_config']['timeout']
        })

    return result

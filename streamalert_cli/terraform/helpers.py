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
from streamalert.shared.logger import get_logger
from streamalert_cli.helpers import run_command

LOGGER = get_logger(__name__)


def terraform_check():
    """Verify that Terraform is configured correctly

    Returns:
        bool: Success or failure of the command ran
    """
    error_message = (
        'Terraform not found! Please install and add to your $PATH:\n'
        '\texport PATH=$PATH:/usr/local/terraform/bin'
    )
    return run_command(
        ['terraform', 'version'],
        error_message=error_message,
        quiet=True,
    )

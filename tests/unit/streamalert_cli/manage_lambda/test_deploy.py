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
# pylint: disable=no-self-use,protected-access
import unittest
from unittest.mock import patch

from streamalert_cli.manage_lambda import deploy
from tests.unit.helpers.config import basic_streamalert_config


class DeployTest(unittest.TestCase):
    """DeployTest class for testing deployment functions"""

    def test_lambda_terraform_targets(self):
        """CLI - Deploy, Lambda Terraform Targets"""
        config = basic_streamalert_config()
        functions = ['rule', 'classifier']
        clusters = ['prod']
        result = deploy._lambda_terraform_targets(config, functions, clusters)
        expected_result = {
            'module.rules_engine_iam',
            'module.rules_engine_lambda',
            'module.classifier_prod_iam',
            'module.classifier_prod_lambda',
        }
        assert result == expected_result

    @patch('logging.Logger.warning')
    def test_lambda_terraform_targets_invalid_target(self, log_mock):
        """CLI - Deploy, Lambda Terraform Targets, Invalid Target"""
        config = basic_streamalert_config()

        # The scheduled_queries function is not enabled
        functions = ['scheduled_queries']
        clusters = []
        result = deploy._lambda_terraform_targets(config, functions, clusters)

        assert result == set()
        log_mock.assert_called_with(
            'Function is not enabled and will be ignored: %s',
            'scheduled_queries'
        )

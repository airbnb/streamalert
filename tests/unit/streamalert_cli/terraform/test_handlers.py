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
import os
from unittest.mock import Mock, patch

from pyfakefs import fake_filesystem_unittest

from streamalert_cli.terraform.handlers import get_tf_modules


class TestTerraformHandlers(fake_filesystem_unittest.TestCase):
    """Test class for the Terraform handler functions"""

    # pylint: disable=attribute-defined-outside-init

    def setUp(self):
        """Setup before each method"""
        self.setUpPyfakefs()
        self._build_directory = 'unit_test_terraform_path'

        mock_main_tf_json = {'module': {'module1': {'foo': 'bar'}}}
        mock_prod_tf_json = {
            'module': {
                'module2': {
                    'foo': 'bar'
                }
            },
            'resource': {
                'resource1': {
                    'foo': 'test'
                },
                'resource2': {
                    'bar': 'test'
                },
                'resource3': {
                    'pan': 'test'
                }
            }
        }
        # fake *.tf.json files
        self.fs.create_file(os.path.join(self._build_directory, 'main.tf.json'),
                            contents=json.dumps(mock_main_tf_json))
        self.fs.create_file(os.path.join(self._build_directory, 'prod.tf.json'),
                            contents=json.dumps(mock_prod_tf_json))

    @patch('streamalert_cli.terraform.handlers.terraform_generate_handler', Mock(return_value=True))
    def test_get_tf_modules_read_tf_json_files(self):
        """CLI - Terraform handler function get tf modules read all *.tf.json files"""
        config = Mock(return_value={}, build_directory=self._build_directory)
        result = get_tf_modules(config)

        expected_result = {
            'module': {'module1', 'module2'},
            'resource': {'resource1.foo', 'resource2.bar', 'resource3.pan'}
        }

        assert result == expected_result

    @patch('streamalert_cli.terraform.handlers.terraform_generate_handler',
           Mock(return_value=False))
    def test_get_tf_modules_early_return(self):
        """CLI - Terraform handler function get tf modules return early"""
        config = Mock(return_value={}, build_directory=self._build_directory)
        assert not get_tf_modules(config, generate=True)

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
# pylint: disable=protected-access
import os
from unittest.mock import Mock, patch

from pyfakefs import fake_filesystem_unittest

from streamalert_cli.config import CLIConfig
from streamalert_cli.manage_lambda import package


class PackageTest(fake_filesystem_unittest.TestCase):
    """Test the packaging logic for the Lambda package"""
    TEST_CONFIG_PATH = 'tests/unit/conf'
    MOCK_TEMP_PATH = '/tmp/test_packaging'

    @patch('streamalert_cli.config.CLIConfig._copy_terraform_files', Mock())
    def setUp(self):
        self.setUpPyfakefs()
        self.fs.add_real_directory(self.TEST_CONFIG_PATH)

        config = CLIConfig(self.TEST_CONFIG_PATH)

        with patch('tempfile.gettempdir') as temp_dir_mock:
            temp_dir_mock.return_value = self.MOCK_TEMP_PATH
            self.packager = package.LambdaPackage(config)

    def test_copy_directory_destination(self):
        """CLI - LambdaPackage copy directory using destination"""
        self.packager._copy_directory(self.TEST_CONFIG_PATH, destination='conf_test')

        # Ensure the specified destination exists and not the default
        self.assertTrue(os.path.exists(f'{self.MOCK_TEMP_PATH}/streamalert/conf_test'))
        self.assertFalse(os.path.exists(f'{self.MOCK_TEMP_PATH}/streamalert/conf'))

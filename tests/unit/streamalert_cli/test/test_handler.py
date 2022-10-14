"""
Copyright 2017-present Airbnb, Inc.

Licensed under the Apache License, Version 2.0 (the 'License');
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an 'AS IS' BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
import os
from io import StringIO
from unittest import mock
from unittest.mock import MagicMock, Mock, patch

import pytest
from pyfakefs import fake_filesystem_unittest

from streamalert.shared.config import load_config
from streamalert.shared.exceptions import ConfigError
from streamalert_cli.config import CLIConfig
from streamalert_cli.test.handler import TestRunner
from tests.unit.streamalert_cli.test.helpers import basic_test_file_json

# Test Runner is not a test class, so we don't want to run it as a test
TestRunner = pytest.mark.usefixtures('patcher')(TestRunner)


class TestTestRunner(fake_filesystem_unittest.TestCase):
    """Test the TestEventFile class"""
    # pylint: disable=protected-access

    TEST_CONFIG_PATH = 'tests/unit/conf'
    _DEFAULT_EVENT_PATH = 'rules/community/unit_test/file.json'

    def setUp(self):
        cli_config = CLIConfig(config_path='tests/unit/conf')
        with patch('streamalert.rules_engine.rules_engine.load_config',
                   Mock(return_value=load_config(self.TEST_CONFIG_PATH))):
            self.runner = TestRunner(MagicMock(), cli_config)

        self.setUpPyfakefs()

    @patch('logging.Logger.debug')
    def test_process_test_file_bad_service(self, log_mock):
        """StreamAlert CLI - TestRunner Process Test File, Misconfigured Service"""
        self.fs.create_file(
            self._DEFAULT_EVENT_PATH,
            contents=basic_test_file_json(
                log='unit_test_simple_log',
                source='unit_test_default_stream',
                service='s3'  # s3 here is a misconfiguration, should be kinesis
            ))

        pytest.raises(ConfigError, self.runner._process_test_file, self._DEFAULT_EVENT_PATH)
        log_mock.assert_has_calls([
            mock.call('Cluster "%s" does not have service "%s" configured as a data source',
                      'advanced', 's3'),
            mock.call('Cluster "%s" does not have service "%s" configured as a data source', 'test',
                      's3'),
            mock.call('Cluster "%s" does not have service "%s" configured as a data source',
                      'trusted', 's3')
        ],
            any_order=True)

    @patch('logging.Logger.debug')
    def test_process_test_file_bad_source(self, log_mock):
        """StreamAlert CLI - TestRunner Process Test File, Misconfigured Source"""
        self.fs.create_file(
            self._DEFAULT_EVENT_PATH,
            contents=basic_test_file_json(
                log='unit_test_simple_log',
                source='nonexistent_source',  # invalid source here
                service='kinesis'))

        pytest.raises(ConfigError, self.runner._process_test_file, self._DEFAULT_EVENT_PATH)
        log_mock.assert_has_calls([
            mock.call('Cluster "%s" does not have service "%s" configured as a data source',
                      'advanced', 'kinesis'),
            mock.call('Cluster "%s" does not have service "%s" configured as a data source',
                      'trusted', 'kinesis'),
            mock.call(
                'Cluster "%s" does not have the source "%s" configured as a data source '
                'for service "%s"', 'test', 'nonexistent_source', 'kinesis'),
        ],
            any_order=True)

    @patch('sys.stdout', new=StringIO())  # patch stdout to suppress integration test result
    def test_process_test_file(self):
        """StreamAlert CLI - TestRunner Process Test File"""
        self.fs.create_file(
            self._DEFAULT_EVENT_PATH,
            contents=basic_test_file_json(
                log='unit_test_simple_log',
                source='unit_test_default_stream',  # valid source
                service='kinesis'  # valid service
            ))
        self.fs.add_real_directory(self.TEST_CONFIG_PATH)
        with patch('streamalert.classifier.classifier.config.load_config',
                   Mock(return_value=load_config(self.TEST_CONFIG_PATH))):
            self.runner._process_test_file(self._DEFAULT_EVENT_PATH)

        # The CLUSTER env var should be properly deduced and set now
        assert os.environ['CLUSTER'] == 'test'

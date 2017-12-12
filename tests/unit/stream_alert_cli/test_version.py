"""
Copyright 2017-present, Airbnb Inc.

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
# pylint: disable=protected-access
from mock import patch
from nose.tools import assert_equal, assert_true, assert_false, nottest

from stream_alert_cli.manage_lambda.package import AthenaPackage, RuleProcessorPackage
from stream_alert_cli.manage_lambda.version import LambdaVersion
from tests.unit.helpers.aws_mocks import MockLambdaClient
from tests.unit.helpers.base import basic_streamalert_config, MockCLIConfig


# @patch('stream_alert_cli.athena_partition_refresh.main.ATHENA_CLIENT',
#        MockAthenaClient(results=[{'alerts': True}]))
@nottest
def test_publish_clustered():
    pass


@patch('boto3.client', MockLambdaClient)
def test_publish_helper_clustered():
    """CLI - Publish Clustered Function"""
    config = MockCLIConfig(config=basic_streamalert_config())
    package = RuleProcessorPackage(config=config)
    publish = LambdaVersion(
        config=config,
        package=package
    )
    result = publish._publish_helper(cluster='prod')

    assert_true(result)
    assert_equal(
        config['clusters']['prod']['modules']['stream_alert']['rule_processor']['current_version'],
        11
    )


@patch('boto3.client', MockLambdaClient)
def test_publish_helper():
    """CLI - Publish Athena Function"""
    config = MockCLIConfig(config=basic_streamalert_config())
    package = AthenaPackage(config=config)
    publish = LambdaVersion(
        config=config,
        package=package
    )
    result = publish._publish_helper()

    assert_equal(config['lambda']['athena_partition_refresh_config']['current_version'], 11)
    assert_true(result)


def test_version_helper():
    """CLI - Publish Helper"""
    package = AthenaPackage(basic_streamalert_config())
    publish = LambdaVersion(
        config=basic_streamalert_config(),
        package=package
    )
    current_version = 10
    fake_client = MockLambdaClient('athena', current_version=current_version)
    result = publish._version_helper(
        client=fake_client,
        function_name='test',
        code_sha_256='12345',
        date='2017-01-01'
    )

    assert_equal(result, current_version + 1)


@patch('stream_alert_cli.manage_lambda.version.LOGGER_CLI')
def test_version_helper_error(mock_logging):
    """CLI - Publish Helper Raises Error"""
    package = AthenaPackage(basic_streamalert_config())
    publish = LambdaVersion(
        config=basic_streamalert_config(),
        package=package
    )
    current_version = 10
    fake_client = MockLambdaClient('athena',
                                   current_version=current_version,
                                   throw_exception=True)
    result = publish._version_helper(
        client=fake_client,
        function_name='test',
        code_sha_256='12345',
        date='2017-01-01'
    )

    assert_false(result)
    assert_true(mock_logging.error.called)

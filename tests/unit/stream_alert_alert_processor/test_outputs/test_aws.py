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
# pylint: disable=abstract-class-instantiated,protected-access,attribute-defined-outside-init,no-self-use
import boto3
from mock import patch
from moto import mock_s3, mock_lambda, mock_kinesis
from nose.tools import (
    assert_equal,
    assert_false,
    assert_is_not_none,
    assert_true
)

from stream_alert.alert_processor.outputs.output_base import OutputProperty
from stream_alert.alert_processor.outputs.aws import (
    AWSOutput,
    KinesisFirehoseOutput,
    LambdaOutput,
    S3Output
)
from stream_alert_cli.helpers import create_lambda_function
from tests.unit.stream_alert_alert_processor import CONFIG, FUNCTION_NAME, REGION
from tests.unit.stream_alert_alert_processor.helpers import get_alert


class TestAWSOutput(object):
    """Test class for AWSOutput Base"""

    @patch.object(AWSOutput, '__service__', 'aws-s3')
    def test_aws_format_output_config(self):
        """AWSOutput - Format Output Config"""
        props = {
            'descriptor': OutputProperty(
                'short_descriptor',
                'descriptor_value'),
            'aws_value': OutputProperty(
                'unique arn value, bucket, etc',
                'bucket.value')}

        formatted_config = AWSOutput.format_output_config(CONFIG, props)

        assert_equal(len(formatted_config), 2)
        assert_is_not_none(formatted_config.get('descriptor_value'))
        assert_is_not_none(formatted_config.get('unit_test_bucket'))


@mock_s3
class TestS3Ouput(object):
    """Test class for S3Output"""
    DESCRIPTOR = 'unit_test_bucket'
    SERVICE = 'aws-s3'

    def setup(self):
        """Setup before each method"""
        self._dispatcher = S3Output(REGION, FUNCTION_NAME, CONFIG)
        bucket = CONFIG[self.SERVICE][self.DESCRIPTOR]
        boto3.client('s3', region_name=REGION).create_bucket(Bucket=bucket)

    def test_locals(self):
        """S3Output local variables"""
        assert_equal(self._dispatcher.__class__.__name__, 'S3Output')
        assert_equal(self._dispatcher.__service__, self.SERVICE)

    @patch('logging.Logger.info')
    def test_dispatch(self, log_mock):
        """S3Output - Dispatch Success"""
        assert_true(self._dispatcher.dispatch(descriptor=self.DESCRIPTOR,
                                              rule_name='rule_name',
                                              alert=get_alert()))

        log_mock.assert_called_with('Successfully sent alert to %s', self.SERVICE)


@mock_kinesis
class TestFirehoseOutput(object):
    """Test class for AWS Kinesis Firehose"""
    DESCRIPTOR = 'unit_test_delivery_stream'
    SERVICE = 'aws-firehose'

    def setup(self):
        """Setup before each method"""
        self._dispatcher = KinesisFirehoseOutput(REGION, FUNCTION_NAME, CONFIG)
        delivery_stream = CONFIG[self.SERVICE][self.DESCRIPTOR]
        boto3.client('firehose', region_name=REGION).create_delivery_stream(
            DeliveryStreamName=delivery_stream,
            S3DestinationConfiguration={
                'RoleARN': 'arn:aws:iam::123456789012:role/firehose_delivery_role',
                'BucketARN': 'arn:aws:s3:::unit_test',
                'Prefix': '/',
                'BufferingHints': {
                    'SizeInMBs': 128,
                    'IntervalInSeconds': 128
                },
                'CompressionFormat': 'GZIP',
            }
        )

    def test_locals(self):
        """Output local variables - Kinesis Firehose"""
        assert_equal(self._dispatcher.__class__.__name__, 'KinesisFirehoseOutput')
        assert_equal(self._dispatcher.__service__, self.SERVICE)

    @patch('logging.Logger.info')
    def test_dispatch(self, log_mock):
        """Kinesis Firehose - Output Dispatch Success"""
        assert_true(self._dispatcher.dispatch(descriptor=self.DESCRIPTOR,
                                              rule_name='rule_name',
                                              alert=get_alert()))

        log_mock.assert_called_with('Successfully sent alert to %s', self.SERVICE)

    def test_dispatch_ignore_large_payload(self):
        """Output Dispatch - Kinesis Firehose with Large Payload"""
        alert = get_alert()
        alert['record'] = 'test' * 1000 * 1000
        assert_false(self._dispatcher.dispatch(descriptor=self.DESCRIPTOR,
                                               rule_name='rule_name',
                                               alert=alert))


@mock_lambda
class TestLambdaOuput(object):
    """Test class for LambdaOutput"""
    DESCRIPTOR = 'unit_test_lambda'
    SERVICE = 'aws-lambda'

    def setup(self):
        """Setup before each method"""
        self._dispatcher = LambdaOutput(REGION, FUNCTION_NAME, CONFIG)
        create_lambda_function(CONFIG[self.SERVICE][self.DESCRIPTOR], REGION)

    def test_locals(self):
        """LambdaOutput local variables"""
        assert_equal(self._dispatcher.__class__.__name__, 'LambdaOutput')
        assert_equal(self._dispatcher.__service__, self.SERVICE)

    @patch('logging.Logger.info')
    def test_dispatch(self, log_mock):
        """LambdaOutput dispatch"""
        assert_true(self._dispatcher.dispatch(descriptor=self.DESCRIPTOR,
                                              rule_name='rule_name',
                                              alert=get_alert()))

        log_mock.assert_called_with('Successfully sent alert to %s', self.SERVICE)

    @patch('logging.Logger.info')
    def test_dispatch_with_qualifier(self, log_mock):
        """LambdaOutput - Dispatch Success, With Qualifier"""
        alt_descriptor = '{}_qual'.format(self.DESCRIPTOR)
        create_lambda_function(alt_descriptor, REGION)
        assert_true(self._dispatcher.dispatch(descriptor=alt_descriptor,
                                              rule_name='rule_name',
                                              alert=get_alert()))

        log_mock.assert_called_with('Successfully sent alert to %s', self.SERVICE)

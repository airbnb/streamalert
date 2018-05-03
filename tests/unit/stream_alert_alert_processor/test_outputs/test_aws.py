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
from moto import mock_kinesis, mock_lambda, mock_s3, mock_sns, mock_sqs
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
    S3Output,
    SNSOutput,
    SQSOutput,
    CloudwatchLogOutput
)
from stream_alert_cli.helpers import create_lambda_function
from tests.unit.stream_alert_alert_processor import (
    ACCOUNT_ID,
    CONFIG,
    FUNCTION_NAME,
    PREFIX,
    REGION
)
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


@mock_kinesis
class TestFirehoseOutput(object):
    """Test class for AWS Kinesis Firehose"""
    DESCRIPTOR = 'unit_test_delivery_stream'
    SERVICE = 'aws-firehose'
    OUTPUT = ':'.join([SERVICE, DESCRIPTOR])

    def setup(self):
        """Setup before each method"""
        self._dispatcher = KinesisFirehoseOutput(REGION, ACCOUNT_ID, PREFIX, CONFIG)
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
        """Kinesis Firehose - Output local variables"""
        assert_equal(self._dispatcher.__class__.__name__, 'KinesisFirehoseOutput')
        assert_equal(self._dispatcher.__service__, self.SERVICE)

    @patch('logging.Logger.info')
    def test_dispatch(self, log_mock):
        """Kinesis Firehose - Output Dispatch Success"""
        assert_true(self._dispatcher.dispatch(get_alert(), self.OUTPUT))

        log_mock.assert_called_with('Successfully sent alert to %s:%s',
                                    self.SERVICE, self.DESCRIPTOR)

    def test_dispatch_ignore_large_payload(self):
        """Output Dispatch - Kinesis Firehose with Large Payload"""
        alert = get_alert()
        alert.record = 'test' * 1000 * 1000
        assert_false(self._dispatcher.dispatch(alert, self.OUTPUT))


@mock_lambda
class TestLambdaOutput(object):
    """Test class for LambdaOutput"""
    DESCRIPTOR = 'unit_test_lambda'
    SERVICE = 'aws-lambda'
    OUTPUT = ':'.join([SERVICE, DESCRIPTOR])

    def setup(self):
        """Setup before each method"""
        self._dispatcher = LambdaOutput(REGION, ACCOUNT_ID, FUNCTION_NAME, CONFIG)
        create_lambda_function(CONFIG[self.SERVICE][self.DESCRIPTOR], REGION)

    def test_locals(self):
        """LambdaOutput local variables"""
        assert_equal(self._dispatcher.__class__.__name__, 'LambdaOutput')
        assert_equal(self._dispatcher.__service__, self.SERVICE)

    @patch('logging.Logger.info')
    def test_dispatch(self, log_mock):
        """LambdaOutput dispatch"""
        assert_true(self._dispatcher.dispatch(get_alert(), self.OUTPUT))

        log_mock.assert_called_with('Successfully sent alert to %s:%s',
                                    self.SERVICE, self.DESCRIPTOR)

    @patch('logging.Logger.info')
    def test_dispatch_with_qualifier(self, log_mock):
        """LambdaOutput - Dispatch Success, With Qualifier"""
        alt_descriptor = '{}_qual'.format(self.DESCRIPTOR)
        create_lambda_function(CONFIG[self.SERVICE][alt_descriptor], REGION)

        assert_true(
            self._dispatcher.dispatch(get_alert(), ':'.join([self.SERVICE, alt_descriptor])))

        log_mock.assert_called_with('Successfully sent alert to %s:%s',
                                    self.SERVICE, alt_descriptor)


@mock_s3
class TestS3Output(object):
    """Test class for S3Output"""
    DESCRIPTOR = 'unit_test_bucket'
    SERVICE = 'aws-s3'
    OUTPUT = ':'.join([SERVICE, DESCRIPTOR])

    def setup(self):
        """Setup before each method"""
        self._dispatcher = S3Output(REGION, ACCOUNT_ID, FUNCTION_NAME, CONFIG)
        bucket = CONFIG[self.SERVICE][self.DESCRIPTOR]
        boto3.client('s3', region_name=REGION).create_bucket(Bucket=bucket)

    def test_locals(self):
        """S3Output local variables"""
        assert_equal(self._dispatcher.__class__.__name__, 'S3Output')
        assert_equal(self._dispatcher.__service__, self.SERVICE)

    @patch('logging.Logger.info')
    def test_dispatch(self, log_mock):
        """S3Output - Dispatch Success"""
        assert_true(self._dispatcher.dispatch(get_alert(), self.OUTPUT))

        log_mock.assert_called_with('Successfully sent alert to %s:%s',
                                    self.SERVICE, self.DESCRIPTOR)


@mock_sns
class TestSNSOutput(object):
    """Test class for SNSOutput"""
    DESCRIPTOR = 'unit_test_topic'
    SERVICE = 'aws-sns'
    OUTPUT = ':'.join([SERVICE, DESCRIPTOR])

    def setup(self):
        """Create the dispatcher and the mock SNS topic."""
        self._dispatcher = SNSOutput(REGION, ACCOUNT_ID, FUNCTION_NAME, CONFIG)
        topic_name = CONFIG[self.SERVICE][self.DESCRIPTOR]
        boto3.client('sns', region_name=REGION).create_topic(Name=topic_name)

    @patch('logging.Logger.info')
    def test_dispatch(self, log_mock):
        """SNSOutput - Dispatch Success"""
        assert_true(self._dispatcher.dispatch(get_alert(), self.OUTPUT))

        log_mock.assert_called_with('Successfully sent alert to %s:%s',
                                    self.SERVICE, self.DESCRIPTOR)


@mock_sqs
class TestSQSOutput(object):
    """Test class for SQSOutput"""
    DESCRIPTOR = 'unit_test_queue'
    SERVICE = 'aws-sqs'
    OUTPUT = ':'.join([SERVICE, DESCRIPTOR])

    def setup(self):
        """Create the dispatcher and the mock SQS queue."""
        self._dispatcher = SQSOutput(REGION, ACCOUNT_ID, FUNCTION_NAME, CONFIG)
        queue_name = CONFIG[self.SERVICE][self.DESCRIPTOR]
        boto3.client('sqs', region_name=REGION).create_queue(QueueName=queue_name)

    @patch('logging.Logger.info')
    def test_dispatch(self, log_mock):
        """SQSOutput - Dispatch Success"""
        assert_true(self._dispatcher.dispatch(get_alert(), self.OUTPUT))

        log_mock.assert_called_with('Successfully sent alert to %s:%s',
                                    self.SERVICE, self.DESCRIPTOR)


class TestCloudwatchLogOutput(object):
    """Test class for CloudwatchLogOutput"""
    DESCRIPTOR = 'unit_test_default'
    SERVICE = 'aws-cloudwatch-log'
    OUTPUT = ':'.join([SERVICE, DESCRIPTOR])

    def setup(self):
        """Create the Cloudwatch dispatcher"""
        self._dispatcher = CloudwatchLogOutput(REGION, ACCOUNT_ID, FUNCTION_NAME, CONFIG)

    @patch('logging.Logger.info')
    def test_dispatch(self, log_mock):
        """Cloudwatch - Dispatch"""
        alert = get_alert()

        assert_true(self._dispatcher.dispatch(alert, self.OUTPUT))
        assert_equal(log_mock.call_count, 3)
        log_mock.assert_called_with('Successfully sent alert to %s:%s',
                                    self.SERVICE, self.DESCRIPTOR)

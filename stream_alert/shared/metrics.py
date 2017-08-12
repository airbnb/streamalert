'''
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
'''
import json
import os

from datetime import datetime

import boto3

from botocore.exceptions import ClientError

from stream_alert.shared import LOGGER

CLUSTER = os.environ.get('CLUSTER', 'unknown_cluster')


class Metrics(object):
    """Class to hold metric names and unit constants
    This basically acts as an enum, allowing for the use of dot notation for
    accessing properties and avoids doing dict lookups a ton.
    """

    def __init__(self, function, region):
        self.boto_cloudwatch = boto3.client('cloudwatch', region_name=region)
        self._metric_data = []
        self._dimensions = [
            {
                'Name': 'Cluster',
                'Value': CLUSTER
            },
            {
                'Name': 'Function',
                'Value': function
            }
        ]

    class Name(object):
        """Constant metric names used for CloudWatch"""
        FAILED_PARSES = 'FailedParses'
        S3_DOWNLOAD_TIME = 'S3DownloadTime'
        TOTAL_RECORDS = 'TotalRecords'
        TOTAL_S3_RECORDS = 'TotalS3Records'
        TRIGGERED_ALERTS = 'TriggeredAlerts'

    class Unit(object):
        """Unit names for metrics. These are taken from the boto3 CloudWatch page"""
        SECONDS = 'Seconds'
        MICROSECONDS = 'Microseconds'
        MILLISECONDS = 'Milliseconds'
        BYTES = 'Bytes'
        KILOBYTES = 'Kilobytes'
        MEGABYTES = 'Megabytes'
        GIGABYTES = 'Gigabytes'
        TERABYTES = 'Terabytes'
        BITS = 'Bits'
        KILOBITS = 'Kilobits'
        MEGABITS = 'Megabits'
        GIGABITS = 'Gigabits'
        TERABITS = 'Terabits'
        PERCENT = 'Percent'
        COUNT = 'Count'
        BYTES_PER_SECOND = 'Bytes/Second'
        KILOBYTES_PER_SECOND = 'Kilobytes/Second'
        MEGABYTES_PER_SECOND = 'Megabytes/Second'
        GIGABYTES_PER_SECOND = 'Gigabytes/Second'
        TERABYTES_PER_SECOND = 'Terabytes/Second'
        BITS_PER_SECOND = 'Bits/Second'
        KILOBITS_PER_SECOND = 'Kilobits/Second'
        MEGABITS_PER_SECOND = 'Megabits/Second'
        GIGABITS_PER_SECOND = 'Gigabits/Second'
        TERABITS_PER_SECOND = 'Terabits/Second'
        COUNT_PER_SECOND = 'Count/Second'
        NONE = 'None'

    def add_metric(self, metric_name, value, unit):
        """Add a metric to the list of metrics to be sent to CloudWatch

        Args:
            metric_name [string]: Name of metric to publish to. Choices are in
                `Metrics.Name` above
            value [number]: Numeric information to post to metric. AWS expects
                this to be of type 'float' but will accept any numeric value that
                is not super small (negative) or super large.
            unit [string]: Unit to use for this metric. Choices are in
                `Metrics.Unit` above.
        """
        if metric_name not in self.Name.__dict__.values():
            LOGGER.error('Metric name not defined: %s', metric_name)
            return

        if unit not in self.Unit.__dict__.values():
            LOGGER.error('Metric unit not defined: %s', unit)
            return

        self._metric_data.append(
            {
                'MetricName': metric_name,
                'Timestamp': datetime.utcnow(),
                'Unit': unit,
                'Value': value,
                "Dimensions": self._dimensions
            }
        )

    def send_metrics(self):
        """Public method for publishing custom metric data to CloudWatch."""
        if not self._metric_data:
            LOGGER.debug('No metric data to send to CloudWatch.')
            return

        for metric in self._metric_data:
            LOGGER.debug('Sending metric data to CloudWatch: %s', metric['MetricName'])

        self._put_metrics()

    def _put_metrics(self):
        """Protected method for publishing custom metric data to CloudWatch that
        handles all of the boto3 calls and error handling.
        """
        try:
            self.boto_cloudwatch.put_metric_data(
                Namespace='StreamAlert', MetricData=self._metric_data)
        except ClientError as err:
            LOGGER.exception(
                'Failed to send metric to CloudWatch. Error: %s\nMetric data:\n%s',
                err.response,
                json.dumps(
                    self._metric_data,
                    indent=2,
                    default=lambda d: d.isoformat()))

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
import os

from stream_alert.shared import (
    ALERT_PROCESSOR_NAME,
    ATHENA_PARTITION_REFRESH_NAME,
    LOGGER,
    RULE_PROCESSOR_NAME
)

CLUSTER = os.environ.get('CLUSTER', 'unknown_cluster')

# The FUNC_PREFIXES dict acts as a simple map to a human-readable name
# Add ATHENA_PARTITION_REFRESH_NAME: 'AthenaPartitionRefresh', to the
# below when metrics are supported there
FUNC_PREFIXES = {ALERT_PROCESSOR_NAME: 'AlertProcessor',
                 RULE_PROCESSOR_NAME: 'RuleProcessor'}

try:
    ENABLE_METRICS = bool(int(os.environ.get('ENABLE_METRICS', 0)))
except ValueError as err:
    ENABLE_METRICS = False
    LOGGER.error('Invalid value for metric toggling, expected 0 or 1: %s',
                 err.message)

if not ENABLE_METRICS:
    LOGGER.debug('Logging of metric data is currently disabled.')


class MetricLogger(object):
    """Class to hold metric logging to be picked up by log metric filters.

    This basically acts as an enum, allowing for the use of dot notation for
    accessing properties and avoids doing dict lookups a ton.
    """

    # Constant metric names used for CloudWatch
    FAILED_PARSES = 'FailedParses'
    S3_DOWNLOAD_TIME = 'S3DownloadTime'
    TOTAL_PROCESSED_SIZE = 'TotalProcessedSize'
    TOTAL_RECORDS = 'TotalRecords'
    TOTAL_S3_RECORDS = 'TotalS3Records'
    TOTAL_STREAM_ALERT_APP_RECORDS = 'TotalStreamAlertAppRecords'
    TRIGGERED_ALERTS = 'TriggeredAlerts'
    FIREHOSE_RECORDS_SENT = 'FirehoseRecordsSent'
    FIREHOSE_FAILED_RECORDS = 'FirehoseFailedRecords'

    _default_filter = '{{ $.metric_name = "{}" }}'
    _default_value_lookup = '$.metric_value'

    # Establish all the of available metrics for each processor. These use default
    # values for the filter pattern and value lookup, created above, but can be
    # overridden in special cases. The terraform generate code uses these values to
    # create the actual CloudWatch metric filters that will be used for each function.
    # If additional metric logging is added that does not conform to this default
    # configuration, new filters & lookups should be created to handle them as well.
    _available_metrics = {
        ALERT_PROCESSOR_NAME: {},   # Placeholder for future alert processor metrics
        ATHENA_PARTITION_REFRESH_NAME: {},  # Placeholder for future athena processor metrics
        RULE_PROCESSOR_NAME: {
            FAILED_PARSES: (_default_filter.format(FAILED_PARSES),
                            _default_value_lookup),
            S3_DOWNLOAD_TIME: (_default_filter.format(S3_DOWNLOAD_TIME),
                               _default_value_lookup),
            TOTAL_PROCESSED_SIZE: (_default_filter.format(TOTAL_PROCESSED_SIZE),
                                   _default_value_lookup),
            TOTAL_RECORDS: (_default_filter.format(TOTAL_RECORDS),
                            _default_value_lookup),
            TOTAL_S3_RECORDS: (_default_filter.format(TOTAL_S3_RECORDS),
                               _default_value_lookup),
            TRIGGERED_ALERTS: (_default_filter.format(TRIGGERED_ALERTS),
                               _default_value_lookup),
            FIREHOSE_RECORDS_SENT: (_default_filter.format(FIREHOSE_RECORDS_SENT),
                                    _default_value_lookup),
            FIREHOSE_FAILED_RECORDS: (_default_filter.format(FIREHOSE_FAILED_RECORDS),
                                      _default_value_lookup),
            TOTAL_STREAM_ALERT_APP_RECORDS:
                (_default_filter.format(TOTAL_STREAM_ALERT_APP_RECORDS), _default_value_lookup)
        }
    }

    @classmethod
    def log_metric(cls, lambda_function, metric_name, value):
        """Log a metric using the logger the list of metrics to be sent to CloudWatch

        Args:
            metric_name (str): Name of metric to publish to. Choices are in `Metrics.Name` above
            value (num): Numeric information to post to metric. AWS expects
                this to be of type 'float' but will accept any numeric value that
                is not super small (negative) or super large.
        """
        # Do not log any metrics if they have been disabled by the user
        if not ENABLE_METRICS:
            return

        if lambda_function not in cls._available_metrics:
            LOGGER.error('Function \'%s\' not defined in available metrics. Options are: %s',
                         lambda_function,
                         ', '.join('\'{}\''.format(key) for key in cls._available_metrics
                                   if cls._available_metrics[key]))
            return

        if metric_name not in cls._available_metrics[lambda_function]:
            LOGGER.error('Metric name (\'%s\') not defined for \'%s\' function. Options are: %s',
                         metric_name,
                         lambda_function,
                         ', '.join('\'{}\''.format(value)
                                   for value in cls._available_metrics[lambda_function]))
            return

        # Use a default format for logging this metric that will get picked up by the filters
        LOGGER.info('{"metric_name": "%s", "metric_value": %s}', metric_name, value)

    @classmethod
    def get_available_metrics(cls):
        """Return the protected dictionary of metrics for all functions"""
        return cls._available_metrics

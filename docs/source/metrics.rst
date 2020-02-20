#######
Metrics
#######
StreamAlert allows to enable `Enhanced Monitoring`_ to surface infrastructure metrics at a granular level.

.. _Enhanced Monitoring: https://docs.aws.amazon.com/kinesis/latest/APIReference/API_EnableEnhancedMonitoring.html

When enabled, access them by going to AWS Console -> CloudWatch -> Metrics -> Kinesis.

Enhanced metrics can be enabled in ``conf/global.json`` as ``shard_level_metrics``, for example:

.. code-block:: bash

  "shard_level_metrics": [
    "IncomingBytes",
    "IncomingRecords",
    "OutgoingBytes",
    "OutgoingRecords",
    "WriteProvisionedThroughputExceeded",
    "ReadProvisionedThroughputExceeded",
    "IteratorAgeMilliseconds"
  ]

These metrics can be viewed at the shard-level or the stream-level (cluster/environment).

All of CloudWatch's features are at your disposal: graphing, dashboards, alerting, and more.

These metrics are useful for debugging, alerting on infrastructure metrics you care about, or for just getting a sense of the scale at which you're analyzing and alerting on data.


.. _custom_metrics:

**************
Custom Metrics
**************
By default, StreamAlert will log various custom metrics to AWS CloudWatch Metrics via Amazon CloudWatch Logs `Metric Filters <http://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/MonitoringLogData.html>`_.

Amazon CloudWatch Logs Metric Filters utilize `Filter Patterns <http://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html>`_ to provide an extremely low-cost and highly scalable
approach to tracking custom metrics.

The decision to use Metric Filters vs `CloudWatch PutMetricData <http://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricData.html>`_ was made easy due to the
`limitations <http://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch_limits.html>`_ imposed by the PutMetricData API. StreamAlert has the potential to handle very
high throughput, so the posting of metrics needed to be able to keep pace. Metric Filter Patterns leverage the runtime's existing logger output in order to generate custom metrics
that can be graphed, use for alarms, etc.

StreamAlert logs custom metrics on the `cluster` level and also on the `aggregate` (aka: global) level. For example, a metric for `FailedParses` will be created for each individual cluster that is
configured. Along with publishing the metric to the respective cluster's metrics, the metric will also get published to the aggregate value for this metric. Think of the aggregate as a summation of a
metric across the entire StreamAlert deployment.

Custom metrics are logged to a unique `StreamAlert` namespace within CloudWatch Logs. Navigate to AWS Console -> CloudWatch -> Metrics -> StreamAlert to view these metrics.

Custom metrics definitions are found within ``streamalert/shared/metrics.py``.

Classifier Custom Metrics
=========================
- FailedParses
- FirehoseFailedRecords
- FirehoseRecordsSent
- NormalizedRecords
- S3DownloadTime
- SQSFailedRecords
- SQSRecordsSent
- TotalProcessedSize
- TotalRecords
- TotalS3Records
- TotalStreamAlertAppRecords
- TriggeredAlerts


Rules Engine Custom Metrics
===========================
- FailedDynamoWrites
- TriggeredAlerts


Alert Merger Custom Metrics
===========================
- AlertAttempts


***********************
Toggling Custom Metrics
***********************
Logging of custom metrics will be enabled by default for the Lambda functions that support this feature.

To globally (for all clusters) disable custom metrics for the classifier function:

.. code-block:: bash

  python manage.py custom-metrics --disable --functions classifier


To disable custom metrics for the classifier function within specific cluster:

.. code-block:: bash

  python manage.py custom-metrics --disable --functions classifier --clusters <CLUSTER>


Swap the ``--disable`` flag for ``--enable`` in the above commands to have the inverse affect.


*************************
Alarms for Custom Metrics
*************************
With the addition of custom metrics comes the added bonus of CloudWatch alarms for custom metrics.
StreamAlert's CLI can be used to add alarms on custom metrics as you see fit. Custom metric alarms
can be applied to both **aggregate** metrics (across all clusters), or one or more **cluster**.

To get an up-to-date list of metrics to which alarms can be assigned on a cluster basis, run:

.. code-block:: bash

  python manage.py create-cluster-alarm --help

To get an up-to-date list of metrics to which alarms can be assigned on an aggregate/global level, run:

.. code-block:: bash

  python manage.py create-alarm --help


The required arguments for the ``create-alarm`` and ``create-cluster-alarm`` commands mimic what is
required by AWS CloudWatch Metric's `PutMetricAlarm API <http://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricAlarm.html>`_.


Example: FailedParses, Cluster
==============================
FailedParses alarm at the ``prod`` cluster level

.. code-block:: bash

  python manage.py create-cluster-alarm FailedParsesAlarm \
    --metric FailedParses \
    --metric-target cluster \
    --comparison-operator GreaterThanOrEqualToThreshold \
    --evaluation-periods 1 \
    --period 600 \
    --threshold 5.0 \
    --alarm-description 'Trigger this alarm if 5 or more failed parses occur within a 10 minute period in the cluster "prod"' \
    --clusters prod \
    --statistic Sum


Example: TotalRecords, Global
=============================
TotalRecords alarm on a global level

.. code-block:: bash

  python manage.py create-alarm MinimumTotalRecordsAlarm \
    --metric TotalRecords \
    --metric-target aggregate \
    --comparison-operator LessThanThreshold \
    --evaluation-periods 3 \
    --period 600 \
    --threshold 200000 \
    --alarm-description 'Trigger this alarm if the total incoming records (aggregate) drops below 200000 for 3 consecutive 10 minute time periods in a row' \
    --statistic Sum

The custom metric alarms will notify StreamAlert's default SNS topic for monitoring: ``<prefix>_streamalert_monitoring``

Metrics
=======

StreamAlert enables `Enhanced Monitoring`_ to surface infrastructure metrics at a granular level.

.. _Enhanced Monitoring: https://docs.aws.amazon.com/kinesis/latest/APIReference/API_EnableEnhancedMonitoring.html

Go to AWS Console -> CloudWatch -> Metrics -> Kinesis to view them.

Example metrics:

* IncomingBytes
* IncomingRecords
* Error/Exceptions

These metrics can be viewed at the shard-level or the stream-level (cluster/environment).

All of CloudWatch's features are at your disposal: graphing, dashboards, alerting, and more.

These metrics are useful for debugging, alerting on infrastructure metrics you care about, or for just getting a sense of the scale at which you're analyzing and alerting on data.

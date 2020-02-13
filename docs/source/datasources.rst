Datasources
===========

StreamAlert supports the following services as datasources:

* Amazon S3
* AWS Kinesis Streams
* AWS SNS

These services above can accept data from:

* Log Forwarding Agents
* Custom Applications
* AWS CloudTrail
* AWS CloudWatch Events
* And more

To configure datasources, read `datasource configuration <conf-datasources.html>`_

Amazon S3
---------

StreamAlert supports data analysis and alerting for logs written to Amazon S3 buckets.
This is achieved via Amazon S3 Event Notifications from an event type of ``s3:ObjectCreated:*``.

Example AWS use-cases:

* AWS Config logs
* S3 Server Access logs

Example non-AWS use-cases:

* Host logs (syslog, auditd, osquery, ...)
* Network logs (Palo Alto Networks, Cisco, ...)
* Web Application logs (Apache, nginx, ...)
* SaaS logs (Box, GSuite, OneLogin, ...)

AWS Kinesis Streams
-------------------

StreamAlert also utilizes AWS Kinesis Streams for real-time data ingestion and analysis.
By default, StreamAlert creates an AWS Kinesis stream per `cluster <clusters.html>`_.

Sending to AWS Kinesis Streams
------------------------------

Log Forwarding Agents
~~~~~~~~~~~~~~~~~~~~~

Log forwarding agents that support AWS Kinesis Streams:

* `aws-kinesis-agent <http://docs.aws.amazon.com/streams/latest/dev/writing-with-agents.html>`_
* `fluentd <http://docs.fluentd.org/v0.12/articles/kinesis-stream>`_
* `logstash <https://github.com/samcday/logstash-output-kinesis>`_
* `osquery <https://osquery.readthedocs.io/en/stable/deployment/aws-logging/>`_

Code/Applications
~~~~~~~~~~~~~~~~~

Code can send data to an AWS Kinesis Stream via:

* `AWS KPL (Amazon Kinesis Producer Library) <http://docs.aws.amazon.com/streams/latest/dev/developing-producers-with-kpl.html>`_

AWS SNS
-------

Amazon Simple Notification Service (SNS) is a flexible, fully managed pub/sub messaging notification service for coordinating the delivery of messages to subscribing endpoints and clients.

StreamAlert can utilize SNS as an input for processing.

Use-cases:

* Receiving messages from other AWS services

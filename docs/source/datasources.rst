Datasources
===========

StreamAlert supports:

* Amazon S3
* AWS Kinesis Streams
* Log Forwarding Agents\*
* Code/Applications\*

.. note:: \* *Must send to a Kinesis Stream*

To configure datasources, read `datasource configuration <conf-datasources.html>`_

Amazon S3
---------

StreamAlert supports data analysis and alerting for logs written to configured Amazon S3 buckets.
This is achieved via Amazon S3 Event Notifications looking for an event type of ``s3:ObjectCreated:*``

Example AWS use-cases:

* **CloudTrail** logs
* **AWS Config** logs
* **S3 Server Access logs**

Example non-AWS use-cases:

* Host logs (syslog, auditd, osquery, ...)
* Network logs (Palo Alto Networks, Cisco, ...)
* Web Application logs (Apache, nginx, ...)
* SaaS logs (Box, OneLogin, …)

AWS Kinesis Streams
-------------------

StreamAlert also supports data analysis and alerting for logs written to AWS Kinesis Streams.
By default, StreamAlert configures an AWS Kinesis stream per `cluster <clusters.html>`_.

Optionally, StreamAlert can also utilize existing streams as an additional source
by adding the following into your generated Terraform cluster file (found in ``terraform/cluster-name.tf``)::

  // Enable a Kinesis Stream to send events to Lambda
  module "kinesis_events_<cluster-name>" {
    source                    = "modules/tf_stream_alert_kinesis_events"
    lambda_staging_enabled    = true
    lambda_production_enabled = true
    lambda_role_id            = "${module.stream_alert_<cluster-name>.lambda_role_id}"
    lambda_function_arn       = "${module.stream_alert_<cluster-name>.lambda_arn}"
    kinesis_stream_arn        = "<add-kinesis-stream-ARN-here>"
    role_policy_prefix        = "<cluster-name>"
  }
  
There are several ways to send data into AWS Kinesis, as listed below.

Log Forwarding Agents
~~~~~~~~~~~~~~~~~~~~~

StreamAlert utilizes AWS Kinesis Streams for real-time data ingestion.

Log forwarding agents that support AWS Kinesis Streams:

* **logstash**
* **fluentd**
* **aws-kinesis-agent**
* **osquery**

Code/Applications
~~~~~~~~~~~~~~~~~

StreamAlert utilizes AWS Kinesis Streams for real-time data ingestion.

Your code can send data to an AWS Kinesis Stream via:

* AWS SDK (Streams API)
* KPL (Amazon Kinesis Producer Library)

Architecture
============

StreamAlert consists of multiple AWS components connected together and managed by Terraform.

.. figure:: ../images/sa-complete-arch.png
  :alt: StreamAlert Architecture
  :align: center
  :target: _images/sa-complete-arch.png

Data Lifecycle
--------------

1. Log data can come through any of the supported `data sources <datasources.html>`_.
This includes Kinesis, S3, SNS, or using a `StreamAlert App <app-configuration.html>`_ to periodically
poll data from a third-party API.

2. Inbound logs are directed to the "rule processor" Lambda function in one of your `clusters <clusters.html>`_.
The rule processor is the first and most substantial component of StreamAlert, responsible for parsing,
classifying, and normalizing logs, running each record through the rules engine, and saving any alerts
to a DynamoDB table. The rule processor(s) also optionally forward raw log records to Firehose so
they can be queried with `Athena <athena-overview.html>`_.

3. The "alert merger" Lambda function regularly scans the alerts DynamoDB table. When new alerts arrive,
they are either forwarded immediately (by default) or, if merge options are specified, they are
bundled together with similar alerts before proceeding to the next stage.

4. The "alert processor" Lambda function is responsible for actually delivering the alert to its
configured `outputs <outputs.html>`_. All alerts implicitly include a Firehose output, which feeds
an S3 bucket that can be queried with Athena. Alerts will be retried indefinitely until they are successfully
delivered, at which point they will be removed from the DynamoDB table.

5. An "athena partition refresh" Lambda function runs periodically to onboard new StreamAlert data
and alerts into their respective Athena databases for historical search.

Other StreamAlert components include DynamoDB tables and Lambda functions for optional rule promotion
and threat intelligence integration.
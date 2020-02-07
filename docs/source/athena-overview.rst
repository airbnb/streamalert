Overview
========

AWS Athena is a Serverless query service used to analyze large volumes of data stored in S3.

Data in Athena is searchable via ANSI SQL and powered by Presto.

StreamAlert uses AWS Athena for historical searching of:

* Generated alerts from StreamAlert, enabled within StreamAlert out of the box
* All incoming log data sent to StreamAlert, configurable after StreamAlert initialization

This works by:

* Creating a ``streamalert`` Athena database
* Creating Athena tables to read S3 data
* Using a Lambda function to periodically refresh Athena to make the data searchable

Concepts
--------
* `AWS Athena details <https://aws.amazon.com/athena/details/>`_
* `AWS Athena tables <http://docs.aws.amazon.com/athena/latest/ug/creating-tables.html>`_
* `AWS Lambda FAQ <https://aws.amazon.com/athena/faqs/>`_
* `AWS Lambda pricing <https://aws.amazon.com/athena/pricing/>`_

Getting Started
---------------

Searching of alerts is enabled within StreamAlert out of the box, and can be further extended to search all incoming log data.

To create tables for searching data sent to StreamAlert, run:

.. code-block:: bash

  $ python manage.py athena create-table \
    --bucket <prefix>-streamalert-data \
    --table-name <log_name>

The log name above reflects an enabled log type in your StreamAlert deployment. These are also top level keys in the various files under the ``schemas`` directory.

For example, if you have 'cloudwatch' in your sources, you would want to create tables for all possible subtypes.  This includes ``cloudwatch:control_message``, ``cloudwatch:events``, and ``cloudwatch:flow_logs``. The ``:`` character is not an acceptable character in table names due to a Hive limitation, but your arguments can be either ``cloudwatch:events`` **or** ``cloudwatch_events``. Both will be handled properly by StreamAlert.

Repeat this process for all relevant data tables in your deployment.

Next Steps
----------

* `Read more about the Athena Partition Refresh Lambda function <athena-arch.html>`_
* `Configure and deploy Kinesis Firehose for delivery of data to S3 <firehose.html>`_

Athena Deployment
=================

Overview
--------

After the initial `Athena Setup <athena-setup.html>`_, a new Lambda function must be deployed.

The name of the Lambda function is Athena Partition Refresh.

The purpose of this function is to periodically refresh Athena tables to enable the search-ability of data.

The default refresh interval is 10 minutes.

Concepts
--------

The Athena Partition Refresh function utilizes:

* `AWS S3 Event Notifications <http://docs.aws.amazon.com/AmazonS3/latest/dev/NotificationHowTo.html>`_
* `AWS SQS <https://aws.amazon.com/sqs/details/>`_
* `AWS Lambda Invocations by Schedule <http://docs.aws.amazon.com/lambda/latest/dg/tutorial-scheduled-events-schedule-expressions.html>`_
* `AWS Athena Repair Table <http://docs.aws.amazon.com/athena/latest/ug/ddl/msck-repair-table.html>`_

Diagram
~~~~~~~

.. figure:: ../images/athena-refresh-arch.png
  :alt: StreamAlert Athena Refresh Partition Diagram
  :align: center
  :target: _images/athena-refresh-arch.png

Internals
~~~~~~~~~

Each time the Athena Partition Refresh Lambda function starts up, it does the following:

* Polls the SQS Queue for the latest S3 event notifications (up to 100)
* S3 event notifications contain context around any new object written to a data bucket (as configured below)
* A set of unique S3 Bucket IDs is deduplicated from the notifications
* Queries Athena to verify the ``streamalert`` database exists
* Refreshes the Athena tables as configured below in the ``repair_type`` key
* Deletes messages off the Queue once partitions are created

Getting Started
---------------

Configure Lambda Settings
~~~~~~~~~~~~~~~~~~~~~~~~~

Open ``conf/lambda.json``, and fill in the following required options below:


===================================  ========  ====================   ===========
Key                                  Required  Default                Description
-----------------------------------  --------  --------------------   -----------
``enabled``                          ``Yes``   ``true``               Enables/Disables the Athena Partition Refresh Lambda function
``enable_metrics``                   ``No``    ``false``              Enables/Disables logging of metrics for the Athena Partition Refresh Lambda function
``log_level``                        ``No``    ``info``               The log level for the Lambda function, can be either ``info`` or ``debug``.  Debug will help with diagnosing errors with polling SQS or sending Athena queries.
``memory``                           ``No``    ``128``                The amount of memory (in MB) allocated to the Lambda function
``timeout``                          ``No``    ``60``                 The maximum duration of the Lambda function (in seconds)
``refresh_interval``                 ``No``    ``rate(10 minutes)``   The rate of which the Athena Lambda function is invoked in the form of a `CloudWatch schedule expression <http://amzn.to/2u5t0hS>`_.
``refresh_type.add_hive_partition``  ``No``    ``{}``                 Add specific Hive partitions for new S3 objects.  This field is automatically populated when configuring your data tables.
``refresh_type.repair_hive_table``   ``Yes``   ``{}``                 Key value pairs of S3 buckets and associated Athena table names.  Currently only supports the default alerts bucket created with every cluster.
===================================  ========  ====================   ===========

**Example:**

.. code-block:: json

  {
    "athena_partition_refresh_config": {
      "enabled": true,
      "enable_metrics": false,
      "log_level": "info",
      "memory": 128,
      "refresh_type": {
        "add_hive_partition": {
          "...": "..."
        },
        "repair_hive_table": {
          "<prefix>.streamalerts": "alerts"
        }
      },
      "...": "...",
      "timeout": 60
    }
  }

Deployment
----------

After configuring the above settings, deploy the Lambda function:

.. code-block:: bash

  $ python manage.py lambda deploy --processor athena

This will create all of the underlying infrastructure to automatically refresh Athena tables.

Going forward, if the deploy flag ``--processor all`` is used, it will redeploy this function along with the ``rule_processor`` and ``alert_processor``.

Monitoring
~~~~~~~~~~

Once deployed, it's recommended to monitor the following SQS metrics for ``streamalert_athena_data_bucket_notifications``:

* ``NumberOfMessagesReceived``
* ``NumberOfMessagesSent``
* ``NumberOfMessagesDeleted``

All three of these metrics should have very close values.

If the ``NumberOfMessagesSent`` is much higher than the other two metrics, the ``refresh_interval`` should be increased in the configuration.

For high throughput production environments, an internal of 1 to 2 minutes is recommended. 

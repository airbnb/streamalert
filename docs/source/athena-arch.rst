Athena Architecture
===================

The Athena Partition Refresh function exists to periodically refresh Athena tables, enabling the searchability of alerts and log data.

The default refresh interval is 10 minutes but can be configured by the user.

Concepts
--------

The Athena Partition Refresh function utilizes:

* `AWS S3 Event Notifications <http://docs.aws.amazon.com/AmazonS3/latest/dev/NotificationHowTo.html>`_
* `AWS SQS <https://aws.amazon.com/sqs/details/>`_
* `AWS Lambda Invocations by Schedule <http://docs.aws.amazon.com/lambda/latest/dg/tutorial-scheduled-events-schedule-expressions.html>`_
* `AWS Athena Repair Table <https://docs.aws.amazon.com/athena/latest/ug/msck-repair-table.html>`_

Diagram
~~~~~~~

.. figure:: ../images/athena-refresh-arch.png
  :alt: StreamAlert Athena Refresh Partition Diagram
  :align: center
  :target: _images/athena-refresh-arch.png

Internals
~~~~~~~~~

Each time the Athena Partition Refresh Lambda function is invoked, it does the following:

* Polls the SQS queue for the latest S3 event notifications (up to 100)
* S3 event notifications contain context around any new object written to a data bucket (as configured below)
* A set of unique S3 Bucket IDs is deduplicated from the notifications
* Queries Athena to verify the ``streamalert`` database exists
* Refreshes the Athena tables for data in the relevant S3 buckets, as specified below in the list of ``buckets``
* Deletes messages off the queue once partitions are created

Configure Lambda Settings
-------------------------

Open ``conf/lambda.json``, and fill in the following options:


===================================  ========  ====================   ===========
Key                                  Required  Default                Description
-----------------------------------  --------  --------------------   -----------
``enabled``                          ``Yes``   ``true``               Enables/Disables the Athena Partition Refresh Lambda function
``enable_custom_metrics``            ``No``    ``false``              Enables/Disables logging of metrics for the Athena Partition Refresh Lambda function
``log_level``                        ``No``    ``info``               The log level for the Lambda function, can be either ``info`` or ``debug``.  Debug will help with diagnosing errors with polling SQS or sending Athena queries.
``memory``                           ``No``    ``128``                The amount of memory (in MB) allocated to the Lambda function
``timeout``                          ``No``    ``60``                 The maximum duration of the Lambda function (in seconds)
``schedule_expression``              ``No``    ``rate(10 minutes)``   The rate of which the Athena Partition Refresh Lambda function is invoked in the form of a `CloudWatch schedule expression <http://amzn.to/2u5t0hS>`_.
``buckets``                          ``Yes``   ``{}``                 Key value pairs of S3 buckets and associated Athena table names.  By default, the alerts bucket will exist in each deployment.
===================================  ========  ====================   ===========

**Example:**

.. code-block:: json

  {
    "athena_partition_refresh_config": {
      "log_level": "info",
      "memory": 128,
      "buckets": {
        "<prefix>-streamalerts": "alerts"
      },
      "...": "...",
      "timeout": 60
    }
  }


Deployment
----------

If any of the settings above are changed from the initialized defaults, the Lambda function will need to be deployed in order for them to take effect:

.. code-block:: bash

  $ python manage.py deploy --function athena

Going forward, if the deploy flag ``--function all`` is used, it will redeploy this function along with the ``rule`` function and ``alert`` function.

Monitoring
~~~~~~~~~~

To ensure the function is operating as expected, monitor the following SQS metrics for ``<prefix>_streamalert_athena_s3_notifications``:

* ``NumberOfMessagesReceived``
* ``NumberOfMessagesSent``
* ``NumberOfMessagesDeleted``

All three of these metrics should have very close values.

If the ``NumberOfMessagesSent`` is much higher than the other two metrics, the ``schedule_expression`` should be increased in the configuration.

For high throughput production environments, an interval of 1 to 2 minutes is recommended.

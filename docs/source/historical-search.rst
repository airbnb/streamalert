Historical Search
=================

Athena Overview
---------------
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
~~~~~~~~
* `AWS Athena details <https://aws.amazon.com/athena/details/>`_
* `AWS Athena tables <http://docs.aws.amazon.com/athena/latest/ug/creating-tables.html>`_
* `AWS Lambda FAQ <https://aws.amazon.com/athena/faqs/>`_
* `AWS Lambda pricing <https://aws.amazon.com/athena/pricing/>`_


Getting Started
~~~~~~~~~~~~~~~
Searching of alerts is enabled within StreamAlert out of the box, and can be further extended to search all incoming log data.

To create tables for searching data sent to StreamAlert, run:

.. code-block:: bash

  $ python manage.py athena create-table \
    --bucket <prefix>-streamalert-data \
    --table-name <log_name>

The log name above reflects an enabled log type in your StreamAlert deployment. These are also top level keys in the various files under the ``schemas`` directory.

For example, if you have 'cloudwatch' in your sources, you would want to create tables for all possible subtypes.  This includes ``cloudwatch:control_message``, ``cloudwatch:events``, and ``cloudwatch:flow_logs``. The ``:`` character is not an acceptable character in table names due to a Hive limitation, but your arguments can be either ``cloudwatch:events`` **or** ``cloudwatch_events``. Both will be handled properly by StreamAlert.

Repeat this process for all relevant data tables in your deployment.


Kinesis Firehose Configuration
------------------------------

Alerts
~~~~~~
By default, StreamAlert will send all alert payloads to S3 for historical retention and searching.
These payloads include the original record data that triggered the alert, as well as the rule that
was triggered, the source of the log, the date/time the alert was triggered, the cluster from
which the log came, and a variety of other fields.


Configuration
`````````````
The following ``alerts_firehose`` configuration settings can be defined within the ``infrastructure``
section of ``global.json``:

.. code-block:: json

  {
    "infrastructure": {
      "alerts_firehose": {
        "bucket_name": "<prefix>-streamalerts",
        "buffer_size": 64,
        "buffer_interval": 300,
        "cloudwatch_log_retention": 14,
        "compression_format": "GZIP"
      }
    }
  }


Options
'''''''
=============================  ========  ==========================  ===========
Key                            Required  Default                     Description
-----------------------------  --------  --------------------------  -----------
``bucket_name``                ``No``    ``<prefix>-streamalerts``   Bucket name to override the default name
``buffer_size``                ``No``    ``64 (MB)``                 Buffer incoming data to the specified size, in megabytes, before delivering it to S3
``buffer_interval``            ``No``    ``300 (seconds)``           Buffer incoming data for the specified period of time, in seconds, before delivering it to S3
``compression_format``         ``No``    ``GZIP``                    The compression algorithm to use on data stored in S3
``cloudwatch_log_retention``   ``No``    ``14 (days)``               Days for which to retain error logs that are sent to CloudWatch in relation to this Kinesis Firehose Delivery Stream
=============================  ========  ==========================  ===========

Classified Data
~~~~~~~~~~~~~~~
StreamAlert also supports sending all logs to S3 for historical retention and searching based on
classified type of the log.

Configuration
`````````````
When enabling the Kinesis Firehose module, a dedicated Delivery Stream is created for each log type.

For example, if the ``data_sources`` for a cluster named prod defined in ``conf/clusters/prod.json``
contains the following:

.. code-block:: json

  {
    "data_sources": {
      "kinesis": {
        "example_prod_streamalert": [
          "cloudwatch",
          "osquery"
        ]
      },
      "s3": {
        "example-prod-streamalert-cloudtrail": [
          "cloudtrail"
        ]
      }
    }
  }

And the following schemas are defined across one or more files in the ``conf/schemas`` directory:

.. code-block:: json

  {
    "cloudwatch:events": {
      "parser": "json",
      "schema": {"key": "type"}
    },
    "cloudwatch:flow_logs": {
      "parser": "json",
      "schema": {"key": "type"}
    },
    "osquery": {
      "parser": "json",
      "schema": {"key": "type"}
    },
    "cloudtrail": {
      "parser": "json",
      "schema": {"key": "type"}
    }
  }

The Firehose module will create four Delivery Streams, one for each type:

- ``<prefix>_streamalert_data_cloudwatch_events``
- ``<prefix>_streamalert_data_cloudwatch_flow_logs``
- ``<prefix>_streamalert_data_osquery``
- ``<prefix>_streamalert_data_cloudtrail``

Each Delivery Stream delivers data to the same S3 bucket created by the module in a prefix based on the corresponding log type:

- ``arn:aws:s3:::<prefix>-streamalert-data/cloudwatch_events/YYYY/MM/DD/data_here``
- ``arn:aws:s3:::<prefix>-streamalert-data/cloudwatch_flow_logs/YYYY/MM/DD/data_here``
- ``arn:aws:s3:::<prefix>-streamalert-data/osquery/YYYY/MM/DD/data_here``
- ``arn:aws:s3:::<prefix>-streamalert-data/cloudtrail/YYYY/MM/DD/data_here``

The following ``firehose`` configuration settings can be defined within the ``infrastructure``
section of ``global.json``:

.. code-block:: json

  {
    "infrastructure": {
      "firehose": {
        "enabled": true,
        "enabled_logs": {
          "osquery": {
            "enable_alarm": true
          },
          "cloudwatch": {},
          "ghe": {
            "enable_alarm": true,
            "evaluation_periods": 10,
            "period_seconds": 3600,
            "log_min_count_threshold": 100000
          }
        },
        "bucket_name": "<prefix>-streamalert-data",
        "buffer_size": 64,
        "buffer_interval": 300,
        "compression_format": "GZIP"
      }
    }
  }

Options
'''''''
======================  ========  ==============================  ===========
Key                     Required  Default                         Description
----------------------  --------  ------------------------------  -----------
``enabled``             ``Yes``   ``None``                        If set to ``false``, will not create a Kinesis Firehose
``bucket_name``         ``No``    ``<prefix>-streamalert-data``   Bucket name to override the default name
``enabled_logs``        ``Yes``   ``[]``                          The set of classified logs to send to Kinesis Firehose from the Classifier function
``buffer_size``         ``No``    ``64 (MB)``                     Buffer incoming data to the specified size, in megabytes, before delivering it to S3
``buffer_interval``     ``No``    ``300 (seconds)``               Buffer incoming data for the specified period of time, in seconds, before delivering it to S3
``compression_format``  ``No``    ``GZIP``                        The compression algorithm to use on data stored in S3
======================  ========  ==============================  ===========


Throughput Alarms
`````````````````
Additionally, each Firehose that is created can be configured with an alarm will fire when
incoming logs drops below a specified threshold. This is disabled by default, and enabled by
setting ``enable_alarm`` to ``true`` within the configuration for the log type. See the config
example above for how this should be performed.


Alarms Options
''''''''''''''
============================  ===============================================  ===========
Key                           Default                                          Description
----------------------------  -----------------------------------------------  -----------
``enable_alarm``              ``false``                                        If set to ``true``, a CloudWatch Metric Alarm will be created for this log type
``evaluation_periods``        ``1``                                            Consecutive periods the records count threshold must be breached before triggering an alarm
``period_seconds``            ``86400``                                        Period over which to count the IncomingRecords (default: 86400 seconds [1 day])
``log_min_count_threshold``   ``1000``                                         Alarm if IncomingRecords count drops below this value in the specified period(s)
``alarm_actions``             ``<prefix>_streamalert_monitoring SNS topic``    Optional list of CloudWatch alarm actions (e.g. SNS topic ARNs)
============================  ===============================================  ===========


Limits
~~~~~~
* `Kinesis Firehose Limits <https://docs.aws.amazon.com/firehose/latest/dev/limits.html>`_
* `Kinesis Firehose Delivery Settings <http://docs.aws.amazon.com/firehose/latest/dev/basic-deliver.html>`_


Deploying
~~~~~~~~~
Once the options above are set, deploy the infrastructure with the following commands:

.. code-block:: bash

  $ python manage.py build
  $ python manage.py deploy --function classifier


Athena Architecture
-------------------
The Athena Partition Refresh function exists to periodically refresh Athena tables, enabling the searchability of alerts and log data.

The default refresh interval is 10 minutes but can be configured by the user.


Concepts
~~~~~~~~
The Athena Partition Refresh function utilizes:

* `AWS S3 Event Notifications <http://docs.aws.amazon.com/AmazonS3/latest/dev/NotificationHowTo.html>`_
* `AWS SQS <https://aws.amazon.com/sqs/details/>`_
* `AWS Lambda Invocations by Schedule <http://docs.aws.amazon.com/lambda/latest/dg/tutorial-scheduled-events-schedule-expressions.html>`_
* `AWS Athena Repair Table <https://docs.aws.amazon.com/athena/latest/ug/msck-repair-table.html>`_


Diagram
```````
.. figure:: ../images/athena-refresh-arch.png
  :alt: StreamAlert Athena Refresh Partition Diagram
  :align: center
  :target: _images/athena-refresh-arch.png


Internals
`````````
Each time the Athena Partition Refresh Lambda function is invoked, it does the following:

* Polls the SQS queue for the latest S3 event notifications (up to 100)
* S3 event notifications contain context around any new object written to a data bucket (as configured below)
* A set of unique S3 Bucket IDs is deduplicated from the notifications
* Queries Athena to verify the ``streamalert`` database exists
* Refreshes the Athena tables for data in the relevant S3 buckets, as specified below in the list of ``buckets``
* Deletes messages off the queue once partitions are created

Configure Lambda Settings
~~~~~~~~~~~~~~~~~~~~~~~~~
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
~~~~~~~~~~
If any of the settings above are changed from the initialized defaults, the Lambda function will need to be deployed in order for them to take effect:

.. code-block:: bash

  $ python manage.py deploy --function athena

Going forward, if the deploy flag ``--function all`` is used, it will redeploy this function along with the ``rule`` function and ``alert`` function.


Monitoring
``````````
To ensure the function is operating as expected, monitor the following SQS metrics for ``<prefix>_streamalert_athena_s3_notifications``:

* ``NumberOfMessagesReceived``
* ``NumberOfMessagesSent``
* ``NumberOfMessagesDeleted``

All three of these metrics should have very close values.

If the ``NumberOfMessagesSent`` is much higher than the other two metrics, the ``schedule_expression`` should be increased in the configuration.

For high throughput production environments, an interval of 1 to 2 minutes is recommended.


Athena User Guide
-----------------

Concepts
~~~~~~~~
* `SQL <https://www.w3schools.com/sql/sql_intro.asp>`_
* `Athena Partitions <http://docs.aws.amazon.com/athena/latest/ug/partitions.html>`_


Querying Data
~~~~~~~~~~~~~
All alerts generated by StreamAlert will be sent to an ``alerts`` S3 bucket via Firehose. These will then be searchable within Athena.

To get started with querying of this data, navigate to the AWS Console, click Services, and type 'Athena'.

When the service loads, switch the ``DATABASE`` option in the dropdown to ``streamalert``:

.. figure:: ../images/athena-usage-1.png
  :alt: StreamAlert Athena Database Selection
  :align: center
  :target: _images/athena-usage-1.png

To view the schema of the ``alerts`` table, click the eye icon:

.. figure:: ../images/athena-usage-2.png
  :alt: StreamAlert Athena Alerts Schema
  :align: center
  :target: _images/athena-usage-2.

To make a query, type a SQL statement in the Query Editor, and click Run Query:

.. figure:: ../images/athena-usage-3.png
  :alt: StreamAlert Athena Run Query
  :align: center
  :target: _images/athena-usage-3.

The query shown above will show the most recent 10 alerts.


Tips
~~~~
Data is partitioned in the following format ``YYYY-MM-DD-hh-mm``.

An example is ``2017-08-01-22-00``.

To increase query performance, filter data within a specific partition or range of partitions.

With StreamAlert tables, the date partition is the ``dt`` column.

As an example, the query below counts all alerts during a given minute:

.. figure:: ../images/athena-usage-4.png
  :alt: StreamAlert Athena Run Query with Partition
  :align: center
  :target: _images/athena-usage-4.

For additional guidance on using SQL, visit the link under Concepts.

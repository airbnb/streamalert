Kinesis Firehose
================

Overview
--------

To enable historical search of all data classified by StreamAlert, Kinesis Firehose can be used.

This feature can be used for long-term data persistence and historical search.

Firehose works by delivering data to AWS S3, which can be loaded and queried by AWS Athena.

Configuration
-------------

When enabling the Kinesis Firehose module, a dedicated Delivery Stream is created per each log type.

For example, if the data_sources for a cluster named prod defined in ``conf/clusters/prod.json`` contains the following:

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

- ``arn:aws:s3:::my-data-bucket/cloudwatch_events/YYYY/MM/DD/data_here``
- ``arn:aws:s3:::my-data-bucket/cloudwatch_flow_logs/YYYY/MM/DD/data_here``
- ``arn:aws:s3:::my-data-bucket/osquery/YYYY/MM/DD/data_here``
- ``arn:aws:s3:::my-data-bucket/cloudtrail/YYYY/MM/DD/data_here``

Limits
------

* `Kinesis Firehose Limits`_
* `Kinesis Firehose Delivery Settings`_

.. _Kinesis Firehose Limits: https://docs.aws.amazon.com/firehose/latest/dev/limits.html
.. _Kinesis Firehose Delivery Settings: http://docs.aws.amazon.com/firehose/latest/dev/basic-deliver.html

Fields
------

The following Firehose configuration settings are defined in ``global.json``:

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
        "s3_bucket_suffix": "streamalert.data",
        "buffer_size": 64,
        "buffer_interval": 300,
        "compression_format": "GZIP"
      }
    }
  }

Options
~~~~~~~

======================   ========  ====================  ===========
Key                      Required  Default               Description
----------------------   --------  --------------------  -----------
``enabled``              ``Yes``   ``None``              If set to ``false``, will not create a Kinesis Firehose
``enabled_logs``         ``Yes``   ``[]``                The set of classified logs to send to Kinesis Firehose from the Classifier function
``s3_bucket_suffix``     ``No``    ``streamalert.data``  The suffix of the S3 bucket used for Kinesis Firehose data. The naming scheme is: ``prefix.suffix``
``buffer_size``          ``No``    ``64 (MB)``           The amount of buffered incoming data before delivering it to Amazon S3
``buffer_interval``      ``No``    ``300 (seconds)``     The frequency of data delivery to Amazon S3
``compression_format``   ``No``    ``GZIP``              The compression algorithm to use on data stored in S3
======================   ========  ====================  ===========

Throughput Alarms
-----------------

Additionlly, each Firehose that is created can be configured with an alarm that fires when
incoming logs drops below a specified threshold. This is disabled by default, and enabled by
setting ``enable_alarm`` to ``true`` within the configuration for the log ype. See the config
example above for how this should be performed.

Alarms Options
~~~~~~~~~~~~~~

============================  ===============================================  ===========
Key                           Default                                          Description
----------------------------  -----------------------------------------------  -----------
``enable_alarm``              ``false``                                        If set to ``true``, a CloudWatch Metric Alarm will be created for this log type
``evaluation_periods``        ``1``                                            Consecutive periods the records count threshold must be breached before triggering an alarm
``period_seconds``            ``86400``                                        Period over which to count the IncomingRecords (default: 86400 seconds [1 day])
``log_min_count_threshold``   ``1000``                                         Alarm if IncomingRecords count drops below this value in the specified period(s)
``alarm_actions``             ``<prefix>_streamalert_monitoring SNS topic``    Optional list of CloudWatch alarm actions (e.g. SNS topic ARNs)
============================  ===============================================  ===========

Deploying
---------

Once the options above are set, deploy the infrastructure with the following commands:

.. code-block:: bash

  $ python manage.py build
  $ python manage.py deploy --function classifier

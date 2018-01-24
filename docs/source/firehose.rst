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

For example, if the ``sources.json`` defines the following:

.. code-block:: json

  {
    "kinesis": {
      "example_prod_stream_alert_kinesis": {
        "logs": [
          "cloudwatch",
          "osquery"
        ]
      }
    },
    "s3": {
      "example.prod.streamalert.cloudtrail": {
        "logs": [
          "cloudtrail"
        ]
      }
    }
  }

And the following schemas are defined in ``logs.json``:

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

- ``streamalert_data_cloudwatch_events``
- ``streamalert_data_cloudwatch_flow_logs``
- ``streamalert_data_osquery``
- ``streamalert_data_cloudtrail``

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
        "enabled_logs": [
          "osquery",
          "cloudwatch",
          "ghe"
        ],
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
``enabled_logs``         ``Yes``   ``[]``                The set of classified logs to send to Kinesis Firehose from the Rule Processor
``s3_bucket_suffix``     ``No``    ``streamalert.data``  The suffix of the S3 bucket used for Kinesis Firehose data. The naming scheme is: ``prefix.suffix``
``buffer_size``          ``No``    ``64 (MB)``           The amount of buffered incoming data before delivering it to Amazon S3
``buffer_interval``      ``No``    ``300 (seconds)``     The frequency of data delivery to Amazon S3
``compression_format``   ``No``    ``GZIP``              The compression algorithm to use on data stored in S3
======================   ========  ====================  ===========

Deploying
---------

Once the options above are set, deploy the infrastructure with the following commands:

.. code-block:: bash

  $ python manage.py terraform build
  $ python manage.py lambda deploy --processor rule

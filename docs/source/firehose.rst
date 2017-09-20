Kinesis Firehose
================

Overview
--------

* To enable historical search of all data classified by StreamAlert, Kinesis Firehose can be used.
* This feature can be used for long-term data persistence and historical search (coming soon).
* This works by delivering data to Amazon S3, which can be loaded and queried by AWS Athena.

Infrastructure
--------------

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
      "...", "..."
    },
    "cloudwatch:flow_logs": {
      "parser": "json",
      "...", "..."
    },
    "osquery": {
      "parser": "json",
      "...", "..."
    },
    "cloudtrail": {
      "parser": "json",
      "...", "..."
    }
  }

The Firehose module will create four Delivery Streams, one for each type:

- ``cloudwatch_events``
- ``cloudwatch_flow_logs``
- ``osquery``
- ``cloudtrail``

Each Delivery Stream delivers data to the same S3 bucket created by the module in a prefix based on the corresponding log type:

- ``arn:aws:s3:::my-data-bucket/cloudwatch_events/YYYY/MM/DD/data``
- ``arn:aws:s3:::my-data-bucket/cloudwatch_flow_logs/YYYY/MM/DD/data``
- ``arn:aws:s3:::my-data-bucket/osquery/YYYY/MM/DD/data``
- ``arn:aws:s3:::my-data-bucket/cloudtrail/YYYY/MM/DD/data``

Limits
------

* `Kinesis Firehose Limits`_
* `Kinesis Firehose Delivery Settings`_

.. _Kinesis Firehose Limits: https://docs.aws.amazon.com/firehose/latest/dev/limits.html
.. _Kinesis Firehose Delivery Settings: http://docs.aws.amazon.com/firehose/latest/dev/basic-deliver.html

Fields
------

The following Firehose configuration settings are defined in ``global.json``:

Example:

.. code-block:: json

  {
    "infrastructure": {
      "firehose": {
        "enabled": true,
        "s3_bucket_suffix": "streamalert.data",
        "buffer_size": 5,
        "buffer_interval": 300,
        "compression_format": "Snappy"
      }
    }
  }

Options
~~~~~~~

======================   ========  ====================  ===========
Key                      Required  Default               Description
----------------------   --------  --------------------  -----------
``enabled``              ``Yes``   ``None``              If set to ``false``, will not create a Kinesis Firehose
``s3_bucket_suffix``     ``No``    ``streamalert.data``  The suffix of the S3 bucket used for Kinesis Firehose data. The naming scheme is: ``prefix.suffix``
``buffer_size``          ``No``    ``5 (MB)``            The amount of buffered incoming data before delivering it to Amazon S3
``buffer_interval``      ``No``    ``300 (seconds)``     The frequency of data delivery to Amazon S3
``compression_format``   ``No``    ``Snappy``            The compression algorithm to use on data stored in S3
======================   ========  ====================  ===========

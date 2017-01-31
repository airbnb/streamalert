S3 Events
=========

Overview
--------

* StreamAlert utilizes AWS Kinesis and S3 as datasources
* S3 can be configured to send events to AWS Lambda, which pulls and analyzes logs

Concepts
--------
* AWS S3 events `details`_

.. _details: http://docs.aws.amazon.com/AmazonS3/latest/dev/NotificationHowTo.html

Fields
------

s3_buckets
~~~~~~~~~~~~~~~

Example::

    "s3_event_buckets": {
        "main": [               # cluster name
            "my-s3-bucket"      # s3 bucket id
        ]
        ...
    },


The ``cluster name`` dictates which AWS Lambda function will process the events.

Note: You must run `./stream_alert_cli.py terraform init` after making changes here!
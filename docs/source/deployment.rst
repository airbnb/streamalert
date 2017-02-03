Deployment
==========

Make sure you've completed the `Getting Started <getting-started.html>`_ instructions prior to continuing.

Initial Build
-------------

To initialize StreamAlert:

``./stream_alert_cli.py terraform init``

This will perform the following:

* Create S3 buckets and encryption keys.
* Create all AWS Lambda functions.
* Build all declared infrastructure in the Terraform files.
* Deploy an initial production AWS Lambda version.

Type ``yes`` at each prompt

Staging Deployment
------------------

With StreamAlert, ``staging`` is first used to verify that our newly deployed rules or configurations do not throw any AWS Lambda errors prior to analyzing ``production`` data.  Alerts generated in this environment are only sent to Amazon Cloudwatch logs.

To publish all AWS Lambda functions changes to ``staging``:
``./stream_alert_cli.py lambda deploy --env 'staging' --func '*'``

To publish a specific AWS Lambda function changes to ``staging``:
``./stream_alert_cli.py lambda deploy --env 'staging' --func 'alert'``
``./stream_alert_cli.py lambda deploy --env 'staging' --func 'output'``

Production Deployment
---------------------

The ``production`` environment analyzes all traffic from both configured S3 buckets and Kinesis streams.  Alerts generated in this environment are sent to their designated output.  The `alert` AWS Lambda function is the only one which can be published to ``production``.

To publish changes to Production, run:
``./stream_alert_cli.py lambda deploy --env 'production' --func 'alert'``

Deployment
==========

Make sure you've completed the `Getting Started <getting-started.html>`_ instructions prior to continuing.

Initial Build
-------------

To initialize StreamAlert:

``$ ./stream_alert_cli.py terraform init``

This will perform the following:

* Create S3 buckets and encryption keys.
* Create all AWS Lambda functions.
* Build all declared infrastructure in the Terraform files.
* Deploy initial production AWS Lambda versions.

Type ``yes`` at each prompt.

Continuous Deployment
---------------------

As new rules, sources, or outputs are added to StreamAlert, new versions of the AWS Lambda functions must be deployed for changes to become effective.  To accomplish this, StreamAlertCLI contains a ``lambda deploy`` command.

To publish new changes for all AWS Lambda functions:
``$ ./stream_alert_cli.py lambda deploy --processor all``

Optionally, to publish changes for only a specific AWS Lambda function:
``$ ./stream_alert_cli.py lambda deploy --processor rule``
``$ ./stream_alert_cli.py lambda deploy --processor alert``

Monitoring Functions
--------------------

StreamAlert clusters contain a module which configures CloudWatch Alarms to monitor AWS Lambda invocation errors.  No errors ensures that the running code is running reliably.  To access these monitors, login to AWS Console and go to CloudWatch, and then click Alarms. 

Deployment
==========

Make sure you've completed the `Getting Started <getting-started.html>`_ instructions prior to continuing.

Initial Build
-------------

To initialize StreamAlert:

.. code-block:: bash

  $ python manage.py init

This will perform the following:

* Create S3 buckets and encryption keys.
* Create AWS Lambda functions.
* Build declared infrastructure in the Terraform files.
* Deploy initial production AWS Lambda versions.

Type ``yes`` at each prompt.

Continuous Deployment
---------------------

As new rules, sources, or outputs are added to StreamAlert, new versions of the AWS Lambda functions must be deployed for changes to become effective.

To accomplish this, ``manage.py`` contains a ``deploy`` command.

To deploy new changes for all AWS Lambda functions:

.. code-block:: bash

  $ python manage.py deploy --function all

Optionally, to deploy changes for only a specific AWS Lambda function:

.. code-block:: bash

  $ python manage.py deploy --function rule
  $ python manage.py deploy --function alert

To apply infrastructure level changes (additional Kinesis Shards, new CloudTrails, etc), run:

.. code-block:: bash

  $ python manage.py build

To speed up the Terraform run, the module name may be specified with the ``target`` parameter:

.. code-block:: bash

  $ python manage.py build --target kinesis       # tf_stream_alert_kinesis module
  $ python manage.py build --target stream_alert  # tf_stream_alert module

Monitoring Functions
--------------------

StreamAlert clusters contain a module to create CloudWatch Alarms for monitoring AWS Lambda invocation errors.

These ensure that the currently running code is reliable.  To access these monitors, login to AWS Console and go to CloudWatch, and then click Alarms.

Rollback
--------
StreamAlert Lambda functions are invoked via a ``production`` alias that can be easily rolled back
to point to the previous version:

.. code-block:: bash

  $ ./manage.py rollback --function rule
  $ ./manage.py rollback --function alert
  $ ./manage.py rollback --function all

This is helpful to quickly revert changes to Lambda functions, e.g. if a bad rule was deployed.

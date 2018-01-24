Deployment
==========

Make sure you've completed the `Getting Started <getting-started.html>`_ instructions prior to continuing.

Initial Build
-------------

To initialize StreamAlert:

.. code-block:: bash

  $ python manage.py terraform init

This will perform the following:

* Create S3 buckets and encryption keys.
* Create AWS Lambda functions.
* Build declared infrastructure in the Terraform files.
* Deploy initial production AWS Lambda versions.

Type ``yes`` at each prompt.

Continuous Deployment
---------------------

As new rules, sources, or outputs are added to StreamAlert, new versions of the AWS Lambda functions must be deployed for changes to become effective.

To accomplish this, ``manage.py`` contains a ``lambda deploy`` command.

To deploy new changes for all AWS Lambda functions:

.. code-block:: bash

  $ python manage.py lambda deploy --processor all

Optionally, to deploy changes for only a specific AWS Lambda function:

.. code-block:: bash

  $ python manage.py lambda deploy --processor rule
  $ python manage.py lambda deploy --processor alert

To apply infrastructure level changes (additional Kinesis Shards, new CloudTrails, etc), run:

.. code-block:: bash

  $ python manage.py terraform build

To speed up the Terraform run, the module name may be specified with the ``target`` parameter:

.. code-block:: bash

  $ python manage.py terraform build --target kinesis            # corresponds to the tf_stream_alert_kinesis module
  $ python manage.py terraform build --target stream_alert       # corresponds to the tf_stream_alert module

Monitoring Functions
--------------------

StreamAlert clusters contain a module to create CloudWatch Alarms for monitoring AWS Lambda invocation errors.

These ensure that the currently running code is reliable.  To access these monitors, login to AWS Console and go to CloudWatch, and then click Alarms.

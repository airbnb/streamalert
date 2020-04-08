##########
Deployment
##########

Make sure you've completed the `Getting Started <getting-started.html>`_ instructions prior to continuing.


*************
Initial Build
*************
To initialize StreamAlert:

.. code-block:: bash

  python manage.py init

This will perform the following:

* Create S3 buckets and encryption keys.
* Create AWS Lambda functions.
* Build declared infrastructure in the Terraform files.
* Deploy initial production AWS Lambda versions.

Type ``yes`` at each prompt.


*********************
Continuous Deployment
*********************
As new rules, sources, or outputs are added to StreamAlert, new versions of the AWS Lambda functions must be deployed for changes to become effective.

To accomplish this, ``manage.py`` contains a ``deploy`` command.

To deploy new changes for all AWS Lambda functions:

.. code-block:: bash

  python manage.py deploy

Optionally, to deploy changes for only a specific AWS Lambda function:

.. code-block:: bash

  python manage.py deploy --functions alert
  python manage.py deploy --functions alert_merger
  python manage.py deploy --functions apps
  python manage.py deploy --functions athena
  python manage.py deploy --functions classifier
  python manage.py deploy --functions rule
  python manage.py deploy --functions rule_promo
  python manage.py deploy --functions threat_intel_downloader

To apply infrastructure level changes (additional Kinesis Shards, new CloudTrails, etc), run:

.. code-block:: bash

  python manage.py build

To apply specific changes to speed up terraform run, use the ``list-targets`` command and the ``build`` command with the ``--target`` option:

.. code-block:: bash

  python manage.py list-targets

    Target                                                                                Type
    ----------------------------------------------------------------------------------------------
    ...
    classifier_prod_iam                                                                   module
    classifier_prod_lambda                                                                module
    cloudwatch_monitoring_prod                                                            module
    kinesis_events_prod                                                                   module
    kinesis_prod                                                                          module
    metric_filters_Classifier_FailedParses_PROD                                           module
    metric_filters_Classifier_FirehoseFailedRecords_PROD                                  module
    metric_filters_Classifier_FirehoseRecordsSent_PROD                                    module
    ...

  python manage.py build --target cloudwatch_monitoring_prod        # apply to single module
  python manage.py build --target kinesis_prod classifier_prod_iam  # apply to two modules
  python manage.py build --target metric_filters_Classifier_*_PROD  # apply to three modules


Monitoring Functions
********************
StreamAlert clusters contain a module to create CloudWatch Alarms for monitoring AWS Lambda invocation errors.

These ensure that the currently running code is reliable.  To access these monitors, login to AWS Console and go to CloudWatch, and then click Alarms.


********
Rollback
********
StreamAlert Lambda functions are invoked via a ``production`` alias that can be easily rolled back
to point to the previous version:

.. code-block:: bash

  python manage.py rollback --functions rule
  python manage.py rollback --functions alert
  python manage.py rollback

This is helpful to quickly revert changes to Lambda functions, e.g. if a bad rule was deployed.

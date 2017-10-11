Rule Testing
============

To test the accuracy of new rules, local tests can be written to verify that alerts trigger against valid input.  The ``manage.py`` CLI tool comes built-in with a ``lambda test`` command which does exactly this.

Configuration
~~~~~~~~~~~~~

To test a new rule, first create a new JSON file anywhere within ``tests/integration/rules`` named ``name_of_your_tests.json``.  This file should contain this exact structure::

  {
    "records": [
      {
        "data": {} or "",
        "description": "information about this test",
        "log": "log_type_from_logs.json",
        "service": "kinesis" or "s3" or "sns" or "stream_alert_app",
        "source": "kinesis_stream_name" or "s3_bucket_id" or "sns_topic_name" or "stream_alert_app_function_name",
        "trigger_rules": [
          "rule_01",
          "rule_02"
        ]
      }
    ]
  }

.. note:: Multiple tests can be included in one file simply by adding them to the "records" array within the `name_of_your_tests.json` file.

Rule Test Reference
-------------------

=========================  ====================  ========  ===========
Key                        Type                  Required  Description
-------------------------  --------------------  --------  -----------
``compress``               ``boolean``           No        Whether or not to compress records with ``gzip`` prior to testing. This is useful to simulate services that send gzipped data
``data``                   ``{}`` or ``string``  Yes       All ``json`` log types should be in JSON object/dict format while others (``csv, kv, syslog``) should be ``string``
``description``            ``string``            Yes       A short sentence describing the intent of the test
``log``                    ``string``            Yes       The log type this test record should parse as. The value of this should be taken from the defined logs in ``conf/logs.json``
``service``                ``string``            Yes       The name of the service which sent the log, e.g: `kinesis, s3, sns, or stream_alert_app`
``source``                 ``string``            Yes       The name of the Kinesis Stream or S3 bucket, SNS topic or StreamAlert App function where the data originated from. This value should match a source provided in ``conf/sources.json``
``trigger_rules``          ``list``              Yes       A list of zero or more rule names that this test record should trigger. An empty list implies this record should not trigger any alerts
``validate_schemas_only``  ``boolean``           No        Whether or not the test record should go through the rule processing engine. If set to ``true``, this record will only have validation performed
=========================  ====================  ========  ===========

For more examples, see the provided default rule tests in ``tests/integration/rules``

Helpers
~~~~~~~

It's often necessary to stub (dynamically fill in) values in our test data.  This could be due to time-based rules which utilize the ``last_hour`` `rule helper <rules.html#helpers>`_.  In order to test in these scenarios, a testing helper can be used.

Helpers Functions
-----------------

``last_hour``: Generates a unix epoch time within the last hour (ex: ``1489105783``).

Usage
-----

To use these helpers in rule testing, replace a specific log field value with the following::

  "<helper:helper_name_goes_here>"

For example, to replace a time based field with ``last_hour``:

.. code-block:: json

  {
    "records": [
      {
        "data": {
          "host": "app01.prod.mydomain.net",
          "time": "<helper:last_hour>"
        },
        "description": "example usage of helpers",
        "log": "host_time_log",
        "service": "kinesis",
        "source": "my_demo_kinesis_stream",
        "trigger_rules": [
          "last_hour_rule_name"
        ]
      }
    ]
  }


Validate Log Schemas
~~~~~~~~~~~~~~~~~~~~

In some cases, there may be incoming logs to StreamAlert with a known type, but without specific rules that apply to them.
However, it is best practice to write schemas for these logs and *verify* that they are valid.

This is possible by first adding the new schema(s) to ``conf/logs.json`` along with creation of test record(s) in ``tests/integration/rules/``
containing samples of real logs (without actually adding a corresponding rule). Running the ``manage.py`` script with the ``validate-schemas``
option will iterate over all json test files and attempt to classify each record.

To run schema validation on all test files:

.. code-block:: bash

  $ python manage.py validate-schemas


To run schema validation on a specific test file within ``tests/integration/rules/``:

.. code-block:: bash

  $ python manage.py validate-schemas --test-files <test_rule_file.json>

Or:

.. code-block:: bash

  $ python manage.py validate-schemas --test-files <test_rule_file>


Schema validation on two valid test files:

.. code-block:: bash

  $ python manage.py validate-schemas --test-files cloudtrail_critical_api_calls cloudtrail_put_bucket_acl.json

This will produce output similar to the following::

  cloudtrail_critical_api_calls
         [Pass]  [log='cloudtrail:events']     validation  (s3): Deleting an AWS subnet (DeleteSubnet) will create an alert.
         [Pass]  [log='cloudtrail:events']     validation  (s3): Deleting an AWS VPC (DeleteVpc) will create an alert.
         [Pass]  [log='cloudtrail:events']     validation  (s3): Updating an AWS CloudTrail trail (UpdateTrail) will create an alert.
         [Pass]  [log='cloudtrail:events']     validation  (s3): Suspending the recording of AWS API calls and log file delivery for a trail will create an alert.
         [Pass]  [log='cloudtrail:events']     validation  (s3): Deleting a database cluster (DeleteDBCluster) will create an alert.
         [Pass]  [log='cloudtrail:events']     validation  (s3): Suspending recording of resource changes through AWS Config (StopConfigurationRecorder) will create an alert.
         [Pass]  [log='cloudtrail:events']     validation  (s3): Deleting AWS network flow logs (DeleteFlowLogs) will create an alert.
         [Pass]  [log='cloudtrail:events']     validation  (s3): Describing AWS network flog logs will not create an alert.

  cloudtrail_put_bucket_acl
         [Pass]  [log='cloudwatch:events']     validation  (kinesis): An AWS S3 bucket with 'AllUsers' permission(s) will create an alert.
         [Pass]  [log='cloudwatch:events']     validation  (kinesis): An AWS S3 bucket with 'AuthenticatedUsers' permission(s) will create an alert.
         [Pass]  [log='cloudwatch:events']     validation  (kinesis): An AWS PutBucketAcl call without 'AuthenticatedUsers' & 'AllUsers' will not create an alert.


   StreamAlertCLI [INFO]: (11/11) Successful Tests
   StreamAlertCLI [INFO]: Completed


Schema validation failure on a test file containing one valid record and one invalid record:

.. code-block:: bash

  $ python manage.py validate-schemas --test-files cloudtrail_put_object_acl.json


This will produce output similar to the following::

  cloudtrail_put_object_acl
         [Pass]  [log='cloudtrail:events']     validation  (s3): CloudTrail - PutObjectAcl - True Positive
         [Fail]  [log='unknown']               validation  (s3): CloudTrail - PutObjectAcl - False Positive


  StreamAlertCLI [INFO]: (1/2) Successful Tests
  StreamAlertCLI [ERROR]: (1/2) Failures
  StreamAlertCLI [ERROR]: (1/1) [cloudtrail_put_object_acl] Data is invalid due to missing key(s) in test record: 'eventVersion'. Rule: 'cloudtrail_put_object_acl'. Description: 'CloudTrail - PutObjectAcl - False Positive'


Running Tests
~~~~~~~~~~~~~~

Tests can be run via the ``manage.py`` script. These tests include the ability to validate rules for
accuracy and alert outputs for proper configuration.

When adding new rules, it is only necessary to run tests for the **rule processor**. If making code changes to the alert
processor, such as adding a new output integration to send alerts to, tests for the **alert processor** should also be performed.

To run integration tests for the **rule processor**:

.. code-block:: bash

  $ python manage.py lambda test --processor rule

To run integration tests for the **alert processor**:

.. code-block:: bash

  $ python manage.py lambda test --processor alert

To run end-to-end integration tests for **both processors**:

.. code-block:: bash

  $ python manage.py lambda test --processor all

Integration tests can be restricted to **specific rules** to reduce time and output:

.. code-block:: bash

  $ python manage.py lambda test --processor rule --test-rules <rule_01> <rule_02>

Integration tests can be restricted to **specific file names** to reduce time and output (the .json suffix is optional):

.. code-block:: bash

  $ python manage.py lambda test --processor rule --test-files <test_file_01.json> <test_file_02>


Integration tests can send **live test alerts** to configured outputs for rules using a specified cluster.
This can also be combined with an optional list of rules to use for tests (using the ``--rules`` argument):

.. code-block:: bash

  $ python manage.py live-test --cluster <cluster_name>

Here is a sample command showing how to run tests against two rules included as integration tests in the default StreamAlert configuration:

.. code-block:: bash

  $ python manage.py lambda test --processor rule --rules cloudtrail_put_bucket_acl cloudtrail_root_account_usage

This will produce output similar to the following::

  cloudtrail_put_bucket_acl
         [Pass]  [trigger=1]                   rule      (kinesis): An AWS S3 bucket with 'AllUsers' permission(s) will create an alert.
         [Pass]  [trigger=1]                   rule      (kinesis): An AWS S3 bucket with 'AuthenticatedUsers' permission(s) will create an alert.
         [Pass]  [trigger=0]                   rule      (kinesis): An AWS PutBucketAcl call without 'AuthenticatedUsers' & 'AllUsers' will not create an alert.

  cloudtrail_root_account_usage
         [Pass]  [trigger=1]                   rule      (kinesis): Use of the AWS 'Root' account will create an alert.
         [Pass]  [trigger=0]                   rule      (kinesis): AWS 'Root' account activity initiated automatically by an AWS service on your behalf will not create an alert.



  StreamAlertCLI [INFO]: (5/5) Successful Tests
  StreamAlertCLI [INFO]: Completed

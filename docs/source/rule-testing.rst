Rule Testing
============

To test the accuracy of new rules, local tests can be written to verify that alerts trigger against valid input.  The ``manage.py`` CLI tool comes built-in with a ``lambda test`` command which does exactly this.

Configuration
~~~~~~~~~~~~~

To test a new rule, first create a new file under ``tests/integration/rules`` named ``rule_name_goes_here.json``.  This file should contain this exact structure::

  {
    "records": [
      {
        "data": {} or "",
        "description": "of the test",
        "trigger": true or false,
        "source": "kinesis_stream_name" or "s3_bucket_id" or "sns_topic_name",
        "service": "kinesis" or "s3" or "sns"
      }
    ]
  }

.. note:: Multiple tests can be included in one file simply by adding them to the "records" array within the `rule_name_goes_here.json` file.

Rule Test Reference
-------------------

=================  ====================  ========  ===========
Key                Type                  Required  Description
-----------------  --------------------  --------  -----------
``data``           ``{}`` or ``string``  Yes       All ``json`` log types should be in Map format while others (``csv, kv, syslog``) should be ``string``
``description``    ``string``            Yes       A short sentence describing the intent of the test
``trigger``        ``boolean``           Yes       Whether or not a record should produce an alert
``trigger_count``  ``integer``           No        The amount of alerts that should be generated.  Used for nested data
``source``         ``string``            Yes       The name of the Kinesis Stream or S3 bucket where the data originated from.  This value should match a source provided in ``conf/sources.json``
``service``        ``string``            Yes       The name of the AWS service which sent the log (Kinesis or S3)
``compress``       ``boolean``           No        Whether or not to compress records with ``gzip`` prior to testing
=================  ====================  ========  ===========

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
        "trigger": true,
        "source": "my_demo_kinesis_stream",
        "service": "kinesis"
      }
    ]
  }


Validating Log Schemas
~~~~~~~~~~~~~~~~~~~~~~

In some cases, there may be logs coming into StreamAlert that are of a known type, but you do not have a current need to apply rule
logic to them. However, it is still advantageous to add schemas for these logs and *test* to ensure your new schemas are valid.

This is possible through the addition of log schema(s) to ``conf/logs.json`` and creation of test record(s) in ``tests/integration/rules/``
using known samples of logs (without actually adding a corresponding rule). Running the ``manage.py`` script with the ``validate-schemas``
option will iterate over all json test files and attempt to match records within them to a defined log schema.

To simply run schema validation on all test files:

.. code-block:: bash

  $ python manage.py validate-schemas


To run schema validation on a specific test file within ``tests/integration/rules/``:

.. code-block:: bash

  $ python manage.py validate-schemas --test-files <test_rule_file.json>

Or:

.. code-block:: bash

  $ python manage.py validate-schemas --test-files <test_rule_file>


Example of running schema validation on two valid test files:

.. code-block:: bash

  $ python manage.py validate-schemas --test-files cloudtrail_critical_api_calls cloudtrail_put_bucket_acl.json

This will produce output similar to the following::

  cloudtrail_critical_api_calls
         [Pass]  [log='cloudtrail:events']     validation  (s3): CloudTrail - Critical API - DeleteSubnet
         [Pass]  [log='cloudtrail:events']     validation  (s3): CloudTrail - Critical API - DeleteVpc
         [Pass]  [log='cloudtrail:events']     validation  (s3): CloudTrail - Critical API - UpdateTrail
         [Pass]  [log='cloudtrail:events']     validation  (s3): CloudTrail - Critical API - StopLogging
         [Pass]  [log='cloudtrail:events']     validation  (s3): CloudTrail - Critical API - DeleteDBCluster
         [Pass]  [log='cloudtrail:events']     validation  (s3): CloudTrail - Critical API - StopConfigurationRecorder
         [Pass]  [log='cloudtrail:events']     validation  (s3): CloudTrail - Critical API - DeleteFlowLogs
         [Pass]  [log='cloudtrail:events']     validation  (s3): CloudTrail - Critical API - False Positive Case

  cloudtrail_put_bucket_acl
         [Pass]  [log='cloudwatch:events']     validation  (kinesis): CloudTrail - PutBucketAcl - True Positive
         [Pass]  [log='cloudwatch:events']     validation  (kinesis): CloudTrail - PutBucketAcl - False Positive



  StreamAlertCLI [INFO]: (10/10) Successful Tests
  StreamAlertCLI [INFO]: Completed


Example of running schema validation on a test file that contains one valid record and one invalid record:

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

  $ python manage.py lambda test --processor rule --rules <rule_01> <rule_02>

Integration tests can send **live test alerts** to configured outputs for rules using a specified cluster.
This can also be combined with an optional list of rules to use for tests (using the ``--rules`` argument):

.. code-block:: bash

  $ python manage.py live-test --cluster <cluster_name>

Here is a sample command showing how to run tests against two rules included as integration tests in the default StreamAlert configuration:

.. code-block:: bash

  $ python manage.py lambda test --processor rule --rules cloudtrail_put_bucket_acl cloudtrail_root_account

This will produce output similar to the following::

  cloudtrail_put_bucket_acl
  	[Pass]   [trigger=1]	rule	(kinesis): CloudTrail - PutBucketAcl - True Positive
  	[Pass]              	alert	(phantom): sending alert to 'sample_integration'
  	[Pass]              	alert	(slack): sending alert to 'sample_channel'
  	[Pass]              	alert	(aws-lambda): sending alert to 'sample_lambda'
  	[Pass]              	alert	(pagerduty): sending alert to 'sample_integration'
  	[Pass]              	alert	(aws-s3): sending alert to 'sample_bucket'
  	[Pass]   [trigger=0]	rule	(kinesis): CloudTrail - PutBucketAcl - False Positive

  cloudtrail_root_account
  	[Pass]   [trigger=1]	rule	(kinesis): CloudTrail - Root Account Usage - True Positive
  	[Pass]              	alert	(phantom): sending alert to 'sample_integration'
  	[Pass]              	alert	(slack): sending alert to 'sample_channel'
  	[Pass]              	alert	(aws-lambda): sending alert to 'sample_lambda'
  	[Pass]              	alert	(pagerduty): sending alert to 'sample_integration'
  	[Pass]              	alert	(aws-s3): sending alert to 'sample_bucket'
  	[Pass]   [trigger=0]	rule	(kinesis): CloudTrail - Root Account Usage - False Positive


  (4/4)	Rule Tests Passed
  (10/10)	Alert Tests Passed
  StreamAlertCLI [INFO]: Completed

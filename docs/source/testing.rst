#######
Testing
#######
To test the accuracy of new rules, local tests can be written to verify that alerts trigger against valid input.

The ``manage.py`` CLI tool comes built-in with a ``test`` command which does exactly this.


*************
Configuration
*************
To test a new rule, first create a new JSON file next to your rule file. The suggested convention is
to use the same name as the rule you are testing, but you can choose any name you would like. This
will help with organization, but you may also create test events to test your rules anywhere within
the same top-level directory where your rules are stored.


Basic Configuration
===================

Each test event file should contain the following structure:

.. code-block:: json

  [
    {
      "data": {
        "key_01": "value_01",
        "key_02": "value_02"
      },
      "description": "This test should trigger or not trigger an alert",
      "log": "The log name declared in a json file under the conf/schemas directory",
      "service": "The service sending the log - kinesis, s3, sns, or streamalert_app",
      "source": "The exact resource which sent the log - kinesis stream name, s3 bucket ID, SNS topic name, or streamalert_app function name",
      "trigger_rules": [
        "rule_name_that_should_trigger_for_this_event",
        "another_rule_name_that_should_trigger_for_this_event"
      ]
    }
  ]

.. note:: Multiple tests can be included in one file by adding them to the array above.


Specifying Test Data
====================

When specifying the test data, it can be either of two fields:

1. ``"data"``: An entire example record, with all necessary fields to properly classify
2. ``"override_record"``: A subset of the example record, where only relevant fields are populated

The advantage of option #2 is that the overall test event is much smaller.

The testing framework will auto-populate the records behind the scenes with the remaining fields for that given log type.

For example:

.. code-block:: json

  [
    {
      "data": {
        "account": "123456789102",
        "detail": {
          "request": {
            "eventName": "putObject",
            "bucketName": "testBucket"
          }
        },
        "detail-type": "API Call",
        "id": "123456",
        "region": "us-west-2",
        "resources": [
          "testBucket"
        ],
        "source": "aws.s3",
        "time": "Jan 01 2018 12:00",
        "version": "1.05"
      },
      "description": "An example test with a full cloudwatch event",
      "log": "cloudwatch:events",
      "service": "s3",
      "source": "test-s3-bucket-name",
      "trigger_rules": [
        "my_fake_rule"
      ]
    }
  ]

Let's say a rule is only checking the value of ``source`` in the test event.  In that case, there's no added benefit to fill in all the other data.  Here is what the event would look like with ``override_record``:

.. code-block:: json

  [
    {
      "override_record": {
        "source": "aws.s3"
      },
      "description": "An example test with a partial cloudwatch event",
      "log": "cloudwatch:events",
      "service": "s3",
      "source": "test-s3-bucket-name",
      "trigger_rules": [
        "my_fake_rule"
      ]
    }
  ]

Both test events would have the same result, but with much less effort.

.. note::

  Either ``override_record`` or ``data`` is required in the test event


Testing Classification
======================

Classification tests are always run on each test. Consider these two fields in the test configuration:

.. code-block:: json

  [
    {
      "log": "cloudwatch:events",
      "classify_only": true
    }
  ]


The ``log`` field in each test specifies the expected classified type of the test record.  The test will fail
if the classified log type differs.

By default, the test runner will continue on to test rules.  If you only wish to test classification,
specify ``classify_only`` as ``true``.


Testing Rules
=============

Assuming a test is not ``classify_only``, rules are run after classification. Consider this field in the test file:

.. code-block:: json

  [
    {
      "trigger_rules": [
        "my_first_fake_rule",
        "my_second_fake_rule"
      ]
    }
  ]

All rules are run on each set of test data.  The ``trigger_rules`` field specifies an array of rule names that should
be triggered as a result.  An empty array implies that the test data should not trigger any rules.


Publisher Tests
===============

Consider the following rule:

.. code-block:: python

  @rule(
    logs=['cloudwatch:events'],
    outputs=['slack:sample-channel'],
    publishers={'slack': my_publisher}
  )
  def my_rule(record):
    # .. something logic
    return True

To test the output of the Alert Publisher framework, you can specify ``publisher_tests``. Consider this field:

.. code-block:: json

  [
    {
      "trigger_rules": ["my_rule"],
      "publisher_tests": {
        "slack:sample-channel": [
          {
            "jmespath_expression": "path.to.record",
            "condition": "is",
            "value": 4
          },
          [ "path.to.other.record", "is", 5 ]
        ]
      }
    }
  ]

This field is a dictionary, where keys specify outputs to test. Each key's value is an array of publisher tests.
These tests compare the Alert Publisher's output to a configured expectation.

Each publisher test can be a dict with 3 keys:

- ``jmespath_expression``: A jmespath search expression. This is run on the Alert Publisher output for the given OutputDispatcher.
- ``condition``: Either "is" or "in", for equality or substring/subset matching, respectively.
- ``value``: The expected value of the field.

The field that is extract via the ``jmespath_expression`` is tested against the expected value, using the conditional.


.. note::

    An alternate shorthand syntax to the above is to specify a triple of strings:

    .. code-block:: json

      ["path.to.field", "is", "value"]


Rule Test Reference
===================
=========================  ======================  ========  ===========
Key                        Type                    Required  Description
-------------------------  ----------------------  --------  -----------
``compress``               ``boolean``             No        Whether or not to compress records with ``gzip`` prior to testing.
                                                             This is useful to simulate services that send gzipped data.
``data``                   ``map`` or ``string``   Yes*      The record to test against your rules.  All ``json`` log types
                                                             should be in JSON object/dict format while others (``csv``,
                                                             ``kv``, or ``syslog``) should be ``string``. \*This is not required
                                                             if the ``override_record`` option is used.
``override_record``        ``map``                 Yes*      A partial record to use in test events, more information below
                                                             \*This is not required if the ``data`` option is used.
``description``            ``string``              Yes       A short sentence describing the intent of the test
``log``                    ``string``              Yes       The log type this test record should parse as. The value of this
                                                             should be taken from the defined logs in one or more files in the ``conf/schemas`` directory
``service``                ``string``              Yes       The name of the service which sent the log.
                                                             This should be one of: ``kinesis``, ``s3``, ``sns``, or ``streamalert_app``.
``source``                 ``string``              Yes       The name of the Kinesis Stream or S3 bucket, SNS topic or StreamAlert App
                                                             function where the data originated from. This value should match a source
                                                             provided in the ``data_sources`` field defined within a cluster in ``conf/clusters/<cluster>.json``
``trigger_rules``          ``list``                No        A list of zero or more rule names that this test record should trigger.
                                                             An empty list implies this record should not trigger any alerts
``classify_only``          ``boolean``             No        Whether or not the test record should go through the rule processing engine.
                                                             If set to ``true``, this record will only be tested for valid classification
``publisher_tests``        ``dict``                No        This is a dict of tests to run against the Alert's published representation.
                                                             The keys of the dict are output descriptors. The values of the dict should be
                                                             arrays of individual tests. Publisher tests use jmespath to extract values from
                                                             the final publication dictionary for testing. At least one rule should be triggered,
                                                             or publisher tests will do nothing.
``test_fixtures``          ``dict``                No        Values to be mocked out for use within rules for the ``threat_intel`` and
                                                             ``lookup_tables`` features. See below for examples of this.
=========================  ======================  ========  ===========


Test Fixtures Configuration
===========================

Fixtures for tests events should be configured as part of the event itself. These should be
added within the ``threat_intel`` or ``lookup_tables`` keys under a ``test_fixtures`` section
of the test event. Usage of these two sections is outlined below.


Threat Intel Fixtures
---------------------

The below format should be used to "mock" out threat intel data to test rules that leverage this feature.

.. code-block:: json

  [
    {
      "test_fixtures": {
        "threat_intel": [
          {
            "ioc_value": "1.2.3.4",
            "ioc_type": "ip",
            "sub_type": "mal_ip"
          },
          {
            "ioc_value": "0123456789abcdef0123456789abcdef",
            "ioc_type": "md5",
            "sub_type": "mal_md5"
          }
        ]
      }
    }
  ]

Lookup Tables Fixtures
----------------------

The below format should be used to "mock" out lookup table data to test rules that leverage this feature.

.. code-block:: json

  [
    {
      "test_fixtures": {
        "lookup_tables": {
          "dynamodb-table-name": {
            "lookup_key": [
              "value_for_rule"
            ]
          }
        }
      }
    }
  ]


For more examples of how to configure tests for rules, see the provided default rules and tests in the ``rules/`` directory


*************
Running Tests
*************
Tests are run via the ``manage.py`` script. These tests include the ability to validate defined
log schemas for accuracy, as well as rules efficacy. Additionally, alerts can be sent from the local
system to a real, live alerting output (if configured).

The below options are available for running tests. Please note that each subsequent test command
here includes all of the prior tests. For instance, the ``rules`` command will also test everything
that the ``classifier`` command tests. See the `Test Options`_ section for available options for
all of these commands.


Classifier Tests
================
Running tests to ensure test events classify properly:

.. code-block:: bash

  python manage.py test classifier

.. note:: The ``classifier`` test command does not test the efficacy of rules, and simply ensures
  defined test events classify as their expected schema type.


Rule Tests
==========
Running tests to ensure test events classify properly **and** trigger the designated rules:

.. code-block:: bash

  python manage.py test rules


Live Tests
==========
Running tests to actually send alerts to a rule's configured outputs:

.. code-block:: bash

  python manage.py test live

.. note:: The ``live`` test command does **not** invoke any deployed Lambda functions, and only
  uses the local code, test events, and rules. However, authentication secrets needed to send alerts
  are in fact read from S3 during this process, so AWS credentials must still be set up properly.


Test Options
============
Any of the test commands above can be restricted to **specific files** to reduce time and output:

.. code-block:: bash

  python manage.py test classifier --test-files <test_file_01.json> <test_file_02>

.. note:: Only the name of the file is required, with or without the file extension, not the entire path.

Tests can also be restricted to **specific rules**:

.. code-block:: bash

  python manage.py test rules --test-rules <rule_01> <rule_02>

.. note:: Note that this is the name of the rule(s) themselves, not the name of the Python file containing the rule(s).

Tests can be directed to run against an alternative directory of test event files:

.. code-block:: bash

  python manage.py test rules --files-dir /path/to/alternate/test/files/directory

.. note:: Note that this is the name of the rule(s) themselves, not the name of the Python file containing the rule(s).


Test Examples
=============
Here is a sample command showing how to run tests against two test event files included in the default StreamAlert configuration:

.. code-block:: bash

  python manage.py test rules --test-files rules/community/cloudwatch_events/cloudtrail_put_bucket_acl.json rules/community/cloudwatch_events/cloudtrail_root_account_usage.json

This will produce output similar to the following::

  Running tests for files found in: rules

  File: rules/community/cloudwatch_events/cloudtrail_put_bucket_acl.json

  Test #01: Pass
  Test #02: Pass

  File: rules/community/cloudwatch_events/cloudtrail_root_account_usage.json

  Test #01: Pass
  Test #02: Pass

  Summary:

  Total Tests: 4
  Pass: 4
  Fail: 0

To see more verbose output for any of the test commands, add the ``--verbose`` flag. The previous
command, with the addition of the ``--verbose`` flag, produces the following output::

  Running tests for files found in: rules

  File: rules/community/cloudwatch_events/cloudtrail_put_bucket_acl.json

  Test #01:

      Description: Modifying an S3 bucket to have a bucket ACL of AllUsers or AuthenticatedUsers should create an alert.

      Classification: Pass
          Classified Type: cloudwatch:events
          Expected Type: cloudwatch:events

      Rules: Pass
          Triggered Rules: cloudtrail_put_bucket_acl
          Expected Rules: cloudtrail_put_bucket_acl

  Test #02:

      Description: Modifying an S3 bucket ACL without use of AllUsers or AuthenticatedUsers should not create an alert.

      Classification: Pass
          Classified Type: cloudwatch:events
          Expected Type: cloudwatch:events

      Rules: Pass
          Triggered Rules: <None>
          Expected Rules: <None>


  File: rules/community/cloudwatch_events/cloudtrail_root_account_usage.json

  Test #01:

      Description: Use of the AWS 'Root' account will create an alert.

      Classification: Pass
          Classified Type: cloudwatch:events
          Expected Type: cloudwatch:events

      Rules: Pass
          Triggered Rules: cloudtrail_root_account_usage
          Expected Rules: cloudtrail_root_account_usage

  Test #02:

      Description: AWS 'Root' account activity initiated automatically by an AWS service on your behalf will not create an alert.

      Classification: Pass
          Classified Type: cloudwatch:events
          Expected Type: cloudwatch:events

      Rules: Pass
          Triggered Rules: <None>
          Expected Rules: <None>


  Summary:

  Total Tests: 4
  Pass: 4
  Fail: 0


Additionally, any given test that results in a status of **Fail** will, by default, print verbosely.
In the below example, the ``cloudtrail_put_bucket_acl.json`` file has been altered to include a triggering
rule that does not actually exist.

.. code-block:: bash

  python manage.py test rules --test-files rules/community/cloudwatch_events/cloudtrail_put_bucket_acl.json rules/community/cloudwatch_events/cloudtrail_root_account_usage.json

::

  Running tests for files found in: rules

  File: rules/community/cloudwatch_events/cloudtrail_put_bucket_acl.json

  Test #01:

      Description: Modifying an S3 bucket to have a bucket ACL of AllUsers or AuthenticatedUsers should create an alert.

      Classification: Pass
          Classified Type: cloudwatch:events
          Expected Type: cloudwatch:events

      Rules: Fail
          Triggered Rules: cloudtrail_put_bucket_acl
          Expected Rules: cloudtrail_put_bucket_acl, nonexistent_rule (does not exist)

  Test #02: Pass

  File: rules/community/cloudwatch_events/cloudtrail_root_account_usage.json

  Test #01: Pass
  Test #02: Pass

  Summary:

  Total Tests: 4
  Pass: 3
  Fail: 1


*******
Helpers
*******
It may occasionally be necessary to dynamically fill in values in the test event data. For instance, if a
rule relies on the time of an event, the ``last_hour`` helper can be embedded in a test event as a key's value.
The embedded helper string will be replaced with the value returned by the helper function.


Available Helpers
=================
``last_hour``: Generates a unix epoch time within the last hour (ex: ``1489105783``).


Usage
=====
To use these helpers in rule testing, replace a specific log field value with the following::

  "<helper:helper_name_goes_here>"

For example, to replace a time field with a value in the last hour, use ``last_hour``:

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

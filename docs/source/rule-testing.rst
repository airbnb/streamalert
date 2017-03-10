Rule Testing
============

In order to test the effectiveness of new rules, local integration tests can be used to verify that alerts would be triggered given a certain input.  The ``stream_alert_cli.py`` command line tool comes built-in with a ``lambda test`` command which does exactly this.

Configuration
~~~~~~~~~~~~~

To test a new rule, first create a new file under ``test/integration/rules`` named ``rule_name_goes_here.json``.  This file should contain this exact structure::
  
  {
    "records": [
      {
        "data": {} or "",
        "description": "of the test",
        "trigger": true or false,
        "source": "kinesis_stream_name" or "s3_bucket_id",
        "service": "kinesis" or "s3"
      }
    ]
  }

The ``data`` key can either be a Map or a String.  Normally all json types should be in Map format while others should be String (``csv, kv, syslog``).

The ``description`` key should be a short sentence describing the intent of the test.

The ``trigger`` key indicates whether or not this record should produce an alert or not.  This is used to determine that all of our test records produce the correct amount of alerts.

The ``source`` key is the name of the kinesis stream or s3 bucket.

The ``service`` key is the name of the AWS service which sent the alert (kinesis or s3).

For more examples, see the default rule tests in ``test/integration/rules``.

Helpers
~~~~~~~

It is often necessary to stub out (dynamically fill in) certain values in our test data.  This could be due to time-based rules which utilize the ``last_hour`` `rule helper <rules.html#helpers>`_.  In order to test in these scenarios, a testing helper can be used.

All Helpers
-----------

``last_hour``: Generates a unix epoch time within the last hour (ex: ``1489105783``).

Usage
-----

To use these helpers in integration test data, replace a specific field with the following syntax::
  
  "<helper:helper_name_goes_here>"

For example, to replace a time based field with ``last_hour``::

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

Running Tests - Kinesis
~~~~~~~~~~~~~~~~~~~~~~~

To run integration tests::

  $ ./stream_alert_cli.py lambda test --func alert --source kinesis

This will produce the following output::

  invalid_subnet
  	test: user logging in from an untrusted subnet       [Pass]
  	test: user logging in from the trusted subnet        [Pass]

  invalid_user
  	test: user not in the whitelist                      [Pass]
  	test: user in the whitelist                          [Pass]

  sample_csv_rule
  	test: host is test-host-2                            [Pass]

  sample_json_rule
  	test: host is test-host-1                            [Pass]

  sample_kv_rule
  	test: fatal message from uid 100                     [Pass]

  sample_syslog_rule
  	test: sudo command ran                               [Pass]

Running Tests - S3
~~~~~~~~~~~~~~~~~~

.. note:: coming soon - Amazon S3 testing instructions

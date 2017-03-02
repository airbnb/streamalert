Rules
=====

* Rules encompass data analysis and alerting logic
* Rules are written in native Python, not a proprietary language
* A Rule can utilize any Python function or library
* A Rule can be run against multiple log sources if desired
* Rules can be isolated into defined environments/clusters
* Rule alerts can be sent to one or more outputs, like S3, PagerDuty or Slack
* Rules can be unit tested and integration tested

Getting Started
---------------

* Rules are located in the ``rules/`` sub-directory.
* We suggest a separate rule file is created for each cluster defined in the ``variables.json`` file.
* Examples: ``corp.py``, ``pci.py``, or ``production.py``
* This structure is optional, you can organize rules however you like.

All rule files must be explicitly imported in ``main.py``.

Example::

  from rules import (
      corp,
      pci,
      production
  )

.. note:: If you skip the step above, your rules will not be load into StreamAlert.

Overview
--------

Each Rule file must contain the following at the top::

  from stream_alert import rule_helpers
  from stream_alert.rules_engine import StreamRules

  rule = StreamRules.rule

All rules take this structure::

    @rule(logs=[...],
          matchers=[...],
          outputs=[...])
    def example(record):          # the rule name will be 'example'
        # code                    # analyze the incoming record w/ your logic
        return True               # return True if an alert should be sent

You define a list of ``logs`` that the rule is applicable to.  Rules will only be evaluated against incoming records that match the declared log types.

Example
-------

Here’s an example that alerts on the use of sudo in a PCI environment::

    from fnmatch import fnmatch

    @rule(logs=['osquery'],                           # applicable datasource(s)
          matchers=['pci'],                           # matcher(s) to evaluate
          outputs=['s3', 'pagerduty', 'slack'])       # where to send alerts
    def production_sudo(record):                      # incoming record/log
        table_name = record['name']
        tag = record['columns']['tag']

        return (
          table_name == 'linux_syslog_auth' and
          fnmatch(tag, 'sudo*')
        )

You have the flexibility to perform simple or complex data analysis

Parameter Details
-----------------

logs
~~~~~~~~~~~

``logs`` define the log sources the rule supports; the ``def`` function block is not run unless this condition is satisfied.

* A rule can be run against multiple log sources if desired.
* Log sources (e.g. datasources) are defined in ``conf/sources.json`` and subsequent schemas are defined in ``conf/logs.json``. For more details on how to setup a datasource, please see the Datasources section.

matchers
~~~~~~~~

``matchers`` is optional; it defines conditions that must be satisfied in order for the rule to be evaluated.  This serves two purposes:

* To extract common logic from rules, which improves readability and writability
* To ensure necessary conditions are met before full analysis of an incoming record

Matchers are defined in ``rules/matchers.py``. If desired, matchers can also be defined in rule files if the following line is added to the top::

  matcher = StreamRules.matcher

In the above example, we are evaluating the ``pci`` matcher.  As you can likely deduce, this ensures alerts are only triggered if the incoming record is from the ``pci`` environment. This is achieved by looking for a particular field in the log. The code::

    @matcher()
    def pci(record):
        return record['decorations']['envIdentifier'] == 'pci'


outputs
~~~~~~~

``outputs`` define where the alert should be sent to, if the return value of the rule is ``True``.

StreamAlert supports sending alerts to PagerDuty, Slack and Amazon S3. As demonstrated in the example, an alert can be sent to multiple destinations.

req_subkeys
~~~~~~~~~~~

``req_subkeys`` is optional; it defines the required sub-keys that must exist in the incoming record in order for the rule to be evaluated.

This feature should be avoided, but it is useful if you defined a loose schema to trade flexibility for safety; see `Schemas <conf-schemas.html#json-example-osquery>`_.

Examples::

  @rule(logs=['osquery'],
        outputs=['pagerduty', 's3'],
        req_subkeys={'columns':['address', 'hostnames']})
        ...

  @rule(logs=['osquery'],
        outputs=['pagerduty', 's3'],
        req_subkeys={'columns':['port', 'protocol']})
        ...


Helpers
-------
To improve readability and writability of rules, you can extract commonly used ``Python`` processing logic into custom helper methods.   These helpers are defined in ``rules/helpers/base.py`` and can be called from within a matcher or rule.

Example function::

    def in_set(data, whitelist):
        """Checks if some data exists in any elements of a whitelist.

        Args:
            data: element in list
            whitelist: list/set to search in

        Returns:
            True/False
        """
        return any(fnmatch(data, x) for x in whitelist)

Example use of that function within a rule::

    @rule(...)
    def foobar(record):
        user = 'joe'
        user_whitelist = { 'mike', 'jin', 'jack', 'mary' }

        return in_set(user, user_whitelist)


Rules Testing
-------------

In order to test the effectiveness of new rules, local integration tests can be ran to verify that alerts would be triggered given a certain input.  The `stream_alert_cli.py` command line tool comes built-in with a `lambda test` command which does exactly this.

Configuration
~~~~~~~~~~~~~

To test a new rule, first create a new file under `test/integration/rules` named `rule_name_goes_here.json`.  This file should contain this exact structure::
  
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

The `data` key can either be a Map or a String.  Normally all json types should be in Map format while others should be String (csv, kv, syslog).

The `description` key should be a short sentence describing the intent of the test.

The `trigger` key indicates whether or not this record should produce an alert or not.  This is used to determine that all of our test records produce the correct amount of alerts.

The `source` key is the name of the kinesis stream or s3 bucket.

The `service` key is the name of the AWS service which sent the alert (kinesis or s3).

For more examples, see the default rule tests in `test/integration/rules`.

Running Tests - Kinesis
~~~~~~~~~~~~~~~~~~~~~~~

To run integration tests::

  ./stream_alert_cli.py lambda test --func alert --source kinesis

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

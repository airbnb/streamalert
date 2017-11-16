Rules
=====

* Rules contain data analysis and alerting logic
* Rules are written in native Python, not a proprietary language
* A Rule can utilize any Python function or library
* A Rule can be run against multiple log sources if desired
* Rules can be isolated into defined environments/clusters
* Rule alerts can be sent to one or more outputs, like S3, PagerDuty or Slack
* Rules can be unit and integration tested

Getting Started
---------------

All rules are located in the ``rules/`` directory.

Within this directory are two folders: ``community/`` and ``default/``.

``community/`` rules are publicly shared from StreamAlert contributors.

``default/`` can be used as a generic container for rules files.

You may create any folder structure desired, as all rules folders are imported recursively. Here are some examples:

* ``rules/intrusion-detection/malware.py``
* ``rules/compliance/pci.py``
* ``rules/default/infrastructure.py``

.. note:: If you create additional folders within the ``rules`` directory, be sure to include a blank ``__init__.py`` file.

Overview
--------

Each Rule file must contain the following at the top:

.. code-block:: python

  from stream_alert.rule_processor.rules_engine import StreamRules
  rule = StreamRules.rule

All rules take this structure:

.. code-block:: python

    @rule(logs=[...],
          matchers=[...],
          outputs=[...])
    def example(record):          # the rule name will be 'example'
        # code                    # analyze the incoming record w/ your logic
        return True               # return True if an alert should be sent

You define a list of ``logs`` that the rule is applicable to.

Rules will only be evaluated against incoming records that match the declared log types found in ``conf/logs.json``.


Example
-------

Here’s an example rule that alerts on the use of sudo in a PCI environment:

.. code-block:: python

    from fnmatch import fnmatch

    @rule(logs=['osquery:differential'],              # applicable datasource(s)
          matchers=['pci'],                           # matcher(s) to evaluate
          outputs=['pagerduty:cirt', 'slack:cirt'])   # where to send alerts
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
~~~~

``logs`` define the log sources the rule supports; The ``def`` function block is not run unless this condition is satisfied. Your rule(s) must define at least one log source.

A rule can be run against multiple log sources if desired.

Log sources are defined in ``conf/sources.json`` and subsequent schemas are defined in ``conf/logs.json``

For more details on how to setup a datasource, please see `Datasources <conf-datasources.html>`_

matchers
~~~~~~~~

``matchers`` is an optional field; It defines conditions that must be satisfied in order for the rule to be evaluated.  This serves two purposes:

* To extract common logic from rules, which improves readability and writability
* To ensure necessary conditions are met before full analysis of an incoming record

Matchers are normally defined in ``rules/matchers.py``. If desired, matchers can also be defined in rule files if the following line is added to the top:

.. code-block:: python

  matcher = StreamRules.matcher()

In the above example, we are evaluating the ``pci`` matcher.  As you can likely deduce, this ensures alerts are only triggered if the incoming record is from the ``pci`` environment.

This is achieved by looking for a particular field in the log. The code:

.. code-block:: python

    @matcher
    def pci(record):
        return record['decorations']['envIdentifier'] == 'pci'


outputs
~~~~~~~

``outputs`` define where the alert should be sent to if the return value of a rule is ``True``. Your rule(s) must define at least one output.

StreamAlert supports sending alerts to PagerDuty, Slack, Amazon S3 and Phantom.

An alert can be sent to multiple destinations.

req_subkeys
~~~~~~~~~~~

``req_subkeys`` is an optional argument which defines required sub-keys that must exist in the incoming record in order for it to be evaluated.

This feature should be avoided, but it is useful if you defined a loose schema to trade flexibility for safety; see `Schemas <conf-schemas.html#json-example-osquery>`_.

Examples:

.. code-block:: python

  # The 'columns' key must contain
  # sub-keys of 'address' and 'hostnames'

  @rule(logs=['osquery:differential'],
        outputs=['pagerduty', 'aws-s3'],
        req_subkeys={'columns':['address', 'hostnames']})
        ...

  # The 'columns' key must contain
  # sub-keys of 'port' and 'protocol'

  @rule(logs=['osquery:differential'],
        outputs=['pagerduty', 'aws-s3'],
        req_subkeys={'columns':['port', 'protocol']})
        ...

context
~~~~~~~~~~~

``context`` is an optional field to pass extra instructions to the alert processor on how to route the alert. It can be particulary helpful to pass data to an output.

Example:

.. code-block:: python

  # Context provided to the pagerduty-incident output
  # with instructions to assign the incident to a user.

  @rule(logs=['osquery:differential'],
        outputs=['pagerduty', 'aws-s3'],
        context={'pagerduty-incident':{'assigned_user': 'valid_user'}})
        ...


Helpers
-------
To improve readability and writability of rules, you can extract commonly used ``Python`` logic into custom helper methods.

These helpers are defined in ``helpers/base.py`` and can be called from within a matcher or rule.

Example function:

.. code-block:: python

    # helpers/base.py

    def in_set(data, whitelist):
        """Checks if some data exists in any elements of a whitelist.

        Args:
            data: element in list
            whitelist: list/set to search in

        Returns:
            True/False
        """
        return any(fnmatch(data, x) for x in whitelist)

Example usage of the function above in a rule:

.. code-block:: python

    # rules/default/prod.py

    from helpers.base import in_set

    @rule(logs=['example'],
          outputs=['slack'])
    def example_rule(record):
        user = record['user']
        user_whitelist = {
          'mike',
          'jin',
          'jack',
          'mary'
        }

        return in_set(user, user_whitelist)


Disabling Rules
---------------

In the event that a rule must be temporarily disabled, due to either poor fidelity or any other reason, the ``@disable`` decorator can be used.

This allows you to keep the rule definition and tests in place, instead of having to remove them entirely.

In the following example, ``@disable`` prevents the first rule from analyzing incoming records:

.. code-block:: python

  # the decorator must be imported, similar to @rule and @matcher
  disable = StreamRules.disable()

  @disable
  @rule(logs=['example'],
        outputs=['slack'])
  def example_rule(record):
      host = record['host']

    return host == 'jump-server-1.network.com'


  @rule(logs=['example'],
        outputs=['slack'])
  def example_rule(record):
      user = record['user']
      user_whitelist = {
        'mike',
        'jin',
        'jack',
        'mary'
      }

      return in_set(user, user_whitelist)


Testing
-------

For instructions on how to create and run tests to validate rules, see `Rule Testing <rule-testing.html>`_.

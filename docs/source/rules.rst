#####
Rules
#####
* Rules contain data analysis and alerting logic
* Rules are written in native Python, not a proprietary language
* A Rule can utilize any Python function or library
* A Rule can be run against multiple log sources if desired
* Rules can be isolated into defined environments/clusters
* Rule alerts can be sent to one or more outputs, like S3, PagerDuty or Slack
* Rules can be unit and integration tested


***************
Getting Started
***************
All rules are located in the ``rules/`` directory.

Within this directory are two folders: ``community/`` and ``default/``.

``community/`` rules are publicly shared from StreamAlert contributors.

``default/`` can be used as a generic container for rules files.

You may create any folder structure desired, as all rules folders are imported recursively. Here are some examples:

* ``rules/intrusion-detection/malware.py``
* ``rules/compliance/pci.py``
* ``rules/default/infrastructure.py``

.. note:: If you create additional folders within the ``rules`` directory, be sure to include a blank ``__init__.py`` file.


********
Overview
********
A StreamAlert rule is a Python method that takes a parsed log record (dictionary) and returns True or False.
A return value of ``True`` means an alert will be generated.


Example: The Basics
===================
The simplest possible rule looks like this:

.. code-block:: python

  from streamalert.shared.rule import rule

  @rule(logs=['cloudwatch:events'])
  def all_cloudwatch_events(record):
      """Minimal StreamAlert rule: alert on all CloudWatch events"""
      return True

This rule will be evaluated against all inbound logs that match the ``cloudwatch:events`` schema defined in a schema file in the ``conf/schemas`` directory, i.e ``conf/schemas/cloudwatch.json``.
In this case, *all* CloudWatch events will generate an alert, which will be sent to the `alerts Athena table <historical-search.html#alerts-search>`_.


Example: Logic & Outputs
========================
Let's modify the rule to page the security team if anyone ever uses AWS root credentials:

.. code-block:: python

  from streamalert.shared.rule import rule

  @rule(logs=['cloudwatch:events'], outputs=['pagerduty:csirt', 'slack:security'])
  def cloudtrail_root_account_usage(record):
      """Page security team for any usage of AWS root account"""
        return (record['detail']['userIdentity']['type'] == 'Root'
                and record['detail']['userIdentity'].get('invokedBy') is None
                and record['detail']['eventType'] != 'AwsServiceEvent')

Now, any AWS root account usage is reported to PagerDuty, Slack, and the aforementioned Athena table.
In order for this to work, your `datasources <config-clusters.html#datasource-configuration>`_ and
`outputs <outputs.html>`_ must be configured so that:

* CloudTrail logs are being sent to StreamAlert via CloudWatch events
* The ``pagerduty:csirt`` and ``slack:security`` outputs have the proper credentials


.. _advanced_example:

Example: More Rule Options
==========================
The previous example suffers from the following problems:

* It only works for CloudTrail data sent via CloudWatch
* A single legitimate root login may generate hundreds of alerts in the span of a few minutes
* There is no distinction between different AWS account IDs

We can generalize the rule to alleviate these issues:

.. code-block:: python

  from rules.helpers.base import get_first_key  # Find first key recursively in record
  from streamalert.shared.rule import rule

  # This could alternatively be defined in matchers/matchers.py to be shareable
  _PROD_ACCOUNTS = {'111111111111', '222222222222'}

  def prod_account(record):
      """Match logs for one of the production AWS accounts"""
      return (
          record.get('account') in _PROD_ACCOUNTS or
          get_first_key(record, 'userIdentity', {}).get('accountId') in _PROD_ACCOUNTS
      )

  @rule(
      logs=['cloudtrail:events', 'cloudwatch:events'],  # Rule applies to these 2 schemas
      matchers=[prod_account],  # Must be satisfied before rule is evaluated
      merge_by_keys=['useragent'],  # Merge alerts with the same 'useragent' key-value pair
      merge_window_mins=5,  # Merge alerts every 5 minutes
      outputs=['pagerduty:csirt', 'slack:security']  # Send alerts to these 2 outputs
  )
  def cloudtrail_root_account_usage(record):
      """Page security team for any usage of AWS root account"""
      return (
          get_first_key(record, 'userIdentity', {}).get('type') == 'Root' and
          not get_first_key(record, 'invokedBy') and
          get_first_key(record, 'eventType') != 'AwsServiceEvent'
      )

To simplify rule logic, you can extract common routines into custom helper methods.
These helpers are defined in ``rules/helpers/base.py`` and can be called from within a matcher or rule (as shown here).

Since rules are written in Python, you can make them as sophisticated as you want!


************
Rule Options
************
The following table provides an overview of each rule option, with more details below:

=====================  ========================  ===============
**@rule kwarg**        **Type**                  **Description**
---------------------  ------------------------  ---------------
``context``            ``Dict[str, Any]``        Dynamically configurable context passed to the alert processor
``datatypes``          ``List[str]``             List of normalized type names the rule applies to
``logs``               ``List[str]``             List of log schemas the rule applies to
``matchers``           ``List[str]``             Matcher pre-conditions which must be met before rule logic runs
``merge_by_keys``      ``List[str]``             List of key names that must match in value before merging alerts
``merge_window_mins``  ``int``                   Merge related alerts at this interval rather than sending immediately
``outputs``            ``List[str]``             List of alert outputs
``dynamic_outputs``    ``List[function]``        List of functions which return valid outputs
``req_subkeys``        ``Dict[str, List[str]]``  Subkeys which must be present in the record
=====================  ========================  ===============


:context:

  ``context`` can pass extra instructions to the alert processor for more precise routing:

  .. code-block:: python

    # Context provided to the pagerduty-incident output with
    # instructions to assign the incident to a user.

    @rule(logs=['osquery:differential'],
          outputs=['pagerduty:csirt'],
          context={'pagerduty-incident': {'assigned_user': 'valid_user'}})
    def my_rule(record, context):
        context['pagerduty-incident']['assigned_user'] = record['username']
        return True

:datatypes:

  ``conf/normalized_types.json`` defines data normalization, whereby you can write rules against a common type instead of a specific field or schema:

  .. code-block:: python

    """These rules apply to several different log types, defined in conf/normalized_types.json"""
    from streamalert.shared.rule import rule
    from streamalert.shared.normalize import Normalizer

    @rule(datatypes=['sourceAddress'], outputs=['aws-sns:my-topic'])
    def ip_watchlist_hit(record):
        """Source IP address matches watchlist."""
        return '127.0.0.1' in Normalizer.get_values_for_normalized_type(record, 'sourceAddress')

    @rule(datatypes=['command'], outputs=['aws-sns:my-topic'])
    def command_etc_shadow(record):
        """Command line arguments include /etc/shadow"""
        return any(
            '/etc/shadow' in cmd.lower()
            for cmd in Normalizer.get_values_for_normalized_type(record, 'command')
        )

:logs:

  ``logs`` define the log schema(s) supported by the rule.

  Log `datasources <config-clusters.html#datasource-configuration>`_ are defined within the
  ``data_sources`` field of a cluster such as ``conf/clusters/<cluster>.json`` and their
  `schemas <config-schemas.html>`_ are defined in one or more files in the ``conf/schemas`` directory.

  .. note::

    Either ``logs`` or ``datatypes`` must be specified for each rule

:matchers:

  ``matchers`` define conditions that must be satisfied in order for the rule to be evaluated.
  Default matchers are defined in ``matchers/matchers.py`` but can also be defined
  in the rules file (see :ref:`example above <advanced_example>`).

  A matcher function should accept a single argument, just like rules. That argument will be the
  record that is being evaluated by the rule.

  Rules can utilize matchers to reduce redundancy of code, allowing you to define the logic once
  and easily use it across multiple rules.

:merge_by_keys \/ merge_window_mins:

  .. note:: Specify neither or both of these fields, not one of them in isolation

  For a better alert triage experience, you can merge alerts whose records share one or more fields in common:

  .. code-block:: python

    @rule(logs=['your-schema'],
          merge_by_keys=['alpha', 'beta', 'gamma'],
          merge_window_mins=5):
    def merged_rule(record):
        return True

  The alert merger Lambda function will buffer all of these alerts until 5 minutes have elapsed,
  at which point

  .. code-block:: json

    {
      "alpha": "A",
      "nested": {
        "beta": "B"
      },
      "gamma": [1, 2, 3],
      "timestamp": 123
    }

  would be automatically merged with

  .. code-block:: json

    {
      "alpha": "A",
      "nested": {
        "beta": "B",
        "extra": "field"
      },
      "gamma": [1, 2, 3],
      "timestamp": 456
    }

  A single consolidated alert will be sent showing the common keys and the record differences.
  *All* of the specified merge keys must have the same value in order for two records to be merged,
  but those keys can be nested anywhere in the record structure.

  .. note::

    The original (unmerged) alert will always be sent to `Athena <historical-search.html#alerts-search>`_.

:dynamic_outputs:

  The ``dynamic_outputs`` keyword argument defines additional `outputs <outputs.html>`_ to an Alert which are dynamically generated.
  See `dynamic_outputs <dynamic-outputs.html>`_ for more info

:outputs:

  The ``outputs`` keyword argument defines the alert destination if the return value of a rule is ``True``.
  Alerts are always sent to an :ref:`Athena alerts table <alerts_search>` which is easy to query.
  Any number of additional `outputs <outputs.html>`_ can be specified.

:req_subkeys:

  ``req_subkeys`` defines sub-keys that must exist in the incoming record (with a non-zero value) in order for it to be evaluated.

  This feature should be used if you have logs with a loose schema defined in order to avoid raising a ``KeyError`` in rules.

  .. code-block:: python

    # The 'columns' key must contain sub-keys of 'address' and 'hostnames'

    @rule(logs=['osquery:differential'],
          outputs=['aws-lambda:my-function'],
          req_subkeys={'columns':['address', 'hostnames']})
    def osquery_host_check(rec):
        # If all logs did not have the 'address' sub-key, this rule would
        # throw a KeyError.  Using req_subkeys avoids this.
        return rec['columns']['address'] == '127.0.0.1'


***************
Disabling Rules
***************
In the event that a rule must be temporarily disabled, the ``@disable`` decorator can be used.
This allows you to keep the rule definition and tests in place instead of having to remove them entirely:

.. code-block:: python

  from streamalert.shared.rule import disable, rule

  @disable  # TODO: this rule is too noisy!
  @rule(logs=['example'], outputs=['slack'])
  def example_rule(record):
      return True


*******
Testing
*******
For instructions on how to create and run tests to validate rules, see `Testing <testing.html>`_.

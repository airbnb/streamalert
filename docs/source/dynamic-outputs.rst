###############
Dynamic Outputs
###############


*************
Prerequisites
*************

* Any output assigned must be added with ``python manage.py output``
* ``functions`` must return ``None``, ``str`` or ``List[str]`` which maps to an output configured with the above.
* Only pass ``context`` if the ``rule`` sets context.


********
Overview
********

Adds the ability to have custom logic run to define an ``output`` or ``outputs`` based on information within the ``record``.
For information on supported outputs and how to add support for additional outputs, see `outputs`_

As can be seen by the examples below, they are easy to configure, but add a very useful feature to StreamAlert. 

- StreamAlert sends to all outputs defined within a rules ``outputs=[]`` and ``dynamic_outputs=[]`` when sending ``Alerts``.
- It is also possible to pass ``context`` to the ``dynamic_function`` if the ``rule`` sets it.

.. note::
  Any ``output`` passed must be configured with ``./manage.py output -h``


Example: Simple
===============

The below code block is considered a simple ``dynamic_output`` function, because the outputs are dynamically configured, but the information used still lives within the code. It also:

 - allows you to maintain a static list of information inside your code
 - will return the outputs relevant to the team who "own" the account
 - ``Alerts`` are sent to the ``aws-sns:security`` output aswell as those returned by the function

.. code-block:: python

  from streamalert.shared.rule import rule

  def map_account_to_team(record):
      teams = {
        "team_a": {"accounts": ["123", "456", ...], "outputs": ["aws-sns:team_a"]},
        "team_b": {"accounts": ["789", ...], "outputs": ["aws-sns:team_b", "slack:team_b"]},
      }

      account_id = record.get('recipientaccountid')

      for team in teams:
          if account_id in team["accounts"]:
              return team["outputs"]
      # None is guarded against by StreamAlert

  @rule(
    logs=['cloudwatch:events'],
    req_subkeys={
      'detail': ['userIdentity', 'eventType']
    },
    outputs=["aws-sns:security"],
    dynamic_outputs=[map_account_to_team]
  )
  def cloudtrail_root_account_usage(rec):
    # Rule logic


Example: With LookupTables
==========================

With the simple addition of a `lookup-table`_ you can take a rule like ``cloudtrail_root_account_usage`` and configure it as such:

.. code-block:: python

  from streamalert.shared.rule import rule
  from streamalert.shared.lookup_tables.core import LookupTables

  def dynamic_output_with_context(record, context): # pass context only if the rule added context
      account_id = context["account_id"]
 
      return LookupTables.get(
        'my_lookup_table',
        'aws-account-owner:{}'.format(account_id), 
        None
      ) # potentially returns [aws-sns:team_a]

  @rule(
    logs=['cloudwatch:events'],
    outputs=["aws-sns:security],
    dynamic_outputs=[dynamic_output_with_context],
    context={"account_id": "valid_account_id"},
  )
  def cloudtrail_root_account_usage(rec):
      context["account_id"] = record.get('recipientaccountid')
      # Rule logic

The above has the benefit of using information that lives outside of StreamAlert, which means teams can acquire new accounts and get ``Alerts``
without having to alter StreamAlert code.


Example:  With Other Data Source
================================

.. code-block:: python

  from streamalert.shared.rule import rule
  import requests

  def dynamic_output(record):
      account_id = record.get('recipientaccountid')

      # invoke an external API to get data back
      response = requests.get("API/team_map")

      for team in response.json():
          if account_id in team["accounts"]:
              return team["outputs"] # potentially "aws-lambda:team_a"

  @rule(
    logs=['cloudwatch:events'],
    outputs=["aws-sns:security],
    dynamic_outputs=[dynamic_output],
  )
  def cloudtrail_root_account_usage(rec):
      # Rule logic

The above example uses an external API to get the output map, which is to be queried with the ``account_id`` on the record.
This is just an example, but hopefully highlights many ways in which ``dynamic_outputs`` can be used.

.. warning:: 
  The above example could result in many queries to the API in use and could potentially slow down StreamAlert
  Lambdas when processing ``Alerts``.


..
   All references should be placed here for easy updating
   This section is not included in the generated documentation

.. _`lookup-table`: lookup-tables.html
.. _`outputs`: outputs.html
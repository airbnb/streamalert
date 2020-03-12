##########
Publishers
##########

Publishers are a framework for transforming alerts prior to dispatching to outputs, on a per-rule basis.
This allows users to customize the look and feel of alerts.


***********************
How do Publishers work?
***********************

Publishers are blocks of code that are run during alert processing, immediately prior to dispatching
an alert to an output.


***************************
Implementing new Publishers
***************************
All publishers must be added to the ``publishers`` directory. Publishers have two valid syntaxes:


Function
========
Implement a top-level function with that accepts two arguments: An Alert and a dict. Decorate this function
with the ``@Register`` decorator.

.. code-block:: python

  from streamalert.shared.publisher import Register

  @Register
  def my_publisher(alert: Alert, publication: dict) -> dict:
    # ...
    return {}


Class
=====
Implement a class that inherits from the ``AlertPublisher`` and fill in the implementations for ``publish()``.
Decorate the class with the ``@Register`` decorator.

.. code-block:: python

  from streamalert.shared.publisher import AlertPublisher, Register

  @Register
  class MyPublisherClass(AlertPublisher):

    def publish(alert: Alert, publication: dict) -> dict:
      # ...
      return {}


Recommended Implementation
==========================
Publishers should always return dicts containing only simple types (str, int, list, dict).

Publishers are executed in series, each passing its published ``Alert`` to the next publisher. The ``publication``
arg is the result of the previous publisher (or ``{}`` if it is the first publisher in the series). Publishers
should freely add, modify, or delete fields from previous publications. However, publishers should avoid
doing in-place modifications of the publications, and should prefer to copy-and-modify:

.. code-block:: python

  from streamalert.shared.publisher import Register

  @Register
  def sample_publisher(alert, publication):
    publication['new_field'] = 'new_value']
    publication.pop('old_field', None)

    return publication


*****************
Preparing Outputs
*****************
In order to take advantage of Publishers, all outputs must be implemented with the following guidelines:

**Use compose_alert()**

When presenting unstructured or miscellaneous data to an output (e.g. an email body, incident details),
outputs should be implemented to use the ``compose_alert(alert: Alert, output: OutputDispatcher, descriptor: str) -> dict``
method.

``compose_alert()`` loads all publishers relevant to the given ``Alert`` and executes these publishers in series,
returning the result of the final publisher.

All data returned by ``compose_alert()`` should be assumed as optional.

.. code-block:: python

  from streamalert.alert_processor.helpers import compose_alert

  def _dispatch(self, alert, descriptor):
    # ...
    publication = compose_alert(alert, self, descriptor)
    make_api_call(misc_data=publication)


"Default" Implementations
=========================
For output-specific fields that are mandatory (such as an incident Title or assignee), each output
should offer a default implementation:

.. code-block:: python

  def _dispatch(self, alert, descriptor):
    default_title = 'Incident Title: #{}'.format(alert.alert_id)
    default_html = '<html><body>Rule: {}</body></html>'.format(alert.rule_description)
    # ...


Custom Fields
=============
Outputs can be implemented to offer custom fields that can be filled in by Publishers. This (optionally)
grants fine-grained control of outputs to Publishers. Such fields should adhere to the following conventions:

* They are top level keys on the final publication dictionary
* Keys are strings, following the format: ``@{output_service}.{field_name}``
* Keys MUST begin with an at-sign
* The ``output_service`` should match the current outputs ``cls.__service__`` value
* The ``field_name`` should describe its function
* Example: ``@slack.attachments``

Below is an example of how you could implement an output:

.. code-block:: python

  def _dispatch(self, alert, descriptor):
    # ...
    publication = compose_alert(alert, self, descriptor)

    default_title = 'Incident Title: #{}'.format(alert.alert_id)
    default_html = '<html><body>Rule: {}</body></html>'.format(alert.rule_description)

    title = publication.get('@pagerduty.title', default_title)
    body_html = publication.get('@pagerduty.body_html', default_html)

    make_api_call(title, body_html, data=publication)


Alert Fields
============
When outputs require mandatory fields that are not subject to publishers, they should reference the ``alert``
fields directly:

.. code-block:: python

  def _dispatch(self, alert, descriptor):
    rule_description = alert.rule_description
    # ...


**********************
Registering Publishers
**********************
Register publishers on a rule using the ``publisher`` argument on the ``@rule`` decorator:

.. code-block:: python

  from publishers import publisher_1, publisher_2
  from streamalert.shared.rule import Rule

  @rule(
    logs=['stuff'],
    outputs=['pagerduty', 'slack'],
    publishers=[publisher_1, publisher_2]
  )
  def my_rule(rec):
    # ...

The ``publishers`` argument is a structure containing references to **Publishers** and can follow any of the
following structures:


Single Publisher
================
.. code-block:: python

  publishers=publisher_1

When using this syntax, the given publisher will be applied to all outputs.


List of Publishers
==================
.. code-block:: python

  publishers=[publisher_1, publisher_2, publisher_3]

When using this syntax, all given publishers will be applied to all outputs.


Dict mapping Output strings to Publisher
========================================
.. code-block:: python

  publishers={
    'pagerduty:analyst': [publisher_1, publisher_2],
    'pagerduty': [publisher_3, publisher_4],
    'demisto': other_publisher,
  }

When using this syntax, publishers under each key will be applied to their matching outputs. Publisher keys
with generic outputs (e.g. ``pagerduty``) are loaded first, before publisher keys that pertain to more
specific outputs (e.g. ``pagerduty:analyst``).

The order in which publishers are loaded will dictate the order in which they are executed.


****************
DefaultPublisher
****************
When the ``publishers`` argument is omitted from a ``@rule``, a ``DefaultPublisher`` is loaded and used. This
also occurs when the ``publishers`` are misconfigured.

The ``DefaultPublisher`` is reverse-compatible with old implementations of ``alert.output_dict()``.


***********************
Putting It All Together
***********************
Here's a real-world example of how to effectively use Publishers and Outputs:

PagerDuty requires all Incidents be created with an `Incident Summary`, which appears at as the title of every
incident in its UI. Additionally, you can optionally supply `custom details` which appear below as a large,
unstructured body.

By default, the PagerDuty integration sends ``"StreamAlert Rule Triggered - rule_name"`` as the `Incident Summary`,
along with the entire Alert record in the `custom details`.

However, the entire record can contain mostly irrelevant or redundant data, which can pollute the PagerDuty UI
and make triage slower, as responders must filter through a large record to find the relevant pieces of
information, this is especially true for alerts of very limited scope and well-understood remediation steps.

Consider an example where informational alerts are triggered upon login into a machine. Responders only care
about the **time** of login, **source IP address**, and the **username** of the login.

You can implement a publisher that only returns those three fields and strips out the rest from the alert.
The publisher can also simplify the PagerDuty title:

.. code-block:: python

  from streamalert.shared.publisher import Register

  @Register
  def simplify_pagerduty_output(alert, publication):
    return {
      '@pagerduty.record': {
          'source_ip': alert.record['source_ip'],
          'time': alert.record['timestamp'],
          'username': alert.record['user'],
      },
      '@pagerduty.summary': 'Machine SSH: {}'.format(alert.record['user']),
    }

Suppose this rule is being output to both PagerDuty and Slack, but you only wish to simplify the PagerDuty
integration, leaving the Slack integration the same. Registering the publisher can be done as such:

.. code-block:: python

  from publishers.pagerduty import simplify_pagerduty_output
  from streamalert.shared.rule import Rule

  @rule(
    logs=['ssh'],
    outputs=['slack:engineering', 'pagerduty:engineering'],
    publishers={
      'pagerduty:engineering': simplify_pagerduty_output,
    }
  )
  def machine_ssh_login(rec):
    # ...

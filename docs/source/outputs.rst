#######
Outputs
#######
StreamAlert comes with a flexible alerting framework that can integrate with new or existing case/incident management tools. Rules can send alerts to one or many outputs.

Out of the box, StreamAlert supports:

* **Amazon CloudWatch Logs**
* **Amazon Kinesis Firehose**
* **AWS Lambda**
* **AWS S3**
* **AWS SES**
* **AWS SNS**
* **AWS SQS**
* **Carbon Black**
* **Demisto**
* **GitHub**
* **Jira**
* **Komand**
* **PagerDuty**
* **Phantom**
* **Slack**
* **Microsoft Teams**

StreamAlert can be extended to support any API. Creating a new output to send alerts to is easily accomplished through inheritance from the ``StreamOutputBase`` class. More on that in the `Adding Support for New Services`_ section below.

With the addition of an output configuration, multiple outputs per service are now possible.
As an example, it is now possible for rules to dispatch alerts to multiple people or channels in Slack.

Adhering to the secure by default principle, all API credentials are encrypted and decrypted using AWS Key Management Service (KMS).
Credentials are stored on Amazon S3 and are not packaged with the StreamAlert code. They are downloaded and decrypted on an as-needed basis.
Credentials are never cached on disk in a decrypted state.


*************
Configuration
*************
Adding a new configuration for a currently supported service is handled using ``manage.py``:

.. code-block:: bash

  python manage.py output <SERVICE_NAME>

.. note::

  ``<SERVICE_NAME>`` above should be one of the following supported service identifiers.
  ``aws-cloudwatch-log``, ``aws-firehose``, ``aws-lambda``, ``aws-lambda-v2``, ``aws-s3``,
  ``aws-sns``, ``aws-sqs``, ``carbonblack``, ``github``, ``jira``, ``komand``, ``pagerduty``,
  ``pagerduty-incident``, ``pagerduty-v2``, ``phantom``, ``slack``

For example:

.. code-block:: bash

  python manage.py output slack


The above command will then prompt the user for a ``descriptor`` to use for this configuration::

 Please supply a short and unique descriptor for this Slack integration (eg: channel, group, etc):

After a ``descriptor`` is provided, the user is then prompted for the Slack webhook URL::

 Please supply the full Slack webhook url, including the secret:

.. note:: The user input for the Slack webhook URL will be masked. This 'masking' approach currently applies to any potentially sensitive information the user may have to enter on the cli and can be enforced through any new services that are implemented.


*******************************
Adding Support for New Services
*******************************
Adding support for a new service involves five steps:

1. Create a subclass of ``OutputDispatcher``

  - For reference, ``OutputDispatcher`` is declared in ``streamalert/alert_processor/outputs/output_base.py``

2. Implement the following methods, at a minimum:

  .. code-block:: python

    from streamalert.alert_processor.helpers import compose_alert


    def get_user_defined_properties(self):
      """Returns any properties for this output that must be provided by the user
      At a minimum, this method should prompt the user for a 'descriptor' value to
      use for configuring any outputs added for this service.

      Returns:
          [OrderedDict] Contains various OutputProperty items
      """
      return OrderedDict([
          ('descriptor',
           OutputProperty(description='a short and unique descriptor for this service configuration '
                                      '(ie: name of integration/channel/service/etc)'))
      ])

    def _dispatch(self, alert, descriptor):
      """Handles the actual sending of alerts to the configured service.
      Any external API calls for this service should be added here.
      This method should return a boolean where True means the alert was successfully sent.

      In general, use the compose_alert() method defined in streamalert.alert_processor.helpers
      when presenting the alert in a generic polymorphic format to be rendered on the chosen output
      integration. This is so specialized Publishers can modify how the alert is represented on the
      output.

      In addition, adding output-specific fields can be useful to offer more fine-grained control
      of the look and feel of an alert.

      For example, an optional field that directly controls a PagerDuty incident's title:
      - '@pagerduty.incident_title'


      When referencing an alert's attributes, reference the alert's field directly (e.g.
      alert.alert_id). Do not rely on the published alert.
      """

      publication = compose_alert(alert, self, descriptor)
      # ...
      return True


  See the :ref:`below <output_property>` for more information on the ``OutputProperty`` object.

3. Implement the private ``__service__`` property within the new subclass.

   - This should be a string value that corresponds to an identifier that best represents this service. (eg: ``__service__ = 'aws-s3'``)

4. Add the ``@StreamAlertOutput`` class decorator to the new subclass so it registered when the `outputs` module is loaded.

5. Extend the ``AlertProcessorTester.setup_outputs`` method in ``streamalert_cli/test.py`` module to provide mock credentials for your new output.


.. _output_property:

The ``OutputProperty`` Object
=============================
The ``OutputProperty`` object used in ``get_user_defined_properties`` is a ``namedtuple`` consisting of a few properties:

:description:
  A description that is used when prompting the user for input. This is to help describe what is expected from the user for this property.
  At a bare minimum, this property **should** be set for all instances of ``OutputProperty``.
  Default is: ``''`` (empty string)

:value:
  The actual value that the user enters for this property. This is replaced using ``namedtuple._replace`` during user input.
  Default is: ``''`` (empty string)

:input_restrictions:
  A ``set`` of character values that should be restricted from user input for this property.
  Default is: ``{' ', ':'}``

:mask_input:
  A ``boolean`` that indicates whether the user's input should be masked using ``getpass`` during entry. This should be set for any input that is potentially sensitive.
  Default is: ``False``

:cred_requirement:
  A ``boolean`` that indicates whether this value is required for API access with this service. Ultimately, setting this value to ``True`` indicates
  that the value should be encrypted and stored in Amazon Systems Manager.
  Default is: ``False``


Strategy
========
A common strategy that has been found to be effective:

* Write your rule and only designate a notification-style service, such as Slack, as an output
* Identify false positives, refine the rule over a period of time
* "Promote" the rule to production by removing Slack and adding PagerDuty and S3 as outputs

Why:

* Slack alerts are ephemeral, great for new/beta rules
* PagerDuty supports webhooks and can still ping Slack
* S3 will act as a persistent store for production alerts (audit trail, historical context)

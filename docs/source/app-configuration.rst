App Integration Configuration
=============================

Overview
--------

To further StreamAlert's abilities past ingesting logs from services that offer support for sending to AWS Lambda,
the package includes a method to fetch logs from RESTful APIs to be forwarded to StreamAlert. This capability is added through the
use of StreamAlert Apps.

StreamAlert Apps are designed to run on scheduled intervals and collect logs from a third-party API to be relayed on to the Rule Processor
for processing.


Concepts
--------

StreamAlert Apps are made possible through the use of AWS technologies:

* `AWS EC2 Simple System Manager's Parameter Store <https://aws.amazon.com/ec2/systems-manager/parameter-store/>`_
* `AWS Lambda Invocations via Scheduled Events <http://docs.aws.amazon.com/lambda/latest/dg/with-scheduled-events.html>`_


Supported Services
------------------

* Duo

  - Authentication Logs
  - Administrator Logs


Getting Started
---------------

An initial deploy of StreamAlert must be performed before StreamAlert Apps can be configured. If you do not have a current deploy,
please visit the `Project's Getting Started <getting-started.html>`_ page to get up and running.


Adding a new StreamAlert App requires the following steps:

1. Configure the StreamAlert App through the CLI (via ``python manage.py app new``).
2. Enter the required authentication information for the app being configured.
3. Deploy the new App and the Rule Processor to accept incoming data from your App.

To get help configuring a new StreamAlert App, use:

.. code-block:: bash

  $ python manage.py app new --help


1. Configure the StreamAlert App
````````````````````````````````

The StreamAlert CLI is used to add a new App configuration.

.. code-block:: bash

  $ python manage.py app new \
  --type duo_auth \
  --cluster prod \
  --name duo_prod_collector \
  --interval 'rate(2 hours)' \
  --timeout 80 \
  --memory 128


.. note:: Duo Security's Admin API is limited to two (2) requests per-minute. Therefore, setting the ``--timeout`` flag to any value between 10 and 60 will be of no additional value. A recommended timeout of 80 seconds will guarantee four (4) requests happen per-execution.



=========================  ===========
Flag                       Description
-------------------------  -----------
``--type``                 Type of app integration function being configured. Current choices are: `duo_auth`, `duo_admin`
``--cluster``              Applicable cluster this function should be configured against.
``--name``                 Unique name to be assigned to this app integration function. This is useful when configuring multiple accounts per service.
``--interval``             The interval, defined using a 'rate' expression, at which this app integration function should execute. See AWS Schedule `Rate Expressions <http://docs.aws.amazon.com/AmazonCloudWatch/latest/events/ScheduledEvents.html#RateExpressions>`_.
``--timeout``              The AWS Lambda function timeout value, in seconds. This should be an integer between 10 and 300.
``--memory``               The AWS Lambda function max memory value, in megabytes. This should be an integer between 128 and 1536.
=========================  ===========



2. Enter the required authentication information
````````````````````````````````````````````````

The above command will result in a few prompts asking for the required authentication information needed to configure this StreamAlert App.

.. note:: After the last required authentication value is entered, the values are sent to AWS SSM's `Parameter Store <https://aws.amazon.com/ec2/systems-manager/parameter-store/>`_ as a ``SecureString`` to be used as part of this App's config. Due to this requirement, please ensure you have the correct and valid AWS credentials loaded before continuing.

Example Prompts for Duo Auth
''''''''''''''''''''''''''''

.. code-block:: bash

  Please supply the API url for this duosecurity instance. This should be in a format similar to 'api-abcdef12.duosecurity.com': api-abcdef12.duosecurity.com

  Please supply the secret key for this duosecurity Admin API. This should a string of 40 alphanumeric characters: 123424af2ae101d47d9704b783c940dffa825678

  Please supply the integration key for this duosecurity Admin API. This should be in a format similar to 'DIABCDEFGHIJKLMN1234': DIABCDEFGHIJKLMN1234


Once the above is completed, a logger statement similar to the following will confirm the configuration::

  StreamAlertCLI [INFO]: App authentication info successfully saved to parameter store.
  StreamAlertCLI [INFO]: Successfully added 'duo_prod_collector' app integration to 'conf/clusters/prod.json' for service 'duo_auth'.


And the ``conf/clusters/prod.json`` file will be updated to include the configuration for this App:

.. code-block:: json

  {
    "...": "...",
    "modules": {
      "...": "...",
      "stream_alert_apps": {
        "duo_prod_collector": {
          "current_version": "$LATEST",
          "interval": "rate(2 hours)",
          "log_level": "info",
          "memory": 128,
          "timeout": 80,
          "type": "duo_auth"
        }
      }
    }
  }


The ``conf/sources.json`` file will also automatically update with the information the Rule Processor needs to accept input from this App:

.. code-block:: json

  {
    "...": "...",
    "stream_alert_app": {
      "<prefix>_<cluster>_duo_auth_duo_prod_collector_app": {
        "logs": [
          "duo"
        ]
      }
    }
  }


3. Deploy the new App and the Rule Processor
````````````````````````````````````````````

StreamAlert's Rule Processor must be aware of all input sources in order to process the data coming from them. As mentioned above, the ``conf/sources.json`` is automatically updated
locally when a new StreamAlert App is configured, but this local change must also be deployed in the Rule Processor to have any affect.

The recommended process is to just deploy both the `apps` function and the `rule` processor function with:

.. code-block:: bash

  $ python manage.py lambda deploy --processor rule --processor apps


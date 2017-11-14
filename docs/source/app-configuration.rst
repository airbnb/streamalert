App Configuration
=================

Overview
--------

For StreamAlert and other related platforms, log forwarding is usually left as an exercise to the reader. This work is non-trivial
and often requires new infrastructure and code. We wanted to make this easier for everyone and have achieved this through StreamAlert Apps.

Apps allow you to collect logs from popular services and applications in minutes. You simply provide the application's
credentials and StreamAlert will deploy an individual serverless application that will fetch and forward logs to StreamAlert for analysis and alerting.


Concepts
--------

Apps are made possible through the use of AWS technologies:

* `AWS EC2 Simple System Manager's Parameter Store <https://aws.amazon.com/ec2/systems-manager/parameter-store/>`_
* `AWS Lambda Invocations via Scheduled Events <http://docs.aws.amazon.com/lambda/latest/dg/with-scheduled-events.html>`_


Supported Services
------------------

* `Duo <https://duo.com/docs/administration-reporting>`_

  - Authentication Logs
  - Administrator Logs

* `OneLogin <https://support.onelogin.com/hc/en-us/articles/202123754-Events>`_

  - Events Logs

* G Suite Reports (`Activities <https://developers.google.com/admin-sdk/reports/v1/reference/activities>`_)

  - Admin
  - Calendar
  - Google Drive
  - Groups
  - Google Plus
  - Logins
  - Mobile Audit
  - Rules
  - SAML
  - Authorization Tokens

* `Box <https://developer.box.com/v2.0/reference#events>`_

  - Admin Events

* *More to come*


Getting Started
---------------

An initial deploy of StreamAlert must be performed before Apps can be configured. If you haven't deployed StreamAlert yet,
please visit the `Getting Started <getting-started.html>`_ page to get up and running.


Deploying an App only takes 3 steps:

1. Configure the App through the CLI (via ``python manage.py app new``).
2. Enter the required authentication information.
3. Deploy the new App and the Rule Processor.

To get help configuring a new App, use:

.. code-block:: bash

  $ python manage.py app new --help


1. Configure the App
````````````````````

The StreamAlert CLI is used to add a new App configuration.

.. code-block:: bash

  $ python manage.py app new \
  --type duo_auth \
  --cluster prod \
  --name duo_prod_collector \
  --interval 'rate(2 hours)' \
  --timeout 80 \
  --memory 128


=========================  ===========
Flag                       Description
-------------------------  -----------
``--type``                 Type of app integration function being configured. Current choices are: `duo_auth`, `duo_admin`
``--cluster``              Applicable cluster this function should be configured against.
``--name``                 Unique name to be assigned to the App. This is useful when configuring multiple accounts per service.
``--interval``             The interval, defined using a 'rate' expression, at which this app integration function should execute. See AWS Schedule `Rate Expressions <http://docs.aws.amazon.com/AmazonCloudWatch/latest/events/ScheduledEvents.html#RateExpressions>`_.
``--timeout``              The AWS Lambda function timeout value, in seconds. This should be an integer between 10 and 300.
``--memory``               The AWS Lambda function max memory value, in megabytes. This should be an integer between 128 and 1536.
=========================  ===========

.. note:: Duo Security's Admin API is limited to two (2) requests per-minute. Therefore, setting the ``--timeout`` flag to any value between 10 and 60 will be of no additional value. A recommended timeout of 80 seconds will guarantee four (4) requests happen per-execution.

2. Enter the required authentication information
````````````````````````````````````````````````

The above command will result in a few prompts asking for the required authentication information needed to configure this App.

.. note:: After the last required authentication value is entered, the values are sent to AWS SSM's `Parameter Store <https://aws.amazon.com/ec2/systems-manager/parameter-store/>`_ as a ``SecureString`` to be used as part of this App's config. Due to this requirement, please ensure you have the correct and valid AWS credentials loaded before continuing.

Example Prompts for Duo Auth
''''''''''''''''''''''''''''

.. code-block:: bash

  Please supply the API URL for your duosecurity instance. This should be in a format similar to 'api-abcdef12.duosecurity.com': api-abcdef12.duosecurity.com

  Please supply the secret key for your duosecurity Admin API. This should a string of 40 alphanumeric characters: 123424af2ae101d47d9704b783c940dffa825678

  Please supply the integration key for your duosecurity Admin API. This should be in a format similar to 'DIABCDEFGHIJKLMN1234': DIABCDEFGHIJKLMN1234


Once the above is completed, a logger statement similar to the following will confirm the configuration::

  StreamAlertCLI [INFO]: App authentication info successfully saved to parameter store.
  StreamAlertCLI [INFO]: Successfully added 'duo_prod_collector' app integration to 'conf/clusters/prod.json' for service 'duo_auth'.


Your configuration files (``conf/clusters/<cluster>.json`` and ``conf/sources.json``) have now been updated and are ready to be deployed.

3. Deploy the new App and the Rule Processor
````````````````````````````````````````````

The recommended process is to deploy both the `apps` function and the `rule` processor function with:

.. code-block:: bash

  $ python manage.py lambda deploy --processor rule apps


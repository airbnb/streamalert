####
Apps
####

*****************
App Configuration
*****************
For StreamAlert and other related platforms, log forwarding is usually left as an exercise to the reader. This work is non-trivial
and often requires new infrastructure and code. We wanted to make this easier for everyone and have achieved this through StreamAlert Apps.

Apps allow you to collect logs from popular services and applications in minutes. You simply provide the application's
credentials and StreamAlert will deploy an individual serverless application that will fetch and forward logs to StreamAlert for analysis and alerting.


Concepts
========
Apps are made possible through the use of AWS technologies:

* `AWS EC2 Simple System Manager's Parameter Store <https://aws.amazon.com/ec2/systems-manager/parameter-store/>`_
* `AWS Lambda Invocations via Scheduled Events <http://docs.aws.amazon.com/lambda/latest/dg/with-scheduled-events.html>`_


Supported Services
==================
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

* `Slack <https://api.slack.com/web/>`_

  - Access Logs
  - Integrations Logs

* `Intercom <https://developers.intercom.com/intercom-api-reference/reference#view-admin-activity-logs>`_

- Admin Activity Logs

* *More to come*


Getting Started
===============
An initial deploy of StreamAlert must be performed before Apps can be configured. If you haven't deployed StreamAlert yet,
please visit the `Getting Started <getting-started.html>`_ page to get up and running.


Deploying an App only takes 3 steps:

1. Configure the App through the CLI (via ``python manage.py app new``).
2. Enter the required authentication information.
3. Deploy the new App and the Classifier.

To get help configuring a new App, use:

.. code-block:: bash

  python manage.py app new --help


Configuring an App
------------------
The StreamAlert CLI is used to add a new App configuration.

.. code-block:: bash

  python manage.py app new \
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

.. note::

  Duo Security's Admin API is limited to two (2) requests per-minute. Therefore, setting the
  ``--timeout`` flag to any value between 10 and 60 will be of no additional value. A recommended
  timeout of 80 seconds will guarantee four (4) requests happen per-execution.


Enter the Authentication Info
-----------------------------
The above command will result in a few prompts asking for the required authentication information needed to configure this App.

.. note::

  After the last required authentication value is entered, the values are sent to AWS SSM's
  `Parameter Store <https://aws.amazon.com/ec2/systems-manager/parameter-store/>`_ as a ``SecureString``
  to be used as part of this App's config. Due to this requirement, please ensure you have the correct
  and valid AWS credentials loaded before continuing.


Example Prompts for Duo Auth
^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. code-block::

  Please supply the API URL for your duosecurity instance. This should be in a format similar to 'api-abcdef12.duosecurity.com': api-abcdef12.duosecurity.com

  Please supply the secret key for your duosecurity Admin API. This should be a string of 40 alphanumeric characters: 123424af2ae101d47d9704b783c940dffa825678

  Please supply the integration key for your duosecurity Admin API. This should be in a format similar to 'DIABCDEFGHIJKLMN1234': DIABCDEFGHIJKLMN1234


Once the above is completed, a logger statement similar to the following will confirm the configuration::

  StreamAlertCLI [INFO]: App authentication info successfully saved to parameter store.
  StreamAlertCLI [INFO]: Successfully added 'duo_prod_collector' app integration to 'conf/clusters/prod.json' for service 'duo_auth'.


Your configuration file ``conf/clusters/<cluster>.json`` has now been updated and is ready to be deployed.


Deploy the Functions
--------------------
The recommended process is to deploy both the `apps` function and the `classifier` processor function with:

.. code-block:: bash

  python manage.py deploy --functions classifier apps


Authorizing the Slack App
=========================
The Slack endpoint API requires a bearer token, obtained by going through the slack oauth authentication process. Only one path through the process is supported by the Slack App: manually installing a custom integration.

To obtain the bearer token, an administrator of the Slack workspace must create a custom Slack app, add the ``admin`` permission scope to the custom app, and install the app to the target workspace.

Step by step:

   1. Visit the `Create a Slack app <https://api.slack.com/apps/new>`_ page, and in the ``Create a Slack App`` dialog box fill in the ``App Name`` field with whatever you like and the select the target workspace from the ``Development Slack Workspace`` dropbdown box. Click ``Create App``.
   2. On the ``Basic Information`` page of the app you just created, scroll to and click on ``OAuth & Permissions`` on the left hand sidebar.
   3. Scroll to the ``Scopes`` section, click on the dropdown box under ``Select Permission Scopes``, and type ``admin`` to bring up the administrator scope (labeled ``Administer the workspace``). Select it, then click ``Save changes``.
   4. Scroll to the top of that same page and click on ``Install App to Workspace``. Click ``Authorize`` on the next dialog. You should be returned to the ``OAuth & Permissions`` page.
   5. The bearer token is the string labeled with ``OAuth Access Token`` and beginning with ``xoxp-``. Provide this when configuring the Slack StreamAlert app.


Enabling the Aliyun App
=======================
The Aliyun API requires an access key and access key secret for an authorized user.

To obtain the access key and access key secret, an authorized user of the Aliyun account should follow their directions to `Create an Access Key <https://www.alibabacloud.com/help/doc-detail/53045.htm>`_.

Additionally, the user for whom the access key was created must have sufficient privileges to make use of ActionTrail; follow the directions on the `Grant ActionTrail permissions to RAM users <https://www.alibabacloud.com/help/doc-detail/28818.htm>`_ page.


How to set up the Intercom App
==============================
The Intercom API requires an access token. Get an access token by following these `instructions <https://developers.intercom.com/building-apps/docs/authorization#section-how-to-get-an-access-token>`_.

To specify an API version, follow `these instructions <https://developers.intercom.com/building-apps/docs/api-versioning>`_ to do so through Intercom's Developer Hub.
The default will be the latest stable version. The Intercom app works on versions 1.2 or later.


*****************************
Updating an App's Credentials
*****************************
You may need to change an App's credentials due to internal rotation policies or otherwise. The StreamAlert CLI allows you to easily update App credentials.
to aid in this process, the CLI also give you the ability to list currently configured Apps.


Listing Apps
============
To list currently configured Apps (grouped by cluster), use the CLI command:

.. code-block:: bash

  python manage.py app list

Example output::

  Cluster: prod

    Name: duo_prod_collector
      log_level:                     info
      interval:                      rate(2 hours)
      timeout:                       80
      memory:                        128
      type:                          duo_auth


.. note:: The output will show `No Apps configured` if you have not configured any Apps.


Updating Credentials
====================
To update an App's credentials, run the the following command:

.. code-block:: bash

  python manage.py app update-auth --cluster <cluster> --name <app_name>


This will have you follow a process similar to `configuring a new App <#configuring-an-app>`_.


********************
Developing a New App
********************
An App can be created to collect logs from virtually any RESTful API that supports HTTP GET requests.

Developing an App for a currently unsupported service is as easy as:

1. Add a new file in ``streamalert/apps/_apps`` to correspond to the new service (eg: ``box.py``).
2. Create a subclass of the ``AppIntegration`` class found in ``streamalert/apps/app_base.py``.
3. Implement the required abstract properties and methods on the new subclass.


Example
=======
This is a non-functional example of adding a new App for the Box `Events <https://developer.box.com/reference#events>`_ API. This is
to outline what methods from the base ``AppIntegration`` class must be implemented and what those methods must do.

.. code:: python
  :name: streamalert/apps/_apps/box.py

  # streamalert/apps/_apps/box.py
  from . import AppIntegration, LOGGER, StreamAlertApp

  @StreamAlertApp
  class BoxApp(AppIntegration):
    """Box StreamAlert App"""

    _BOX_API_V2_EVENTS_ENDPOINT = 'https://api.box.com/2.0/events'
    _MAX_EVENTS_LIMIT = 500

    # Implement this abstractproperty
    @classmethod
    def service(cls):
      return 'box'

    # Implement this abstractproperty
    @classmethod
    def _type(cls):
      return 'admin_logs'

    # Implement this abstractmethod
    def required_auth_info(self):
      return {
          'secret_key':
              {
                  'description': ('the secret key for this Box instance...'),
                  'format': re.compile(r'...')
              },
          'client_id':
              {
                  'description': ('the client_id for this Box instance...'),
                  'format': re.compile(r'...')
              },
          'token':
              {
                  'description': ('the token for this Box instance...'),
                  'format': re.compile(r'...')
              }
          }

    # Implement this abstractmethod
    def _sleep_seconds(self):
      """Return the number of seconds this polling function should sleep for between requests

      Box imposes the following API limits: 10 API calls per second per user
      Box reference: https://developer.box.com/reference#rate-limiting

      Basically, this function should guarantee we sleep for 1 second every 10 requests

      Returns:
          int: Number of seconds that this function should sleep for between requests
      """
      return self._poll_count / 10 * 1

    # Implement this abstractmethod
    def _gather_logs(self):
      """Gather the Box event logs.

      This function should set a few things on the superclass:
        self._last_timestamp     # Set to the last timestamp/stream position from the logs
        self._more_to_poll       # Set to True if the max # of logs was polled this time


      Returns:
        list or bool: The list of logs fetched from the service, or False if
          there was an error during log collection.
      """
      headers = {'Authorization': 'Bearer {}'.format(self._get_oauth())}
      params = {'stream_position': self._last_timestamp,
                'limit': self._MAX_EVENTS_LIMIT,
                'stream_type': 'admin_logs'}

      # Make the request to the api, resulting in a bool or dict
      response = self._make_request(self._BOX_API_V2_EVENTS_ENDPOINT, headers=headers, params=params)
      if not response:
          return False

      logs = response['entries']

      # Set the last timestamp to the next stream position to be used in the next poll
      self._last_timestamp = response['next_stream_position']

      # Set self._more_to_poll to indicate there are more logs to collect
      self._more_to_poll = len(logs) >= self._MAX_EVENTS_LIMIT

      return logs

    def _get_oauth(self):
      """This should return the oauth token for this request"""
      secret_key = self._config.auth['secret_key']
      client_id = self._config.auth['client_id']
      token = self._config.auth['token']

      # Do something to generate oauth
      return generated_oauth

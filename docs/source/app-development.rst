Developing a New App
====================

Overview
--------

An App can be created to collect logs from virtually any RESTful API that supports HTTP GET requests.

Developing an App for a currently unsupported service is as easy as:

1. Add a new file in ``app_integrations/apps/`` to correspond to the new service (ie: ``box.py``).
2. Create a subclass of the ``AppIntegration`` class found in ``app_integrations/apps/app_base.py``.
3. Implement the required abstract properties and methods on the new subclass.


New App Example
---------------

This is a non-functional example of adding a new App for the Box `Events <https://developer.box.com/reference#events>`_ API. This is
to outline what methods from the base ``AppIntegration`` class must be implemented and what those methods must do.

.. code:: python
  :name: app_integrations/apps/box.py

  # app_integrations/apps/box.py
  from app_integrations.apps.app_base import StreamAlertApp, AppIntegration

  # @StreamAlertApp
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

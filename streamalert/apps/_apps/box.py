"""
Copyright 2017-present Airbnb, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""
import json

import requests
from boxsdk import Client, JWTAuth
from boxsdk.exception import BoxException
from boxsdk.object.events import EnterpriseEventsStreamType

from . import AppIntegration, StreamAlertApp, get_logger, safe_timeout

LOGGER = get_logger(__name__)


@StreamAlertApp
class BoxApp(AppIntegration):
    """BoxApp integration"""
    _MAX_CHUNK_SIZE = 500
    _MAX_RETRY_COUNT = 3

    def __init__(self, event, context):
        super().__init__(event, context)
        self._client = None
        self._next_stream_position = None

    @classmethod
    def _type(cls):
        return 'admin_events'

    @classmethod
    def service(cls):
        return 'box'

    @classmethod
    def date_formatter(cls):
        """Return a format string for a date, ie: 2017-11-01T00:29:51-00:00

        This format is consistent with the format recommended by Box docs:
            https://developer.box.com/reference#section-date-format
        """
        return '%Y-%m-%dT%H:%M:%S-00:00'

    @classmethod
    def _load_auth(cls, auth_data):
        """Load JWTAuth from Box service account JSON keyfile

        Args:
            auth_data (dict): The loaded keyfile data from a Box service account
                JSON file
        Returns:
            boxsdk.JWTAuth Instance of JWTAuth that allows the client to authenticate
                or False if there was an issue loading the auth
        """
        try:
            auth = JWTAuth.from_settings_dictionary(auth_data)
        except (TypeError, ValueError, KeyError):
            LOGGER.exception('Could not load JWT from settings dictionary')
            return False

        return auth

    def _create_client(self):
        """Box requests must be signed with a JWT keyfile

        Returns:
            bool: True if the Box client was successfully created or False
                if any errors occurred during the creation of the client
        """
        if self._client:
            LOGGER.debug('[%s] Client already instantiated', self)
            return True

        auth = self._load_auth(self._config.auth['keyfile'])
        if not auth:
            return False

        self._client = Client(auth)

        return bool(self._client)

    @safe_timeout
    def _make_request(self):
        """Make the request using the Box client

        The inner function of `_perform_request` is used to handle a single retry in
        the event of a ConnectionError. If this fails twice, the function will return

        Returns:
            dict: Response from Box (boxsdk.session.box_session.BoxResponse) that is
                json loaded into a dictionary.
        """
        # Create the parameters for this request, 100 is the max value for limit
        params = {
            'limit': self._MAX_CHUNK_SIZE,
            'stream_type': EnterpriseEventsStreamType.ADMIN_LOGS,
        }

        # From Box's docs: Box responds to the created_before and created_after
        # parameters only if the stream_position parameter is not included.
        if self._next_stream_position:
            params['stream_position'] = self._next_stream_position
        else:
            params['created_after'] = self._last_timestamp

        LOGGER.debug('[%s] Requesting events', self)

        def _perform_request(timeout, allow_retry=True, retry_count=0):
            try:
                # Get the events using a make_request call with the box api. This is to
                # support custom parameters such as 'created_after' and 'created_before'
                box_response = self._client.make_request('GET',
                                                         self._client.get_url('events'),
                                                         params=params,
                                                         timeout=timeout)
            except BoxException:
                LOGGER.exception('[%s] Failed to get events', self)
                return False, {}  # Return a tuple to conform to return value of safe_timeout
            except requests.exceptions.Timeout:
                # Retry requests that timed out a few more times, with increased timeout
                timeout *= 2
                LOGGER.debug('Attempting new request with timeout: %0.2f seconds', timeout)
                if retry_count == self._MAX_RETRY_COUNT:
                    raise  # eventually give up and raise this
                return _perform_request(timeout, allow_retry, retry_count + 1)
            except requests.exceptions.ConnectionError:
                # In testing, the requests connection seemed to get reset for no
                # obvious reason, and a simple retry once works fine so catch it
                # and retry once, but after that return False
                LOGGER.exception('Bad response received from host, will retry once')
                if allow_retry:
                    return _perform_request(timeout, allow_retry=False)

                return False, {}  # Return a tuple to conform to return value of safe_timeout

            # Return a successful status and the JSON from the box response
            # Return a tuple to conform to return value of safe_timeout
            return True, box_response.json()

        return _perform_request(self._DEFAULT_REQUEST_TIMEOUT)

    def _gather_logs(self):
        """Gather the Box Admin Events

        The ideal way to do this would be to use the boxsdk.events.Events class and the
        `get_events` method to retrieve these events. However, this method does allow you
        to pass keyword arguments (such as params) which are needed for specifying the
        'created_after' parameter.

        Returns:
            bool or list: If the execution fails for some reason, return False.
                Otherwise, return a list of box admin event entries.
        """
        if not self._create_client():
            LOGGER.error('[%s] Could not create client', self)
            return False

        result, response = self._make_request()

        # If the result is False, errors would be previously logged up
        # the stack before this, so just return False
        if not result:
            return False

        if not response:
            LOGGER.error('[%s] No results received in request', self)
            return False

        self._more_to_poll = int(response['chunk_size']) >= self._MAX_CHUNK_SIZE

        events = response.get('entries', [])
        if not events:
            LOGGER.info('[%s] No events found in result', self)
            return False

        self._next_stream_position = response['next_stream_position']

        self._last_timestamp = events[-1]['created_at']

        return events

    @classmethod
    def _required_auth_info(cls):
        # Use a validation function to ensure the file the user provides is valid
        def keyfile_validator(keyfile):
            """A JSON formatted Box service account private key file key"""
            try:
                with open(keyfile.strip(), encoding="utf-8") as json_keyfile:
                    auth_data = json.load(json_keyfile)
            except (OSError, ValueError):
                return False

            return auth_data if cls._load_auth(auth_data) else False

        return {
            'keyfile': {
                'description': ('the path on disk to the JSON formatted Box '
                                'service account private key file'),
                'format':
                keyfile_validator
            }
        }

    def _sleep_seconds(self):
        """Return the number of seconds this polling function should sleep for
        between requests to avoid failed requests.

        The Box API has a limit of 10 API calls per second per user, which we will
        not hit, so return 0 here.

        Returns:
            int: Number of seconds that this function should sleep for between requests
        """
        return 0

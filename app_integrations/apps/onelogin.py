"""
Copyright 2017-present, Airbnb Inc.

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
import re

from datetime import datetime
import requests

from app_integrations import LOGGER
from app_integrations.apps.app_base import app, AppIntegration


class OneLoginApp(AppIntegration):
    """OneLogin StreamAlert App"""
    _ONELOGIN_EVENTS_URL = 'https://api.us.onelogin.com/api/1/events'
    _ONELOGIN_TOKEN_URL = 'https://api.us.onelogin.com/auth/oauth2/v2/token'
    # OneLogin API returns 50 events per page
    _MAX_EVENTS_LIMIT = 50

    # Define our authorization headers variable
    def __init__(self, config):
        super(OneLoginApp, self).__init__(config)
        self._auth_headers = None
        self._next_page_url = None

    @classmethod
    def _type(cls):
        return 'events'

    @classmethod
    def _endpoint(cls):
        """Class method to return the OneLogin events endpoint

        Returns:
            str: Path of the events endpoint to query
        """
        return cls._ONELOGIN_EVENTS_URL

    @classmethod
    def service(cls):
        return 'onelogin'

    def _generate_headers(self, token_url, client_secret, client_id):
        """Each request will request a new token to call the resources APIs.

        More details to be found here:
            https://developers.onelogin.com/api-docs/1/oauth20-tokens/generate-tokens-2

        Returns:
            str: Bearer token to be used to call the OneLogin resource APIs
        """
        authorization = 'client_id: %s, client_secret: %s' % (client_id, client_secret)
        headers_token = {'Authorization': authorization,
                         'Content-Type': 'application/json'}

        response = requests.post(token_url,
                                 json={'grant_type':'client_credentials'},
                                 headers=headers_token)

        if not self._check_http_response(response):
            return False

        bearer = 'bearer:' % (response.json()['access_token'])
        self._auth_headers = {'Authorization': bearer}

    def _gather_logs(self):
        """Gather the authentication log events."""

        if not self._auth_headers:
            self._auth_headers = self._generate_headers(self._ONELOGIN_TOKEN_URL,
                                                        self._config['auth']['client_secret'],
                                                        self._config['auth']['client_id'])

        self._next_page_url = self._ONELOGIN_EVENTS_URL
        return self._get_onelogin_events()

    def _get_onelogin_events(self):
        """Get all events from the endpoint for this timeframe

        Returns:
            [
                {
                    'id': <int:id>,
                    'created_at': <str:created_at>,
                    'account_id': <int:account_id>,
                    'user_id': <int:user_id>,
                    'event_type_id': <int:event_type_id>,
                    'notes': <str:notes>,
                    'ipaddr': <str:ipaddr>,
                    'actor_user_id': <int:actor_user_id>,
                    'assuming_acting_user_id': null,
                    'role_id': <int:role_id>,
                    'app_id': <int:app_id>,
                    'group_id': <int:group_id>,
                    'otp_device_id': <int:otp_device_id>,
                    'policy_id': <int:policy_id>,
                    'actor_system': <str:actor_system>,
                    'custom_message': <str:custom_message>,
                    'role_name': <str:role_name>,
                    'app_name': <str:app_name>,
                    'group_name': <str:group_name>,
                    'actor_user_name': <str:actor_user_name>,
                    'user_name': <str:user_name>,
                    'policy_name': <str:policy_name>,
                    'otp_device_name': <str:otp_device_name>,
                    'operation_name': <str:operation_name>,
                    'directory_sync_run_id': <int:directory_sync_run_id>,
                    'directory_id': <int:directory_id>,
                    'resolution': <str:resolution>,
                    'client_id': <int:client_id>,
                    'resource_type_id': <int:resource_type_id>,
                    'error_description': <str:error_description>
                }
            ]
        """
        # OneLogin API expects the ISO 8601 format: YYYY-MM-DDTHH:MM:SSZ
        formatted_date = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        params = {'since': formatted_date}

        # Make sure we have authentication headers
        if not self._auth_headers:
            return False

        events = self._get_onelogin_paginated_events(params)

        while self._more_to_poll and self._next_page_url:
            LOGGER.debug('More events to retrieve for \'%s\': %s', self.type(), self._more_to_poll)
            pagination = self._get_onelogin_paginated_events(None)

            # Add the events to our results, this is equivalent to using events.extend()
            events += pagination

        # Return the list of logs to the caller so they can be send to the batcher
        return events

    def _get_onelogin_paginated_events(self, params):
        """Get events from the API pagination url

        Returns:
            The same as the method _get_onelogin_events()
        """
        response = requests.get(self._next_page_url, headers=self._auth_headers, params=params)
        if not self._check_http_response(response):
            return False

        # Extract events from response
        events = response.json()['data']

        # Do we have a pagination link to follow?
        self._more_to_poll = len(events) >= self._MAX_EVENTS_LIMIT

        # If we are already retrieved all the events, then set the value to prevent more requests
        self._next_page_url = response.json()['pagination']['next_link']

        return events

    def required_auth_info(self):
        return {
            'client_secret':
                {
                    'description': ('the client secret for the OneLogin API. This '
                                    'should a string of 57 alphanumeric characters'),
                    'format': re.compile(r'^[a-zA-Z0-9]{57}$')
                },
            'client_id':
                {
                    'description': ('the client id for the OneLogin API. This '
                                    'should a string of 57 alphanumeric characters'),
                    'format': re.compile(r'^[a-zA-Z0-9]{57}$')
                }
            }

    def _sleep_seconds(self):
        """Return the number of seconds this polling function should sleep for
        between requests to avoid failed requests. OneLogin tokens allows for 5000 requests
        every hour, so returning 0 for now.

        Returns:
            int: Number of seconds that this function shoud sleep for between requests
        """
        return 0

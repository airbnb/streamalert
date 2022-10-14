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
import re

from . import AppIntegration, StreamAlertApp, get_logger

LOGGER = get_logger(__name__)


@StreamAlertApp
class OneLoginApp(AppIntegration):
    """OneLogin StreamAlert App"""
    _ONELOGIN_EVENTS_URL = 'https://api.{}.onelogin.com/api/1/events'
    _ONELOGIN_TOKEN_URL = 'https://api.{}.onelogin.com/auth/oauth2/v2/token'  # nosec
    _ONELOGIN_RATE_LIMIT_URL = 'https://api.{}.onelogin.com/auth/rate_limit'
    # OneLogin API returns 50 events per page
    _MAX_EVENTS_LIMIT = 50

    # Define our authorization headers variable
    def __init__(self, event, config):
        super().__init__(event, config)
        self._auth_headers = None
        self._next_page_url = None
        self._rate_limit_sleep = 0

    @classmethod
    def _type(cls):
        return 'events'

    @classmethod
    def service(cls):
        return 'onelogin'

    @classmethod
    def date_formatter(cls):
        """OneLogin API expects the ISO 8601 format: YYYY-MM-DDTHH:MM:SSZ"""
        return '%Y-%m-%dT%H:%M:%SZ'

    def _token_endpoint(self):
        """Get the endpoint URL to retrieve tokens

        Returns:
            str: Full URL to generate tokens for the OneLogin API
        """
        return self._ONELOGIN_TOKEN_URL.format(self._config.auth['region'])

    def _events_endpoint(self):
        """Get the endpoint URL to retrieve events

        Returns:
            str: Full URL to retrieve events in the OneLogin API
        """
        return self._ONELOGIN_EVENTS_URL.format(self._config.auth['region'])

    def _rate_limit_endpoint(self):
        """Get the endpoint URL to retrieve rate limit details

        Returns:
            str: Full URL to retrieve rate limit details in the OneLogin API
        """
        return self._ONELOGIN_RATE_LIMIT_URL.format(self._config.auth['region'])

    def _generate_headers(self):
        """Each request will request a new token to call the resources APIs.

        More details to be found here:
            https://developers.onelogin.com/api-docs/1/oauth20-tokens/generate-tokens-2

        Returns:
            str: Bearer token to be used to call the OneLogin resource APIs
        """
        if self._auth_headers:
            return True

        authorization = f"client_id: {self._config.auth['client_id']}, client_secret: {self._config.auth['client_secret']}"

        headers_token = {'Authorization': authorization, 'Content-Type': 'application/json'}

        result, response = self._make_post_request(self._token_endpoint(), headers_token,
                                                   {'grant_type': 'client_credentials'})

        if not result:
            return False

        if not response:
            LOGGER.error('[%s] Response invalid, could not generate headers', self)
            return False

        bearer = f"bearer:{response.get('access_token')}"
        self._auth_headers = {'Authorization': bearer}

        return True

    def _gather_logs(self):
        """Gather the authentication log events."""
        return self._get_onelogin_events() if self._generate_headers() else False

    def _set_rate_limit_sleep(self):
        """Get the number of seconds we need to sleep until we are clear to continue"""
        # Make sure we have authentication headers
        if not self._auth_headers:
            self._rate_limit_sleep = 0
            LOGGER.error('[%s] No authentication headers set', self)
            return

        result, response = self._make_get_request(self._rate_limit_endpoint(), self._auth_headers)

        if not result:
            self._rate_limit_sleep = 0
            return

        # Making sure we have a valid response
        if not response:
            LOGGER.error('[%s] Response invalid, could not get rate limit info', self)
            self._rate_limit_sleep = 0
            return

        self._rate_limit_sleep = response.get('data')['X-RateLimit-Reset']
        LOGGER.info('[%s] Rate limit sleep set: %d', self, self._rate_limit_sleep)

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
        # Make sure we have authentication headers
        if not self._auth_headers:
            LOGGER.error('[%s] No authentication headers set', self)
            return False

        # Are we just getting events or getting paginated events?
        if self._next_page_url:
            params = None
            request_url = self._next_page_url
        else:
            params = {'since': self._last_timestamp}
            request_url = self._events_endpoint()

        result, response = self._make_get_request(request_url, self._auth_headers, params)

        if not result:
            # If we hit the rate limit, update the sleep time
            if response and response.get('status'):
                r_status = response.get('status')
                if r_status['code'] == 400 and r_status['message'] == 'rate_limit_exceeded':
                    self._set_rate_limit_sleep()

            return False

        # Fail if response is invalid
        if not response:
            LOGGER.error('[%s] Received invalid response', self)
            return False

        # Set pagination link, if there is any
        self._next_page_url = response['pagination']['next_link']
        self._more_to_poll = bool(self._next_page_url)

        # Adjust the last seen event, if the events list is not empty
        if not response['data']:
            LOGGER.info('[%s] Received empty list of events', self)
            return False

        self._last_timestamp = response['data'][-1]['created_at']

        # Return the list of events to the caller so they can be send to the batcher
        return response['data']

    @classmethod
    def _required_auth_info(cls):
        return {
            'region': {
                'description': ('the region for the OneLogin API. This should be'
                                'just "en" or "us".'),
                'format': re.compile(r'^(en|us)$')
            },
            'client_secret': {
                'description': ('the client secret for the OneLogin API. This '
                                'should be a string of 64 alphanumeric characters'),
                'format':
                re.compile(r'^[a-z0-9]{64}$')
            },
            'client_id': {
                'description': ('the client id for the OneLogin API. This '
                                'should be a string of 64 alphanumeric characters'),
                'format':
                re.compile(r'^[a-z0-9]{64}$')
            }
        }

    def _sleep_seconds(self):
        """Return the number of seconds this polling function should sleep for
        between requests to avoid failed requests. OneLogin tokens allows for 5000 requests
        every hour, but if the rate limit is reached, we can retrieve how long until we are clear.

        More information about this here:
            https://developers.onelogin.com/api-docs/1/oauth20-tokens/get-rate-limit

        Returns:
            int: Number of seconds that this function should sleep for between requests
        """
        return self._rate_limit_sleep

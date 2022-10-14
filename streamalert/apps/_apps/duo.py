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
import hashlib
import hmac
import re
import urllib.error
import urllib.parse
import urllib.request
from base64 import b64encode
from datetime import datetime

import requests

from . import AppIntegration, StreamAlertApp, get_logger

LOGGER = get_logger(__name__)


class DuoApp(AppIntegration):
    """Duo base app integration. This is subclassed for the auth and admin APIs"""
    # Duo's api returns a max of 1000 logs per request
    _MAX_RESPONSE_LOGS = 1000
    _ENDPOINT_PREFIX = '/admin/v1/logs/'

    @classmethod
    def _endpoint(cls):
        """Class method to return the endpoint to be used for this duo instance

        Returns:
            str: Path of the desired endpoint to query

        Raises:
            NotImplementedError: If the subclasses do not properly implement this method
        """
        raise NotImplementedError('Subclasses should implement the _endpoint method')

    @classmethod
    def service(cls):
        return 'duo'

    def _generate_auth(self, hostname, params):
        """Duo requests must be signed each time.

        This has been largely borrowed/updated from here:
            https://github.com/duosecurity/duo_client_python/blob/master/duo_client/admin.py
        """
        formatted_date = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S -0000')

        auth_string = '\n'.join(
            [formatted_date, 'GET', hostname,
             self._endpoint(),
             urllib.parse.urlencode(params)]).encode()

        try:
            signature = hmac.new(self._config.auth['secret_key'].encode(), auth_string,
                                 hashlib.sha1)
        # Since we force the auth_string and auth['secret_key'] to types which
        # support .encode(), we must expand the catch to include attribute
        # errors for mismatched types.
        except (TypeError, AttributeError):
            LOGGER.exception('Could not generate hmac signature')
            return False

        # Format the basic auth with integration key and the hmac hex digest
        basic_auth = ':'.join([self._config.auth['integration_key'],
                               signature.hexdigest()]).encode()

        return {
            'Date': formatted_date,
            'Authorization': f'Basic {b64encode(basic_auth).decode()}',
            'Host': hostname
        }

    def _gather_logs(self):
        """Gather the Duo log events."""
        hostname = self._config.auth['api_hostname']
        full_url = 'https://{hostname}{endpoint}'.format(hostname=hostname,
                                                         endpoint=self._endpoint())

        return self._get_duo_logs(hostname, full_url)

    def _get_duo_logs(self, hostname, full_url):
        """Get all logs from the endpoint for this timeframe

        Returns:
            [
                {
                    'access_device': {
                        'browser': 'Chrome',
                        'browser_version': '1.2.3',
                        'flash_version': 'uninstalled',
                        'java_version': 'uninstalled',
                        'os': 'Mac OS X',
                        'os_version': '10.15.3',
                        'trusted_endpoint_status': 'unknown'
                    },
                    'alias': '',
                    'device': '123-456-7890',
                    'factor': 'Duo Push',
                    'integration': 'web.site.com',
                    'ip': '1.1.1.1',
                    'location': {
                        'city': 'Portland',
                        'country': 'US',
                        'state': 'Oregon'
                    },
                    'new_enrollment': False,
                    'reason': 'User approved',
                    'result': 'SUCCESS',
                    'timestamp': 1581705165,
                    'username': 'user.name@site.com'
                }
            ]
        """
        # Get the last timestamp and add one to it to avoid duplicates
        # Sanity check mintime as unix timestamp, then transform to string
        params = {'mintime': str(int(self._last_timestamp + 1))}

        # Contstruct the headers for this request. Every request must be signed
        headers = self._generate_auth(hostname, params)
        if not headers:
            return False

        try:
            # Make the request to the api, resulting in a bool or dict
            result, response = self._make_get_request(full_url, headers=headers, params=params)
        except requests.exceptions.ConnectionError:
            LOGGER.exception('Received bad response from duo')
            return False

        if not result:
            return False

        # Duo stores the list of logs in the 'response' key of the response
        logs = response['response']
        if not logs:
            LOGGER.info('No logs in response from duo')
            return False

        # Get the timestamp from the latest event. Duo produces these sequentially
        # so we can just extract the timestamp from the last item in the list
        self._last_timestamp = logs[-1]['timestamp']

        # Check if the max amount of logs was returned with this request. If the value
        # is not the max, then we are done polling logs for this timeframe
        # Setting _more_to_poll to true here will allow the caller to try to poll again
        self._more_to_poll = len(logs) >= self._MAX_RESPONSE_LOGS

        # Return the list of logs to the caller so they can be send to the batcher
        return logs

    @classmethod
    def _required_auth_info(cls):
        return {
            'api_hostname': {
                'description': ('the API URL for your duosecurity instance. This should '
                                'be in a format similar to \'api-abcdef12.duosecurity.com\''),
                'format':
                re.compile(r'^api-[a-f0-9]{8}\.duosecurity\.com$')
            },
            'integration_key': {
                'description': ('the integration key for your duosecurity Admin API. This '
                                'should be in a format similar to \'DIABCDEFGHIJKLMN1234\''),
                'format':
                re.compile(r'^DI[A-Z0-9]{18}$')
            },
            'secret_key': {
                'description': ('the secret key for your duosecurity Admin API. This '
                                'should be a string of 40 alphanumeric characters'),
                'format':
                re.compile(r'^[a-zA-Z0-9]{40}$')
            }
        }

    def _sleep_seconds(self):
        """Return the number of seconds this polling function should sleep for
        between requests to avoid failed requests. Duo allows for 2 API requests
        every 1 minute, so this should sleep every 2 polls.

        Returns:
            int: Number of seconds that this function should sleep for between requests
        """
        return abs((self._poll_count % 2) - 1) * 60


@StreamAlertApp
class DuoAuthApp(DuoApp):
    """Duo authentication log app integration"""
    @classmethod
    def _type(cls):
        return 'auth'

    @classmethod
    def _endpoint(cls):
        """Class method to return the duo authentication log endpoint

        Returns:
            str: Path of the authentication endpoint to query
        """
        return f'{cls._ENDPOINT_PREFIX}authentication'


@StreamAlertApp
class DuoAdminApp(DuoApp):
    """Duo administrator log app integration"""
    @classmethod
    def _type(cls):
        return 'admin'

    @classmethod
    def _endpoint(cls):
        """Class method to return the duo administrator log endpoint

        Returns:
            str: Path of the administrator endpoint to query
        """
        return f'{cls._ENDPOINT_PREFIX}administrator'

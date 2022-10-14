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
import calendar
import re
import time
from datetime import datetime

import backoff
import requests

from . import AppIntegration, StreamAlertApp, get_logger

LOGGER = get_logger(__name__)


class SalesforceAppError(Exception):
    """Salesforce App Error class"""


class SalesforceApp(AppIntegration):
    """Salesforce StreamAlert Base App

    SalesforceApp will audit 5 types of event logs include 'Console', 'Login',
    'LoginAs', 'Report' and 'ReportExport' for user access audit and data loss
    prevention, although Salesforce provides 42 types of event logs.

    This base class will be inherited by different subclasssed based on different
    event types.

    Console events:
        contain information about the performance and use of Salesforce Consoles.

    Login events:
        contain details about your org's user login history.

    LoginAs events:
        contain details about what a Salesforce admin did while logged in as another user.

    Report events:
        contain information about what happened when a user ran a report and
        captures report's size.

    ReportExport:
        events contain details about reports that a user exported.
    """
    _SALESFORCE_TOKEN_URL = 'https://login.salesforce.com/services/oauth2/token'  # nosec
    _SALESFORCE_QUERY_URL = ('{instance_url}/services/data/v{api_version}/'
                             '{query}{start_time}{event_type}')
    # Use the Query resource to retrieve log files.
    _SALESFORCE_QUERY_FILTERS = ('query?q=SELECT+Id+,+EventType+,+LogFile+,+LogDate+,'
                                 '+LogFileLength+FROM+EventLogFile+')

    # Use "Where" and "LogDate" clause to filter log files which are generated after
    # last_timestamp.
    _SALESFORCE_CREATE_AFTER = 'WHERE+LogDate+>+{}+'

    _TIMEOUT = 15
    EXCEPTIONS_TO_BACKOFF = (SalesforceAppError, )
    BACKOFF_MAX_RETRIES = 3

    def __init__(self, event, context):
        super().__init__(event, context)
        self._auth_headers = None
        self._instance_url = None
        self._latest_api_version = 0
        self._current_time = int(calendar.timegm(time.gmtime()))

    @classmethod
    def _type(cls):
        raise NotImplementedError('Subclasses should implement the _type method')

    @classmethod
    def service(cls):
        return 'salesforce'

    @classmethod
    def date_formatter(cls):
        """Salesforce API date format: YYYY-MM-DDTHH:MM:SSZ"""
        return '%Y-%m-%dT%H:%M:%SZ'

    def _request_token(self):
        """Request OAuth token from salesforce

        Meanwhile, it will also get instance url which will be used in future
        requests. The instance url identifies the Salesforce instance to which
        API calls should be sent.

        Returns:
            bool: Returns True if update auth headers and instance url successfully.
        """
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        # required credentials when request for a token.
        data = {
            'grant_type': 'password',
            'client_id': self._config.auth['client_id'],
            'client_secret': self._config.auth['client_secret'],
            'username': self._config.auth['username'],
            'password': f"{self._config.auth['password']}{self._config.auth['security_token']}",
            'response_type': 'code',
            'redirect_uri': self._SALESFORCE_TOKEN_URL
        }

        success, response = self._make_post_request(self._SALESFORCE_TOKEN_URL, headers, data,
                                                    False)

        if not (success and response):
            return False

        if not (response.get('access_token') and response.get('instance_url')):
            LOGGER.error('Response invalid generating headers for service \'%s\'', self._type())
            return False

        bearer = f"Bearer {response.get('access_token')}"
        self._auth_headers = {'Content-Type': 'application/json', 'Authorization': bearer}
        self._instance_url = response.get('instance_url')
        LOGGER.debug('Successfully obtain OAuth token and instance URL')
        return True

    def _sleep_seconds(self):
        """Salesforce doesn't provide rate limit information. We can default it to 0"""
        return 0

    @classmethod
    def _required_auth_info(cls):
        """Required credentials for requesting OAuth token"""
        return {
            'client_id': {
                'description': ('The consumer key from the Salesforce connected App. '
                                'This should be a string of 85 alphanumeric and special '
                                'characters'),
                'format':
                re.compile(r'^[a-zA-Z0-9._#@]{85}$')
            },
            'client_secret': {
                'description': ('The consumer secret from the Salesforce connected App. '
                                'This should be a string of 19 numeric characters'),
                'format':
                re.compile(r'^[0-9]{19}$')
            },
            'username': {
                'description': ('The username of a user account. This should be an '
                                'Email address'),
                'format': re.compile(r'^[A-Za-z0-9-_.+]+@[A-Za-z0-9-.]+\.[A-Za-z]{2,}$')
            },
            'password': {
                'description': ('The password of a user account. This should be a '
                                'random string'),
                'format': re.compile(r'.*')
            },
            'security_token': {
                'description': ('The security token generated in user account. This '
                                'should be a string of 24 alphanumeric characters'),
                'format':
                re.compile(r'^[a-zA-Z0-9]{24}$')
            }
        }

    def _validate_status_code(self, resp):
        """Validate status code from get response

        Args:
            resp (Response): The response object from get request

        Returns:
            bool: Returns True if status_code is 200. Otherwise returns False,
                except
        """
        if resp.status_code == 200:
            return True
        if resp.status_code == 401:
            # The OAuth token used has expired or is invalid.
            # Retry to renew OAuth token
            LOGGER.error(
                'The OAuth token used has expired or is invalid. '
                'Error code %s, error message %s',
                resp.json().get('errorCode', None),
                resp.json().get('message', None))
            self._request_token()

            # Get request will retry when SalesforceAppError exception raised
            raise SalesforceAppError
        if resp.status_code == 403 and resp.json().get('errorCode') == 'REQUEST_LIMIT_EXCEEDED':
            # Exceeded API request limits in your org. Log this information for
            # future reference.
            LOGGER.error('Exceeded API request limits')
            return False
        if resp.status_code == 500:
            # Server internal error. Get request will retry.
            raise SalesforceAppError
        if resp.status_code > 200:
            LOGGER.error('Unexpected status code %d detected, error message %s', resp.status_code,
                         resp.json())
            return False

    def _make_get_request(self, full_url, headers, params=None):
        """Make GET request with backoff logic

        This method overrides the method in AppIntegration base class to handle
        not only JSON response, but also raw text response which is returned when
        send GET request to fetch event logs. Also, this class will trigger backoff
        when SalesforceAppError exception raised.

        Args:
            full_url (str): The full url of GET request.
            headers (dict): A dictionary includes bearer token.

        Returns:
            bool: True if GET response is valid.
            dict/string/None: If GET request to fetch log files and support API
                version list, it will return a dict. If it requests to fetch event
                logs, it will return raw text which can be decoded by CSV DictReader
                later. Otherwise it will return None.
        """
        @backoff.on_exception(backoff.expo,
                              self.EXCEPTIONS_TO_BACKOFF,
                              max_tries=self.BACKOFF_MAX_RETRIES)
        def _make_get_request():
            # To use closure here is to make backoff logic patchable and testable.
            try:
                # Log GET request URL for debugging purpose, especially useful when
                # debugging query syntax
                LOGGER.debug('URL of GET request is %s', full_url)
                resp = requests.get(full_url, headers=headers, params=params, timeout=self._TIMEOUT)

                # Return false if resp contains non-200 status code.
                return (True, resp.json()) if self._validate_status_code(resp) else (False, None)

            except requests.exceptions.Timeout:
                LOGGER.exception('Request timed out for when sending get request to %s', full_url)
                return False, None
            except ValueError:
                # When fetch log events, Salesforce returns raw data in csv format, not json
                return True, resp.text

        return _make_get_request()

    def _get_latest_api_version(self):
        """GET request to fetch supported API versions and find the latest API version

        The example of response json body:
        [
            {
                "version": "20.0",
                "label": "Winter '11",
                "url": "/services/data/v20.0"
            },
            {
                "version": "21.0",
                "label": "Spring '11",
                "url": "/services/data/v21.0"
            },
            {
                "version": "26.0",
                "label": "Winter '13",
                "url": "/services/data/v26.0"
            }
        ]

        Returns:
            bool: Return True if get latest api version successfully.
        """
        url = f'{self._instance_url}/services/data/'
        success, response = self._make_get_request(url, self._auth_headers)

        if not (success and response):
            LOGGER.error('Failed to fetch lastest api version')
            return False

        if versions := [float(version.get('version', 0)) for version in response]:
            self._latest_api_version = str(sorted(versions)[-1])
            if self._latest_api_version == '0.0':
                LOGGER.error('Failed to obtain latest API version')
                return False
            LOGGER.debug('Successfully obtain latest API version %s', self._latest_api_version)
            return True

    def _list_log_files(self):
        """Fetch a list of available log files by event types.

        An event generates log data in real time. However, log files are generated
        the day after an event takes place, during nonpeak hours. Therefore, log
        file data is unavailable for at least one day after an event.

        Returns:
            list: a list of log file location or empty list.

        An example of log files response json body:
        {
            "totalSize": 2,
            "done": True,
            "records": [
                {
                    "attributes": {
                        "type": "EventLogFile",
                        "url": "/services/data/v32.0/sobjects/EventLogFile/0ATD00001bROAQ"
                    },
                    "Id": "0ATD000000001bROAQ",
                    "EventType": "Console",
                    "LogFile": "/services/data/v32.0/sobjects/EventLogFile/0ATD00001bROAQ/LogFile",
                    "LogDate": "2014-03-14T00:00:00.000+0000",
                    "LogFileLength": 2692.0
                },
                {
                    "attributes": {
                        "type": "EventLogFile",
                        "url": "/services/data/v32.0/sobjects/EventLogFile/0ATD000000001SdOAI"
                    },
                    "Id": "0ATD000000001SdOAI",
                    "EventType": "Console",
                    "LogFile": "/services/data/v32.0/sobjects/EventLogFile/0ATD00001SdOAI/LogFile",
                    "LogDate": "2014-03-13T00:00:00.000+0000",
                    "LogFileLength": 1345.0
                }
            ]
        }
        """
        url = self._SALESFORCE_QUERY_URL.format(instance_url=self._instance_url,
                                                api_version=self._latest_api_version,
                                                query=self._SALESFORCE_QUERY_FILTERS,
                                                start_time=self._SALESFORCE_CREATE_AFTER.format(
                                                    self._last_timestamp),
                                                event_type=f"AND+EventType+=+\'{self._type()}\'")

        success, response = self._make_get_request(url, self._auth_headers)
        if not success:
            LOGGER.error('Failed to get a list of log files.')
            return

        log_files = []
        if response.get('records'):
            log_files.extend(
                [record['LogFile'] for record in response['records'] if record.get('LogFile')])

        LOGGER.debug('Retrived %d log files', len(log_files))
        return log_files

    def _fetch_event_logs(self, log_file_path):
        """Get event logs by sending GET request to each log file location.

        Args:
            log_file_path (str): log file location.

        Returns:
            list: a list of event logs or None.
        """
        url = f'{self._instance_url}/{log_file_path}'
        try:
            success, resp = self._make_get_request(url, self._auth_headers)
        except SalesforceAppError:
            LOGGER.exception('Failed to get event logs')
            return

        if not (success and resp):
            LOGGER.error('Failed to get event logs')
            return

        # skip header line before passing to the classifier function
        return resp.splitlines()[1:]

    def _gather_logs(self):
        """Gather all log events. There are 32 event types.

        Returns:
            list: A list of dictionaries contains log events.
        """
        if not (self._request_token() and self._get_latest_api_version()):
            return

        log_files = self._list_log_files()
        if not log_files:
            return

        logs = []
        for log_file_path in log_files:
            response = self._fetch_event_logs(log_file_path)
            logs.extend(response)

        # Update last_timestamp to lambda function starting time
        self._last_timestamp = datetime.utcfromtimestamp(self._current_time).strftime(
            self.date_formatter())
        return logs


@StreamAlertApp
class SalesforceConsole(SalesforceApp):
    """Salesforce Console Events app integration

    Console events contain information about the performance and use of Salesforce
    Consoles
    """
    @classmethod
    def _type(cls):
        return 'console'


@StreamAlertApp
class SalesforceLogin(SalesforceApp):
    """Salesforce Login Events app integration

    Login events contain details about your org's user login history
    """
    @classmethod
    def _type(cls):
        return 'login'


@StreamAlertApp
class SalesforceLoginAs(SalesforceApp):
    """Salesforce LoginAs Events app integration

    LoginAs events contain details about what a Salesforce admin did while logged
    in as another user
    """
    @classmethod
    def _type(cls):
        return 'loginas'


@StreamAlertApp
class SalesforceReport(SalesforceApp):
    """Salesforce Report Events app integration

    Report events contain information about what happened when a user ran a report
    """
    @classmethod
    def _type(cls):
        return 'report'


@StreamAlertApp
class SalesforceReportExport(SalesforceApp):
    """Salesforce ReportExport Events app integration

    ReportExport events contain details about reports that a user exported
    """
    @classmethod
    def _type(cls):
        return 'reportexport'

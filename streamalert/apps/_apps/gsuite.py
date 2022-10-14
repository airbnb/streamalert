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
import logging
import re
import socket
import ssl

import googleapiclient.discovery
import googleapiclient.errors
from google.auth.exceptions import GoogleAuthError
from google.oauth2 import service_account

from . import AppIntegration, StreamAlertApp, get_logger

LOGGER = get_logger(__name__)

# Disable noisy google api client logger
logging.getLogger('googleapiclient.discovery_cache').setLevel(logging.ERROR)


class GSuiteReportsApp(AppIntegration):
    """G Suite Reports base app integration. This is subclassed for various endpoints"""
    _SCOPES = ['https://www.googleapis.com/auth/admin.reports.audit.readonly']
    # A tuple of uncaught exceptions that the googleapiclient can raise
    _GOOGLE_API_EXCEPTIONS = (
        googleapiclient.errors.Error,
        GoogleAuthError,
        socket.timeout,
        ssl.SSLError,
    )

    # The maximum number of unique event ids to store that occur on the most
    # recent timestamp. These are used to de-duplicate events in the next poll.
    # This is limited by AWS SSM parameter store maximum of 4096 characters.
    _MAX_EVENT_IDS = 100

    def __init__(self, event, context):
        super().__init__(event, context)
        self._activities_service = None
        self._last_event_timestamp = None
        self._next_page_token = None
        self._last_run_event_ids = []

    @classmethod
    def _type(cls):
        raise NotImplementedError('Subclasses should implement the _type method')

    @classmethod
    def service(cls):
        return 'gsuite'

    @classmethod
    def date_formatter(cls):
        """Return a format string for a date, ie: 2010-10-28T10:26:35.000Z"""
        return '%Y-%m-%dT%H:%M:%S.%fZ'

    @classmethod
    def _load_credentials(cls, keydata):
        """Load ServiceAccountCredentials from Google service account JSON keyfile

        Args:
            keydata (dict): The loaded keyfile data from a Google service account
                JSON file

        Returns:
             google.oauth2.service_account.ServiceAccountCredentials: Instance of
                service account credentials for this discovery service
        """
        try:
            creds = service_account.Credentials.from_service_account_info(
                keydata,
                scopes=cls._SCOPES,
            )
        except (ValueError, KeyError):
            # This has the potential to raise errors. See: https://tinyurl.com/y8q5e9rm
            LOGGER.exception('[%s] Could not generate credentials from keyfile', cls.type())
            return False

        return creds

    def _create_service(self):
        """GSuite requests must be signed with the keyfile

        Returns:
            bool: True if the Google API discovery service was successfully established or False
                if any errors occurred during the creation of the Google discovery service,
        """
        LOGGER.debug('[%s] Creating activities service', self)

        if self._activities_service:
            LOGGER.debug('[%s] Service already instantiated', self)
            return True

        creds = self._load_credentials(self._config.auth['keyfile'])
        if not creds:
            return False

        delegation = creds.with_subject(self._config.auth['delegation_email'])
        try:
            resource = googleapiclient.discovery.build('admin',
                                                       'reports_v1',
                                                       credentials=delegation)
        except self._GOOGLE_API_EXCEPTIONS:
            LOGGER.exception('[%s] Failed to build discovery service', self)
            return False

        # The google discovery service 'Resource' class that is returned by
        # 'discovery.build' dynamically loads methods/attributes, so pylint will complain
        # about no 'activities' member existing without the below pylint comment
        self._activities_service = resource.activities()  # pylint: disable=no-member

        return True

    def _gather_logs(self):
        """Gather the G Suite Admin Report logs for this application type

        Returns:
            bool or list: If the execution fails for some reason, return False.
                Otherwise, return a list of activies for this application type.
        """
        if not self._create_service():
            return False

        # Cache the last event timestamp so it can be used for future requests
        if not self._next_page_token:
            self._last_event_timestamp = self._last_timestamp
            self._last_run_event_ids = self._context.get('last_event_ids', [])

        LOGGER.debug('[%s] Querying activities since %s', self, self._last_event_timestamp)
        LOGGER.debug('[%s] Using next page token: %s', self, self._next_page_token)
        LOGGER.debug('[%s] Last run event ids: %s', self, self._last_run_event_ids)

        activities_list = self._activities_service.list(userKey='all',
                                                        applicationName=self._type(),
                                                        startTime=self._last_event_timestamp,
                                                        pageToken=self._next_page_token)

        try:
            results = activities_list.execute()
        except self._GOOGLE_API_EXCEPTIONS:
            LOGGER.exception('[%s] Failed to execute activities listing', self)
            return False

        if not results:
            LOGGER.error('[%s] No results received from the G Suite API request', self)
            return False

        # Remove duplicate events present in the last time period.
        activities = [
            activity for activity in results.get('items', [])
            if activity['id']['uniqueQualifier'] not in set(self._last_run_event_ids)
        ]
        if not activities:
            LOGGER.info('[%s] No logs in response from G Suite API request', self)
            return False

        # The activity api returns logs in reverse chronological order, for some reason, and
        # therefore the newest log will be first in the list. This should only be updated
        # once during the first poll
        if not self._next_page_token:
            self._last_timestamp = activities[0]['id']['time']
            LOGGER.debug('[%s] Caching last timestamp: %s', self, self._last_timestamp)
            # Store the event ids with the most recent timestamp to de-duplicate them next time
            next_run_event_ids = [
                activity['id']['uniqueQualifier'] for activity in activities
                if activity['id']['time'] == self._last_timestamp
            ]
            self._context['last_event_ids'] = next_run_event_ids[:self._MAX_EVENT_IDS]
            if len(next_run_event_ids) > self._MAX_EVENT_IDS:
                LOGGER.warning('[%s] More than %d next_run_event_ids. Unable to de-duplicate: %s',
                               self, self._MAX_EVENT_IDS, next_run_event_ids[self._MAX_EVENT_IDS:])

        self._next_page_token = results.get('nextPageToken')
        self._more_to_poll = bool(self._next_page_token)

        return activities

    @classmethod
    def _required_auth_info(cls):
        # Use a validation function to ensure the file the user provides is valid
        def keyfile_validator(keyfile):
            """A JSON formatted (not p12) Google service account private key file key"""
            try:
                with open(keyfile.strip(), encoding="utf-8") as json_keyfile:
                    keydata = json.load(json_keyfile)
            except (OSError, ValueError):
                return False

            return keydata if cls._load_credentials(keydata) else False

        return {
            'keyfile': {
                'description': ('the path on disk to the JSON formatted Google '
                                'service account private key file'),
                'format':
                keyfile_validator
            },
            'delegation_email': {
                'description': 'the service account user email to delegate access to',
                'format': re.compile(r'^[A-Za-z0-9-_.+]+@[A-Za-z0-9-.]+\.[A-Za-z]{2,}$')
            }
        }

    def _sleep_seconds(self):
        """Return the number of seconds this polling function should sleep for
        between requests to avoid failed requests. The Google Admin API allows for
        5 queries per second. Since it is very unlikely we will hit that, and since
        we are using Google's api client for requests, this can default to 0.

        Resource(s):
            https://developers.google.com/admin-sdk/reports/v1/limits

        Returns:
            int: Number of seconds that this function should sleep for between requests
        """
        return 0


@StreamAlertApp
class GSuiteAccessTransparencyReports(GSuiteReportsApp):
    """G Suite Access Transparency  Report app integration"""
    @classmethod
    def _type(cls):
        return 'access_transparency'


@StreamAlertApp
class GSuiteAdminReports(GSuiteReportsApp):
    """G Suite Admin Activity Report app integration"""
    @classmethod
    def _type(cls):
        return 'admin'


@StreamAlertApp
class GSuiteCalendarReports(GSuiteReportsApp):
    """G Suite Calendar Activity Report app integration"""
    @classmethod
    def _type(cls):
        return 'calendar'


@StreamAlertApp
class GSuiteDriveReports(GSuiteReportsApp):
    """G Suite Drive Activity Report app integration"""
    @classmethod
    def _type(cls):
        return 'drive'


@StreamAlertApp
class GSuiteUserGCPReports(GSuiteReportsApp):
    """G Suite GCP Accounts Activity Report app integration"""
    @classmethod
    def _type(cls):
        return 'gcp'


@StreamAlertApp
class GSuiteGroupReports(GSuiteReportsApp):
    """G Suite Group Activity Report app integration"""
    @classmethod
    def _type(cls):
        return 'groups'


@StreamAlertApp
class GSuiteGroupEnterpriseReports(GSuiteReportsApp):
    """G Suite Groups Enterprise Activity Report app integration"""
    @classmethod
    def _type(cls):
        return 'groups_enterprise'


@StreamAlertApp
class GSuiteGPlusReports(GSuiteReportsApp):
    """G Suite Google Plus Activity Report app integration"""
    @classmethod
    def _type(cls):
        return 'gplus'


@StreamAlertApp
class GSuiteLoginReports(GSuiteReportsApp):
    """G Suite Login Activity Report app integration"""
    @classmethod
    def _type(cls):
        return 'login'


@StreamAlertApp
class GSuiteMeetGCPReports(GSuiteReportsApp):
    """G Suite meet Accounts Activity Report app integration"""
    @classmethod
    def _type(cls):
        return 'meet'


@StreamAlertApp
class GSuiteMobileReports(GSuiteReportsApp):
    """G Suite Mobile Activity Report app integration"""
    @classmethod
    def _type(cls):
        return 'mobile'


@StreamAlertApp
class GSuiteRulesReports(GSuiteReportsApp):
    """G Suite Rules Activity Report app integration"""
    @classmethod
    def _type(cls):
        return 'rules'


@StreamAlertApp
class GSuiteSAMLGCPReports(GSuiteReportsApp):
    """G Suite SAML Accounts Activity Report app integration"""
    @classmethod
    def _type(cls):
        return 'saml'


@StreamAlertApp
class GSuiteTokenReports(GSuiteReportsApp):
    """G Suite Token Activity Report app integration"""
    @classmethod
    def _type(cls):
        return 'token'


@StreamAlertApp
class GSuiteUserAccountsReports(GSuiteReportsApp):
    """G Suite User Accounts Activity Report app integration"""
    @classmethod
    def _type(cls):
        return 'user_accounts'

import calendar
import re
import time

import requests

from . import AppIntegration, StreamAlertApp, get_logger

LOGGER = get_logger(__name__)


@StreamAlertApp
class IntercomApp(AppIntegration):
    """Intercom StreamAlert app"""
    _INTERCOM_LOGS_URL = 'https://api.intercom.io/admins/activity_logs'

    def __init__(self, event, config):
        super().__init__(event, config)
        self._next_page = None

    @classmethod
    def _type(cls):
        return 'admin_activity_logs'

    @classmethod
    def service(cls):
        return 'intercom'

    @classmethod
    def _required_auth_info(cls):
        return {
            'token': {
                'description': 'the access token for this Intercom app',
                'format': re.compile(r'^dG9r([0-9A-Za-z+\/=]*)$')
            }
        }

    def _sleep_seconds(self):
        """Return the number of seconds this polling function should sleep for
        between requests to avoid failed requests. Intercom API allows for a default of 500 requests
        every minute, distributed over 10 seconds periods. This means for a default rate limit of
        500 per minute, you can send a maximum of 83 operations per 10 second period. It's unlikely
        we will hit that limit, so this can default to 0.

        Resource(s):
            https://developers.intercom.com/intercom-api-reference/reference#rate-limiting

        Returns:
            int: Number of seconds that this function should sleep for between requests
        """
        return 0

    def _gather_logs(self):
        # Generate headers
        headers = {
            'Authorization': f"Bearer {self._config.auth['token']}",
            'Accept': 'application/json'
        }

        # Results are paginated with a page url field provided that is used in subsequent queries.
        # If this field exists, make a a query to the page url, and if not, make a fresh query to
        # the default _INTERCOM_LOGS_URL with the required created_at_before and created_at_after
        # parameters
        if self._next_page:
            params = None
            url = self._next_page
        else:
            params = {
                'created_at_before': int(calendar.timegm(time.gmtime())),
                'created_at_after': self._last_timestamp
            }
            url = self._INTERCOM_LOGS_URL

        LOGGER.info("Requesting events from: %s params: %s", url, params)

        try:
            result, response = self._make_get_request(url, headers=headers, params=params)
        except requests.exceptions.ConnectionError:
            LOGGER.exception('Received bad response from Intercom')
            return False

        if not result:
            return False

        activities = [
            activity for activity in response['activity_logs']
            if int(activity['created_at']) > self._last_timestamp
        ]

        if not activities:
            return False

        # Save next page url if any for paginated results
        if response['pages']['next'] is not None:
            self._more_to_poll = True
            self._next_page = response['pages']['next']
        else:
            self._more_to_poll = False
            self._next_page = None

        most_recent_timestamp = max(int(activity['created_at']) for activity in activities)

        # Save most recent time stamp for the next query
        if most_recent_timestamp > self._last_timestamp:
            self._last_timestamp = most_recent_timestamp

        return activities

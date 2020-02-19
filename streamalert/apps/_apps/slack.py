"""
Copyright 2018-present, Airbnb, Inc.

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
import time

from . import AppIntegration, StreamAlertApp, get_logger


LOGGER = get_logger(__name__)


class SlackApp(AppIntegration):
    """SlackApp will collect 2 types of event logs: access logs and integration logs.

    This base class will be inherited by different subclasses based on different
    event types.

    Access logs:
        contain information about logins

    Integration logs:
        contain details about your workspace's integrated apps
    """

    _DEFAULT_REQUEST_TIMEOUT = 30
    _SLACK_API_BASE_URL = 'https://slack.com/api/'
    _SLACK_API_MAX_ENTRY_COUNT = 1000
    _SLACK_API_MAX_PAGE_COUNT = 100

    def __init__(self, event, context):
        super(SlackApp, self).__init__(event, context)
        self._next_page = 1

    @classmethod
    def _endpoint(cls):
        """Class method to return the endpoint to be used for this slack instance

        Returns:
            str: Path of the desired endpoint to query

        Raises:
            NotImplementedError: If the subclasses do not properly implement this method
        """
        raise NotImplementedError('Subclasses should implement the _endpoint method')

    @classmethod
    def _type(cls):
        raise NotImplementedError('Subclasses should implement the _type method')

    @classmethod
    def _sleep_seconds(cls):
        raise NotImplementedError('Subclasses should implement the _sleep_seconds method')

    @classmethod
    def service(cls):
        return 'slack'

    @classmethod
    def _required_auth_info(cls):
        """Required credentials for access to the workspace"""
        return {
            'auth_token': {
                'description': ('The security token generated by installing an app. '
                                'This should be a string of characters beginning with xoxp-'),
                'format': re.compile(r'^xoxp-[a-zA-Z0-9-]+$')
            }
        }

    def _check_for_more_to_poll(self, response):
        self._next_page += 1
        return not ('paging' in list(response.keys()) and
                    response['paging']['pages'] == response['paging']['page'])

    def _filter_response_entries(self, response):
        """The slack endpoints don't provide a programmatic way to filter for new results,
        so subclasses must implement their own endpoint specific filtering methods"""
        raise NotImplementedError("Subclasses must implement the _filter_response_entries method")

    def _get_request_data(self):
        """The Slack API takes additional parameters to its endpoints in the body of the request.
        Pagination control is one set of parameters.
        """
        return {
            'count': self._SLACK_API_MAX_ENTRY_COUNT,
            'page': self._next_page
        }

    def _gather_logs(self):
        """Gather log events.

        Returns:
            list: A list of dictionaries containing log events.
        """
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Authorization': 'Bearer {}'.format(self._config.auth['auth_token'])
        }

        data = self._get_request_data()

        url = '{}{}'.format(self._SLACK_API_BASE_URL, self._endpoint())
        success, response = self._make_post_request(url, headers, data, False)

        if not success:
            LOGGER.error('Received bad response from slack')
            return False

        if not response.get('ok'):
            LOGGER.error('Received error or warning from slack: %s', response.get('error'))
            return False

        self._more_to_poll = self._check_for_more_to_poll(response)

        results = self._filter_response_entries(response)

        self._last_timestamp = int(time.time())

        return results

@StreamAlertApp
class SlackAccessApp(SlackApp):
    """An app that collects the logs from the team.accessLogs endpoint on Slack.

    There are a couple of quirks with this endpoint. It returns one entry per unique
    combination of user/ip/user_agent, with the values date_first and date_last
    indicating the first and most recent access with this combination. Entries
    are sorted by date_first descending, meaning that the entire log must be collected
    to ensure that all possible updates are available.

    Results are paginated, with the count parameter of the api dictating the max number
    of results per page (max 1000) and the page parameter of the api dictating which page
    is requested (max 100).

    The result of a successful api call is json whose outermost schema is

    {
        "ok": True,
        "login": [entries],
        "pagination": {
            "count": <number of entries per page>,
            "total": <total number of entries>,
            "page": <current page of results>,
            "pages": <total number of pages of results>
        }
    }

    Resource:
        https://api.slack.com/methods/team.accessLogs
    """
    _SLACK_ACCESS_LOGS_ENDPOINT = 'team.accessLogs'

    def __init__(self, event, context):
        super(SlackAccessApp, self).__init__(event, context)
        self._before_time = None
        self._next_page = 1

    @classmethod
    def _type(cls):
        return 'access'

    @classmethod
    def _endpoint(cls):
        return cls._SLACK_ACCESS_LOGS_ENDPOINT

    def _filter_response_entries(self, response):
        if 'logins' in response:
            return [x for x in response['logins'] if x['date_last'] > self._last_timestamp]
        return False

    def _check_for_more_to_poll(self, response):
        """if we hit the maximum possible number of returned entries, there may still be more
        to check. Grab the `date_first` value of the oldest entry for the next round"""
        if (response['paging']['page'] >= self._SLACK_API_MAX_PAGE_COUNT and
                response['paging']['count'] >= self._SLACK_API_MAX_ENTRY_COUNT):
            self._before_time = response['logins'][-1]['date_first']
            self._next_page = 1
            return True

        self._next_page += 1
        return response['paging']['pages'] > response['paging']['page']

    def _get_request_data(self):
        data = {
            'count': self._SLACK_API_MAX_ENTRY_COUNT,
            'page': self._next_page
        }

        if self._before_time:
            data['before'] = self._before_time

        return data


    @classmethod
    def _sleep_seconds(cls):
        """Return the number of seconds this polling function should sleep for
        between requests to avoid failed requests. The Slack team.accessLog API
        has Tier 2 limiting, which is 20 requests per minute.

        Resource:
            http://api.slack.com/methods/team.accessLogs

        Returns:
            int: Number of seconds the polling function should sleep for
        """
        return 3


@StreamAlertApp
class SlackIntegrationsApp(SlackApp):
    """An app that collects the logs from the team.integrationLogs endpoint on Slack.

    Results are paginated, with the count parameter of the api dictating the max number
    of results per page (max 1000) and the page parameter of the api dictating which page
    is requested (max 100).

    The result of a successful api call is json whose outermost schema is

    {
        "ok": True,
        "logs": [entries],
        "pagination": {
            "count": <number of entries per page>,
            "total": <total number of entries>,
            "page": <current page of results>,
            "pages": <total number of pages of results>
        }
    }

    Resource:
        https://api.slack.com/methods/team.integrationLogs
    """
    _SLACK_INTEGRATION_LOG_ENDPOINT = 'team.integrationLogs'

    @classmethod
    def _type(cls):
        return 'integration'

    @classmethod
    def _endpoint(cls):
        return cls._SLACK_INTEGRATION_LOG_ENDPOINT

    def _filter_response_entries(self, response):
        if 'logs' in response:
            return [x for x in response['logs'] if int(x['date']) > self._last_timestamp]
        return False

    @classmethod
    def _sleep_seconds(cls):
        """Return the number of seconds this polling function should sleep for
        between requests to avoid failed requests. The Slack team.integrationLog API
        has Tier 2 limiting, which is 20 requests per minute.

        Resource:
            http://api.slack.com/methods/team.integrationLogs

        Returns:
            int: Number of seconds the polling function should sleep for
        """
        return 3

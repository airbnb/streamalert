"""
Copyright 2018-present Airbnb, Inc.

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
import re
from datetime import datetime

from aliyunsdkactiontrail.request.v20171204 import LookupEventsRequest
from aliyunsdkcore.acs_exception.exceptions import (ClientException,
                                                    ServerException)
from aliyunsdkcore.client import AcsClient

from . import AppIntegration, StreamAlertApp, get_logger

LOGGER = get_logger(__name__)


@StreamAlertApp
class AliyunApp(AppIntegration):
    """An app that collects events from the ActionTrail feature of Aliyun.

    Results are paginated, with a NextToken field provided that is used in subsequent queries.
    The result of a successful api call is json whose outermost schema is

    {
      "EndTime": <end of the time range of events>,
      "NextToken": <the token to use to request the next page of data>,
      "RequestId": <the ID of the request>,
      "StartTime": <start of the time range of events>,
      "Events": [entries],
    }

    If there are no more events in the queried range, the 'NextToken' element is not present.

    Resource:
        https://www.alibabacloud.com/help/doc-detail/28849.htm
    """

    # The maximum number of results to be returned. Valid values: 0 to 50.
    _MAX_RESULTS = 50

    # In aliyun sdk PR https://github.com/aliyun/aliyun-openapi-python-sdk/pull/216, it separates
    # timeout to connection and read timeout and also lower the default connection timeout time
    # from 10 to 5 seconds. We notice the connection to server gets timed out more often recently,
    # increase default timeout will be helpful.
    _CONNECT_TIMEOUT = 15
    _READ_TIMEOUT = 15

    def __init__(self, event, context):
        super().__init__(event, context)
        auth = self._config.auth
        self.client = AcsClient(auth['access_key_id'], auth['access_key_secret'], auth['region_id'])

        self.request = LookupEventsRequest.LookupEventsRequest()
        self.request.set_MaxResults(self._MAX_RESULTS)
        self.request.set_StartTime(self._config.last_timestamp)

        # Source code can be found here https://github.com/aliyun/aliyun-openapi-python-sdk/
        # blob/master/aliyun-python-sdk-actiontrail/aliyunsdkactiontrail/request/v20171204/
        # LookupEventsRequest.py
        self.request.set_EndTime(datetime.utcnow().strftime(self.date_formatter()))

        self.request.set_connect_timeout(self._CONNECT_TIMEOUT)
        self.request.set_read_timeout(self._READ_TIMEOUT)

    @classmethod
    def _type(cls):
        return 'actiontrail'

    @classmethod
    def service(cls):
        return 'aliyun'

    @classmethod
    def date_formatter(cls):
        """Return a format string for a date, ie: 2014-05-26T12:00:00Z

        This format is consistent with the format used by the Aliyun API:
            https://www.alibabacloud.com/help/doc-detail/28849.htm
        """
        return '%Y-%m-%dT%H:%M:%SZ'

    def _gather_logs(self):
        """Fetch ActionTrail events and return a list of events

        Example response from do_action_with_exception method

        {
          'EndTime': '2019-08-22T04:41:32Z',
          'NextToken': '2',
          'RequestId': '562D9C08-E766-4038-B49F-B0D2BE1980FE',
          'StartTime': '2019-08-01T04:31:52Z',
          'Events': [{
            'eventId': '60.152_1566447558068_1247',
            'eventVersion': '1',
            'acsRegion': 'cn-hangzhou',
            'additionalEventData': {
              'mfaChecked': 'true',
              'callbackUrl': 'https://home.console.aliyun.com/'
            },
            'eventType': 'ConsoleSignin',
            'errorMessage': 'success',
            'eventTime': '2019-08-22T04:19:18Z',
            'eventName': 'ConsoleSignin',
            'userIdentity': {
              'userName': 'dead_joke',
              'type': 'ram-user',
              'principalId': '222222222222222222',
              'accountId': '1111111111111111'
            },
            'eventSource': 'signin.aliyun.com',
            'requestId': '60.152_1566447558068_1247',
            'userAgent': 'some browser version',
            'sourceIpAddress': '1.1.1.1',
            'serviceName': 'AasSub'
          }, {
            'eventId': '029B39F0-5E23-4931-B4C9-BA72C7261ADF',
            ...
            'eventTime': '2019-08-21T22:26:09Z',
            ...
          }]
        }
        """
        try:
            response = self.client.do_action_with_exception(self.request)
            json_response = json.loads(response)

            # Note: ActionTrail API return ActionTrail events in sorted order, and
            # it is latest events first. There still has a small chance that it may not get
            # all the logs when there are still more logs to pull when lambda function
            # timeout reached, and remaining logs will be lost because the last_timestamp
            # is updated to "EndTime" during the first lambda function call.
            #
            # To lower the data loss possibility, suggest to have longer timeout for lambda
            # function (aliyun app) and set app schedule more frequently, e.g. every 10 mins
            self._last_timestamp = json_response['EndTime']
            if 'NextToken' in json_response:
                self._more_to_poll = True
                self.request.set_NextToken(json_response['NextToken'])
            else:
                self._more_to_poll = False
            return json_response['Events']

        except (ServerException, ClientException) as e:
            LOGGER.exception("%s error occurred", e.get_error_type())
            raise

    @classmethod
    def _required_auth_info(cls):
        """Required credentials for access to the resources"""
        def region_validator(region):
            """Region names pulled from https://www.alibabacloud.com/help/doc-detail/40654.htm"""

            if region in {
                    'cn-qingdao', 'cn-beijing', 'cn-zhangjiakou', 'cn-huhehaote', 'cn-hangzhou',
                    'cn-shanghai', 'cn-shenzhen', 'cn-hongkong', 'ap-southeast-1', 'ap-southeast-2',
                    'ap-southeast-3', 'ap-southeast-5', 'ap-northeast-1', 'ap-south-1', 'us-west-1',
                    'us-east-1', 'eu-central-1', 'me-east-1'
            }:
                return region
            return False

        return {
            'access_key_id': {
                'description': ('The access key id generated for a RAM user. This '
                                'should be a string of alphanumeric characters.'),
                'format':
                re.compile(r'.*')
            },
            'access_key_secret': {
                'description': ('The access key secret generated for a RAM user. This '
                                'should be a string of alphanumeric characters.'),
                'format':
                re.compile(r'.*')
            },
            'region_id': {
                'description': ('The region for the Aliyun API. This should be '
                                'a string like \'ap-northeast-1\'.'),
                'format':
                region_validator
            },
        }

    @classmethod
    def _sleep_seconds(cls): # pylint: disable=arguments-differ
        """Return the number of seconds this polling function should sleep for
        between requests to avoid failed requests. The Aliyun documentation doesn't
        list limits on the requests portion of the actionTrail feature, so the only
        limit is the general limit on Aliyun API requests, which is no more than
        100 per second. We can set this value to 0 safely.

        Resource:
            https://www.alibabacloud.com/help/doc-detail/29474.htm

        Returns:
            int: Number of seconds the polling function should sleep for
        """
        return 0

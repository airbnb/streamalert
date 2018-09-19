"""
Copyright 2018-present, Airbnb Inc.

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

from aliyunsdkcore.client import AcsClient
from aliyunsdkcore.acs_exception.exceptions import ServerException, ClientException
from aliyunsdkactiontrail.request.v20171204 import LookupEventsRequest

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

    _MAX_RESULTS = 50

    def __init__(self, event, context):
        super(AliyunApp, self).__init__(event, context)
        auth = self._config.auth
        self.client = AcsClient(auth['access_key_id'], auth['access_key_secret'], auth['region_id'])

        self.request = LookupEventsRequest.LookupEventsRequest()
        self.request.set_MaxResults(self._MAX_RESULTS)
        self.request.set_StartTime(self._config.last_timestamp)

    @classmethod
    def _type(cls):
        return 'actiontrail'

    @classmethod
    def service(cls):
        return 'aliyun'

    @classmethod
    def date_formatter(cls):
        """Return a format string for a date, ie: 2014-05-26T12:00:00Z

        This format is consisten with the format used by the Aliyun API:
            https://www.alibabacloud.com/help/doc-detail/28849.htm
        """
        return '%Y-%m-%dT%H:%M:%SZ'

    def _gather_logs(self):

        try:
            response = self.client.do_action_with_exception(self.request)
            json_response = json.loads(response)
            if 'NextToken' in json_response:
                self._more_to_poll = True
                self.request.set_NextToken(json_response['NextToken'])
            else:
                self._more_to_poll = False
                self._last_timestamp = json_response['EndTime']

            return json_response['Events']

        except (ServerException, ClientException) as e:
            LOGGER.exception("%s error occurred", e.get_error_type())
            return False

    @classmethod
    def _required_auth_info(cls):
        """Required credentials for access to the resources"""

        def region_validator(region):
            """Region names pulled from https://www.alibabacloud.com/help/doc-detail/40654.htm"""

            if region in {'cn-qingdao', 'cn-beijing', 'cn-zhangjiakou', 'cn-huhehaote',
                          'cn-hangzhou', 'cn-shanghai', 'cn-shenzhen', 'cn-hongkong',
                          'ap-southeast-1', 'ap-southeast-2', 'ap-southeast-3', 'ap-southeast-5',
                          'ap-northeast-1', 'ap-south-1', 'us-west-1', 'us-east-1',
                          'eu-central-1', 'me-east-1'}:
                return region
            return False

        return {
            'access_key_id': {
                'description': ('The access key id generated for a RAM user. This '
                                'should be a string of alphanumeric characters.'),
                'format': re.compile(r'.*')
            },
            'access_key_secret': {
                'description': ('The access key secret generated for a RAM user. This '
                                'should be a string of alphanumeric characters.'),
                'format': re.compile(r'.*')
            },
            'region_id': {
                'description': ('The region for the Aliyun API. This should be '
                                'a string like \'ap-northeast-1\'.'),
                'format': region_validator
            },
        }

    @classmethod
    def _sleep_seconds(cls):
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

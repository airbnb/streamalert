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
from aliyunsdkcore.acs_exception.exceptions import ClientException
from aliyunsdkcore.acs_exception.exceptions import ServerException
from aliyunsdkactiontrail.request.v20171204 import LookupEventsRequest

from app_integrations import LOGGER
from app_integrations.apps.app_base import StreamAlertApp, AppIntegration

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

    _PAGE_SIZE = 50

    def __init__(self, config):
        super(AliyunApp, self).__init__(config)
        self._next_token = None

    @classmethod
    def _type(cls):
        return 'events'

    @classmethod
    def service(cls):
        return 'aliyun'


    #@classmethod
    #def date_formatter(cls):
    #    """Return a format string for a date, ie: 2014-05-26T12:00:00Z

    #    This format is consisten with the format used by the Aliyun API:
    #        https://www.alibabacloud.com/help/doc-detail/28849.htm
    #    """
    #    return '%y-%m-%dT%h:%m:%sZ'

    def _gather_logs(self):
        auth = self._config.auth
        client = AcsClient(auth['access_key_id'], auth['access_key_secret'], auth['region_id'])

        request = LookupEventsRequest.LookupEventsRequest()
        request.set_MaxResults(self._PAGE_SIZE)
        request.set_StartTime = self._last_timestamp
        if self._next_token:
            request.set_NextToken(self._next_token)

        try:
            response = client.do_action_with_exception(request)
            json_response = json.loads(response)
            if 'NextToken' in json_response:
                self._more_to_poll = True
                self._next_token = json_response['NextToken']
            else:
                self._more_to_poll = False
                self._last_timestamp = json_response['EndTime']

            return json_response['Events']

        except ServerException as e:
            LOGGER.exception("Server Exception: %s", str(e))
            return False
        except ClientException as e:
            LOGGER.exception("Client Exception: %s", str(e))
            return False

    @classmethod
    def _required_auth_info(cls):
        """Required credentials for access to the resources"""
        #TODO: support more regions, and lay out documentation for which regions are supported.
        return {
            'access_key_id': {
                'description': ('The access key id generated for a RAM user.'),
                'format': re.compile(r'.*')
                },
            'access_key_secret': {
                'description': ('The access key secret generated for a RAM user.'),
                'format': re.compile(r'.*')
                },
            'region_id': {
                'description': ('The region identifier to collect data from.'),
                'format': lambda x: x == 'ap-northeast-1'
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

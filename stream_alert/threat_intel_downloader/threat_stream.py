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
from datetime import datetime, timedelta
import json

import backoff
import boto3
from botocore.exceptions import ClientError
import requests

from stream_alert.shared.backoff_handlers import (
    backoff_handler,
    success_handler,
    giveup_handler
)

from stream_alert.threat_intel_downloader import LOGGER
from stream_alert.threat_intel_downloader.exceptions import (
    ThreatStreamCredsError,
    ThreatStreamRequestsError
)

class ThreatStream(object):
    """Class to retrieve IOCs from ThreatStream.com and store them in DynamoDB"""
    _API_URL = 'https://api.threatstream.com'
    _API_RESOURCE = 'intelligence'
    _IOC_STATUS = 'active'
    # max IOC objects received from one API call, default is 0 (equal to 1000)
    _API_MAX_LIMIT = 1000
    _API_MAX_INDEX = 500000
    _PARAMETER_NAME = 'threat_intel_downloader_api_creds'

    EXCEPTIONS_TO_BACKOFF = (requests.exceptions.Timeout,
                             requests.exceptions.ConnectionError,
                             requests.exceptions.ChunkedEncodingError,
                             ThreatStreamRequestsError)
    BACKOFF_MAX_RETRIES = 3

    def __init__(self, config):
        self.ioc_types = config['ioc_types']
        self.ioc_sources = config['ioc_filters']
        self.threshold = self._API_MAX_INDEX - self._API_MAX_LIMIT
        self.region = config['region']
        self.ioc_keys = config['ioc_keys']
        self.api_user = None
        self.api_key = None
        self._get_api_creds()
        self.table_name = config['function_name']

    def _get_api_creds(self):
        """Retrieve ThreatStream API credentials from Parameter Store"""
        try:
            ssm = boto3.client('ssm', self.region)
            response = ssm.get_parameters(
                Names=[self._PARAMETER_NAME], WithDecryption=True
            )
        except ClientError as err:
            LOGGER.error('SSM client error: %s', err)
            raise

        for cred in response['Parameters']:
            if cred['Name'] == self._PARAMETER_NAME:
                try:
                    decoded_creds = json.loads(cred['Value'])
                    self.api_user = decoded_creds['api_user']
                    self.api_key = decoded_creds['api_key']
                except ValueError:
                    LOGGER.error('Can not load value for parameter with '
                                 'name \'%s\'. The value is not valid json: '
                                 '\'%s\'', cred['Name'], cred['Value'])
                    raise ThreatStreamCredsError('ValueError')

        if not (self.api_user and self.api_key):
            LOGGER.error('API Creds Error')
            raise ThreatStreamCredsError('API Creds Error')

    @backoff.on_exception(backoff.constant,
                          EXCEPTIONS_TO_BACKOFF,
                          max_tries=BACKOFF_MAX_RETRIES,
                          on_backoff=backoff_handler,
                          on_success=success_handler,
                          on_giveup=giveup_handler)
    def _connect(self, next_url):
        """Send API call to ThreatStream with next token and return parsed IOCs

        The API call has retry logic up to 3 times.
        Args:
            next_url (str): url of next token to retrieve more objects from
                ThreatStream

        Returns:
            (tuple): (list, str, bool)
                - First object is a list of intelligence.
                - Second object is a string of next token to retrieve more IOCs.
                - Third object is bool to indicated if retrieve more IOCs from
                    threat feed.
                    Return False if next token is empty or threshold of number
                    of IOCs is reached.
        """
        continue_invoke = False
        intelligence = list()

        https_req = requests.get('{}{}'.format(self._API_URL, next_url),
                                 timeout=10)
        if https_req.status_code == 200:
            data = https_req.json()
            if data.get('objects'):
                intelligence.extend(self._process_data(data['objects']))
            LOGGER.info('IOC Offset: %d', data['meta']['offset'])
            if not (data['meta']['next']
                    and data['meta']['offset'] < self.threshold):
                LOGGER.debug('Either next token is empty or IOC offset '
                             'reaches threshold %d. Stop retrieve more '
                             'IOCs.', self.threshold)
                continue_invoke = False
            else:
                next_url = data['meta']['next']
                continue_invoke = True
        elif https_req.status_code == 401:
            raise ThreatStreamRequestsError('Response status code 401, unauthorized.')
        elif https_req.status_code == 500:
            raise ThreatStreamRequestsError('Response status code 500, retry now.')
        else:
            raise ThreatStreamRequestsError('Unknown status code {}, '
                                            'do not retry.'.format(https_req.status_code)
                                           )

        return (intelligence, next_url, continue_invoke)

    def runner(self, event):
        """Process URL before making API call
        Args:
            event (dict): Contains lambda function invocation information. Initially,
                Threat Intel Downloader lambda funciton is invoked by Cloudwatch
                event. 'next_url' key will be inserted to event lambda function
                invokes itself to retrieve more IOCs.

        Returns:
            (tuple): (list, str, bool)
                - First object is a list of intelligence.
                - Second object is a string of next token to retrieve more IOCs.
                - Third object is bool to indicated if retrieve more IOCs from
                    threat feed.
        """
        if not event:
            return None, None, False

        next_url = event.get(
            'next_url',
            '/api/v2/{}/?username={}&api_key={}&status={}&limit={}'.format(
                self._API_RESOURCE,
                self.api_user,
                self.api_key,
                self._IOC_STATUS,
                self._API_MAX_LIMIT
            )
        )

        if not next_url:
            return None, None, False

        return self._connect(next_url)

    @staticmethod
    def _epoch_time(time_str, days=90):
        """Convert expiration time (in UTC) to epoch time
        Args:
            time_str (str): expiration time in string format
                Example: '2017-12-19T04:45:18.412Z'
            days (int): default expiration days which 90 days from now

        Returns:
            (int): Epoch time. If no expiration time presented, return to
                default value which is current time + 90 days.
        """

        if not time_str:
            return int((datetime.now()
                        + timedelta(days)
                        - datetime.utcfromtimestamp(0)).total_seconds())

        try:
            utc_time = datetime.strptime(time_str, "%Y-%m-%dT%H:%M:%S.%fZ")
            return int((utc_time - datetime.utcfromtimestamp(0)).total_seconds())
        except ValueError:
            LOGGER.error('Cannot convert expiration date \'%s\' to epoch time',
                         time_str)
            raise

    def _process_data(self, data):
        """Process and filter data by sources and keys
        Args:
            data (list): A list contains ioc information
                Example:
                    [
                        {
                            'value': 'malicious_domain.com',
                            'itype': 'c2_domain',
                            'source': 'crowdstrike',
                            'type': 'domain',
                            'expiration_ts': '2017-12-19T04:45:18.412Z',
                            'key1': 'value1',
                            'key2': 'value2',
                            ...
                        },
                        {
                            'value': 'malicious_domain2.com',
                            'itype': 'c2_domain',
                            'source': 'ioc_source2',
                            'type': 'domain',
                            'expiration_ts': '2017-12-31T04:45:18.412Z',
                            'key1': 'value1',
                            'key2': 'value2',
                            ...
                        }
                    ]

        Returns:
            (list): A list of dict contains useful IOC information
                Example:
                    [
                        {
                            'value': 'malicious_domain.com',
                            'itype': 'c2_domain',
                            'source': 'crowdstrike',
                            'type': 'domain',
                            'expiration_ts': 1513658718,
                        }
                    ]
        """
        results = list()
        for obj in data:
            for source in self.ioc_sources:
                if source in obj['source'].lower() and obj['type'] in self.ioc_types:
                    filtered_obj = {key: value for key, value in obj.iteritems()
                                    if key in self.ioc_keys}
                    filtered_obj['expiration_ts'] = self._epoch_time(filtered_obj['expiration_ts'])
                    results.append(filtered_obj)
        return results

    def write_to_dynamodb_table(self, intelligence):
        """Store IOCs to DynamoDB table"""
        try:
            dynamodb = boto3.resource('dynamodb', region_name=self.region)
            table = dynamodb.Table(self.table_name)
            with table.batch_writer() as batch:
                for ioc in intelligence:
                    batch.put_item(
                        Item={
                            'ioc_value': ioc['value'],
                            'ioc_type': ioc['type'],
                            'sub_type': ioc['itype'],
                            'source': ioc['source'],
                            'expiration_ts': ioc['expiration_ts']
                        }
                    )
        except ClientError as err:
            LOGGER.debug('DynamoDB client error: %s', err)
            raise

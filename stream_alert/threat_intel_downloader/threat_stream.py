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
import boto3
from botocore.exceptions import ClientError
import requests

from stream_alert.threat_intel_downloader import LOGGER
from stream_alert.threat_intel_downloader.exceptions import ThreatStreamCredsError

class ThreatStream(object):
    """Class to retrieve IOCs from ThreatStream.com and store them in DynamoDB"""
    API_URL = 'https://api.threatstream.com'
    API_RESOURCE = 'intelligence'
    IOC_STATUS = 'active'
    # max IOC objects received from one API call, default is 0 (equal to 1000)
    API_MAX_LIMIT = 1000
    MAX_INDEX = 1000000
    API_USER = 'api_user'
    API_KEY = 'api_key'
    TABLE_NAME = 'test_table_name'
    MAX_RETRY = 3

    def __init__(self, ioc_types, region='us-east-1'):
        self.ioc_types = ioc_types
        self.ioc_sources = set(['crowdstrike', '@airbnb.com'])
        self.threshold = self.MAX_INDEX - self.API_MAX_LIMIT
        self.region = region
        self.api_user = None
        self.api_key = None
        self._get_api_creds()
        self.table_name = self.TABLE_NAME

    def _get_api_creds(self):
        """Retrieve ThreatStream API credentials from Parameter Store"""
        try:
            ssm = boto3.client('ssm', self.region)
            response = ssm.get_parameters(
                Names=[self.API_USER, self.API_KEY], WithDecryption=True
            )
            for cred in response['Parameters']:
                if cred['Name'] == self.API_USER:
                    self.api_user = cred['Value']
                elif cred['Name'] == self.API_KEY:
                    self.api_key = cred['Value']
        except ClientError as err:
            LOGGER.debug('SSM client error: %s', err)
            raise

        if not (self.api_user and self.api_key):
            LOGGER.debug('API Creds Error')
            raise ThreatStreamCredsError


    def _connect(self, next_url):
        """Send API call to ThreatStream with next token and return parsed IOCs

        The API call has retry logic up to 3 times.
        Args:
            next_url (str): url of next token to retrieve more objects from
                ThreatStream

        Returns:
            intelligence (list): List of IOCs in the format
                [
                    ['malicious_domain.com', 'c2_domain', 'ioc_source'],
                    ['malicious_domain2.com', 'c2_domain', 'ioc_source2']
                ]
            next_url (str): Next token to retrieve more IOCs
            continue_invoke (bool): Returns False if next token is empty or
                threshold of number of IOCs is reached. Return True if more IOCs
                can be retrievd.
        """
        retry, retry_num, continue_invoke = True, self.MAX_RETRY, False
        intelligence = list()
        while retry:
            if retry_num == 0:
                return intelligence, next_url, False
            try:
                https_req = requests.get('{}{}'.format(self.API_URL, next_url),
                                         timeout=10)
                if https_req.status_code == 200:
                    data = https_req.json()
                    if data.get('objects'):
                        intelligence.extend(self._process_data(data['objects']))
                    LOGGER.debug('offset: %d', data['meta']['offset'])
                    if not (data['meta']['next']
                            and data['meta']['offset'] < self.threshold):
                        retry, continue_invoke = False, False
                    else:
                        next_url = data['meta']['next']
                        continue_invoke = True
                    retry = False
                elif https_req.status_code == 500:
                    retry_num -= 1
                    continue
                else:
                    return intelligence, next_url, continue_invoke
            except (requests.exceptions.Timeout,
                    requests.exceptions.ConnectionError,
                    requests.exceptions.ChunkedEncodingError):
                retry_num -= 1
                continue
        return (intelligence, next_url, continue_invoke)

    def runner(self, event):
        """Method to process threatstream url before making API call"""
        if not event:
            return None, None, False

        next_url = None
        if 'next_url' not in event:
            next_url = '/api/v2/{}/?username={}&api_key={}&status={}&limit={}'\
                .format(self.API_RESOURCE,
                        self.api_user,
                        self.api_key,
                        self.IOC_STATUS,
                        self.API_MAX_LIMIT)
        else:
            next_url = event.get('next_url', None)

        if not next_url:
            return None, None, False

        return self._connect(next_url)

    def _process_data(self, data):
        """Process and filter data by sources
        Args:
            data (list): A list contains ioc information
                Example:
                    [
                        {
                            'value': 'malicious_domain.com',
                            'itype': 'c2_domain',
                            'source': 'ioc_source',
                            'type': 'domain'
                        },
                        {
                            'value': 'malicious_domain2.com',
                            'itype': 'c2_domain',
                            'source': 'ioc_source2',
                            'type': 'domain'
                        }
                    ]

        Returns:
            (list): A dictionary includes IOCs with value, itype, source info
                Example:
                    [
                        ['malicious_domain.com', 'domain','c2_domain', 'ioc_source'],
                        ['malicious_domain2.com', 'domain', 'c2_domain', 'ioc_source2']
                    ]
        """
        results = list()
        for obj in data:
            for source in self.ioc_sources:
                if source in obj['source'].lower() and obj['type'] in self.ioc_types:
                    results.append([obj['value'], obj['type'], obj['itype'], obj['source']])
        return results

    def write_to_dynamodb_table(self, intelligence):
        """Store IOCs to DynamoDB table"""
        dynamodb = boto3.resource('dynamodb', region_name=self.region)
        table = dynamodb.Table(self.table_name)
        with table.batch_writer() as batch:
            for value, ioc_type, sub_type, source in intelligence:
                batch.put_item(
                    Item={
                        'value': value,
                        'sub_type': sub_type,
                        'type': ioc_type,
                        'source': source
                    }
                )

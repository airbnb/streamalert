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
from datetime import datetime, timedelta

import backoff
import boto3
import requests
from botocore.exceptions import ClientError

from streamalert.shared.backoff_handlers import (backoff_handler,
                                                 giveup_handler,
                                                 success_handler)
from streamalert.shared.config import load_config, parse_lambda_arn
from streamalert.shared.logger import get_logger
from streamalert.threat_intel_downloader.exceptions import (
    ThreatStreamCredsError, ThreatStreamLambdaInvokeError,
    ThreatStreamRequestsError)

LOGGER = get_logger(__name__)


class ThreatStream:
    """Class to retrieve IOCs from ThreatStream.com and store them in DynamoDB"""
    _API_URL = 'https://api.threatstream.com'
    _API_RESOURCE = 'intelligence'
    _IOC_STATUS = 'active'
    # max IOC objects received from one API call, default is 0 (equal to 1000)
    _API_MAX_LIMIT = 1000
    _API_MAX_INDEX = 500000
    # Remaining time in seconds before lambda termination
    _END_TIME_BUFFER = 5
    CRED_PARAMETER_NAME = 'threat_intel_downloader_api_creds'

    EXCEPTIONS_TO_BACKOFF = (requests.exceptions.Timeout, requests.exceptions.ConnectionError,
                             requests.exceptions.ChunkedEncodingError, ThreatStreamRequestsError)
    BACKOFF_MAX_RETRIES = 3

    def __init__(self, function_arn, timing_func):
        self._config = self._load_config(function_arn)
        self.timing_func = timing_func
        self.api_user = None
        self.api_key = None

    @staticmethod
    def _load_config(function_arn):
        """Load the Threat Intel Downloader configuration from conf/lambda.json file

        Returns:
            (dict): Configuration for Threat Intel Downloader

        Raises:
            ConfigError: For invalid or missing configuration files.
        """

        base_config = parse_lambda_arn(function_arn)
        config = load_config(include={'lambda.json'})['lambda']
        base_config.update(config.get('threat_intel_downloader_config', {}))
        return base_config

    def _load_api_creds(self):
        """Retrieve ThreatStream API credentials from Parameter Store"""
        if self.api_user and self.api_key:
            return  # credentials already loaded from SSM

        try:
            ssm = boto3.client('ssm', self.region)
            response = ssm.get_parameter(Name=self.CRED_PARAMETER_NAME, WithDecryption=True)
        except ClientError:
            LOGGER.exception('Failed to get SSM parameters')
            raise

        if not response:
            raise ThreatStreamCredsError('Invalid response')

        try:
            decoded_creds = json.loads(response['Parameter']['Value'])
        except ValueError as e:
            raise ThreatStreamCredsError(
                f"Cannot load value for parameter with name '{response['Parameter']['Name']}'. "
                f"The value is not valid json: '{response['Parameter']['Value']}'"
            ) from e


        self.api_user = decoded_creds['api_user']
        self.api_key = decoded_creds['api_key']

        if not (self.api_user and self.api_key):
            raise ThreatStreamCredsError('API Creds Error')

    @backoff.on_exception(backoff.constant,
                          EXCEPTIONS_TO_BACKOFF,
                          max_tries=BACKOFF_MAX_RETRIES,
                          on_backoff=backoff_handler(),
                          on_success=success_handler(),
                          on_giveup=giveup_handler())
    def _connect(self, next_url):
        """Send API call to ThreatStream with next token and return parsed IOCs

        The API call has retry logic up to 3 times.
        Args:
            next_url (str): url of next token to retrieve more objects from
                ThreatStream
        """
        intelligence = []
        https_req = requests.get(f'{self._API_URL}{next_url}', timeout=10)

        next_url = None
        if https_req.status_code == 200:
            data = https_req.json()
            if data.get('objects'):
                intelligence.extend(self._process_data(data['objects']))

            LOGGER.info('IOC Offset: %d', data['meta']['offset'])
            if not (data['meta']['next'] and data['meta']['offset'] < self.threshold):
                LOGGER.debug(
                    'Either next token is empty or IOC offset reaches threshold '
                    '%d. Stop retrieve more IOCs.', self.threshold)
            else:
                next_url = data['meta']['next']
        elif https_req.status_code == 401:
            raise ThreatStreamRequestsError('Response status code 401, unauthorized.')
        elif https_req.status_code == 500:
            raise ThreatStreamRequestsError('Response status code 500, retry now.')
        else:
            raise ThreatStreamRequestsError(
                f'Unknown status code {https_req.status_code}, do not retry.')

        self._finalize(intelligence, next_url)

    def _finalize(self, intel, next_url):
        """Finalize the execution

        Send data to dynamo and continue the invocation if necessary.

        Arguments:
            intel (list): List of intelligence to send to DynamoDB
            next_url (str): Next token to retrieve more IOCs
            continue_invoke (bool): Whether to retrieve more IOCs from
                threat feed. False if next token is empty or threshold of number
                of IOCs is reached.
        """
        if intel:
            LOGGER.info('Write %d IOCs to DynamoDB table', len(intel))
            self._write_to_dynamodb_table(intel)

        if next_url and self.timing_func() > self._END_TIME_BUFFER * 1000:
            self._invoke_lambda_function(next_url)

        LOGGER.debug("Time remaining (MS): %s", self.timing_func())

    def _invoke_lambda_function(self, next_url):
        """Invoke lambda function itself with next token to continually retrieve IOCs"""
        LOGGER.debug('This invocation is invoked by lambda function self.')
        lambda_client = boto3.client('lambda', region_name=self.region)
        try:
            lambda_client.invoke(FunctionName=self._config['function_name'],
                                 InvocationType='Event',
                                 Payload=json.dumps({'next_url': next_url}),
                                 Qualifier=self._config['qualifier'])
        except ClientError as err:
            raise ThreatStreamLambdaInvokeError(f'Error invoking function: {err}') from err

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
            return int((datetime.utcnow() + timedelta(days) -
                        datetime.utcfromtimestamp(0)).total_seconds())

        try:
            utc_time = datetime.strptime(time_str, "%Y-%m-%dT%H:%M:%S.%fZ")
            return int((utc_time - datetime.utcfromtimestamp(0)).total_seconds())
        except ValueError:
            LOGGER.error('Cannot convert expiration date \'%s\' to epoch time', time_str)
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
        results = []
        for obj in data:
            for source in self.ioc_sources:
                if source in obj['source'].lower():
                    filtered_obj = {
                        key: value
                        for key, value in obj.items() if key in self.ioc_keys
                    }
                    filtered_obj['expiration_ts'] = self._epoch_time(filtered_obj['expiration_ts'])
                    results.append(filtered_obj)
        return results

    def _write_to_dynamodb_table(self, intelligence):
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
                        })
        except ClientError as err:
            LOGGER.debug('DynamoDB client error: %s', err)
            raise

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
        event = event or {}

        self._load_api_creds()

        query = '(status="{}")+AND+({})+AND+NOT+({})'.format(
            self._IOC_STATUS, "+OR+".join([f'type="{ioc}"' for ioc in self.ioc_types]),
            "+OR+".join([f'itype="{itype}"' for itype in self.excluded_sub_types]))

        next_url = event.get(
            'next_url',
            f'/api/v2/{self._API_RESOURCE}/?username={self.api_user}&api_key={self.api_key}&limit={self._API_MAX_LIMIT}&q={query}'
        )

        self._connect(next_url)

    @property
    def excluded_sub_types(self):
        return self._config['excluded_sub_types']

    @property
    def ioc_keys(self):
        return self._config['ioc_keys']

    @property
    def ioc_sources(self):
        return self._config['ioc_filters']

    @property
    def ioc_types(self):
        return self._config['ioc_types']

    @property
    def region(self):
        return self._config['region']

    @property
    def table_name(self):
        return self._config['function_name']

    @property
    def threshold(self):
        return self._API_MAX_INDEX - self._API_MAX_LIMIT


def handler(event, context):
    """Lambda handler"""
    ThreatStream(context.invoked_function_arn, context.get_remaining_time_in_millis).runner(event)

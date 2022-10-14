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
from collections import defaultdict
from os import environ as env

import backoff
import boto3
from boto3.dynamodb.types import TypeDeserializer
from botocore.exceptions import ClientError, ParamValidationError
from netaddr import IPNetwork

from streamalert.shared.backoff_handlers import (backoff_handler,
                                                 giveup_handler,
                                                 success_handler)
from streamalert.shared.logger import get_logger
from streamalert.shared.normalize import Normalizer
from streamalert.shared.utils import in_network, valid_ip

LOGGER = get_logger(__name__)


class ThreatIntel:
    """Load threat intelligence data from DynamoDB and perform IOC detection"""
    IOC_KEY = 'streamalert:ioc'

    EXCEPTIONS_TO_BACKOFF = (ClientError, )
    BACKOFF_MAX_RETRIES = 3

    # DynamoDB Table settings
    MAX_QUERY_CNT = 100
    PRIMARY_KEY = 'ioc_value'
    SUB_TYPE_KEY = 'sub_type'
    PROJECTION_EXPRESSION = f'{PRIMARY_KEY},{SUB_TYPE_KEY}'

    _deserializer = TypeDeserializer()
    _client = None

    def __init__(self, table, enabled_clusters, ioc_types_map, excluded_iocs=None):
        self._table = table
        self._enabled_clusters = enabled_clusters
        self._ioc_config = ioc_types_map
        self._excluded_iocs = self._setup_excluded_iocs(excluded_iocs)

        region = env.get('AWS_REGION') or env.get('AWS_DEFAULT_REGION') or 'us-east-1'
        ThreatIntel._client = ThreatIntel._client or boto3.client('dynamodb', region_name=region)

    @property
    def _dynamodb(self):
        return ThreatIntel._client

    @staticmethod
    def _exceptions_to_giveup(err):
        """Function to decide if giveup backoff or not."""
        error_code = {
            'AccessDeniedException', 'ProvisionedThroughputExceededException',
            'ResourceNotFoundException'
        }
        return err.response['Error']['Code'] in error_code

    def threat_detection(self, records):
        """Public instance method to run threat intelligence against normalized records

        The records will be modified in-place by inserting IOC information if the
        records contain malicious IOC(s).

        Args:
            records (list): A list of payload instance with normalized records.

        Returns:
            list: A list of payload instances including IOC information.
        """
        if not records:
            return

        # Extract information from the records for IOC detection
        potential_iocs = self._extract_ioc_values(records)

        if not potential_iocs:
            LOGGER.debug('No IOCs extracted from records for processing')
            return

        # Query DynamoDB IOC type to verify if the extracted info are malicious IOC(s)
        for valid_ioc in self._process_ioc_values(list(potential_iocs)):
            value = valid_ioc['ioc_value']
            for ioc_type, record in potential_iocs[value]:
                # Inserted the IOC info into the record
                self._insert_ioc_info(record, ioc_type, value)

    @classmethod
    def _insert_ioc_info(cls, rec, ioc_type, ioc_value):
        """Insert ioc info to a record

        Record is modified/updated in-place with IOC info inserted.

        Example:
            A new field of 'streamalert:ioc' will be added to the record:

            {
                'key': 'value',
                'sourceAddress': '4.3.2.1',
                'sourceDomain': 'evil1.com',
                'streamalert:ioc': {
                    'ip': {'4.3.2.1'},
                    'domain' : {'evil1.com'}
                }
            }

        Args:
            rec (dict): Record data
            ioc_type (str): IOC type, can be 'ip', 'domain', or 'md5'
            ioc_value (str): Malicious IOC value
        """
        # Get the current collection of IOCs, or create a new empty dictionary
        record_iocs = rec.get(cls.IOC_KEY, defaultdict(set))
        record_iocs[ioc_type].add(ioc_value)
        rec[cls.IOC_KEY] = record_iocs

    def _process_ioc_values(self, potential_iocs):
        """Check if any info is malicious by querying DynamoDB IOC table

        Args:
            potential_iocs (list<str>): A list of potential IOC values
        """
        LOGGER.debug('Checking %d potential IOCs for validity', len(potential_iocs))
        # Segment data before calling DynamoDB table with batch_get_item.
        for query_values in self._segment(potential_iocs):
            try:
                query_result = self._query(query_values)
            except (ClientError, ParamValidationError):
                LOGGER.exception('An error occurred while querying dynamodb table')
                continue

            yield from query_result

    @classmethod
    def _segment(cls, potential_iocs):
        """Segment list of potential IOC values into smaller set(s)

        Batch query to dynamodb supports up to 100 items.

        Args:
            potential_iocs (list<str>): A list of potential IOC values

        Yields:
            set: Subset of total potential IOC values
        """
        end = len(potential_iocs)
        for index in range(0, end, cls.MAX_QUERY_CNT):
            yield set(potential_iocs[index:min(index + cls.MAX_QUERY_CNT, end)])

    def _query(self, values):
        """Instance method to query DynamoDB table

        Args:
            values (list): A list of string which contains IOC values

        Returns:
            A tuple(list, dict)
            list: A list of dict returned from dynamodb
                table query, in the format of
                    [
                        {'sub_type': 'c2_domain', 'ioc_value': 'evil.com'},
                        {'sub_type': 'mal_ip', 'ioc_value': '1.1.1.2'},
                    ]
            dict: A dict containing unprocesed keys.
        """
        @backoff.on_predicate(
            backoff.fibo,
            lambda resp: bool(resp['UnprocessedKeys']),  # retry if this is true
            max_tries=2,  # only retry unprocessed key 2 times max
            on_backoff=backoff_handler(),
            on_success=success_handler(),
            on_giveup=giveup_handler())
        @backoff.on_exception(backoff.expo,
                              self.EXCEPTIONS_TO_BACKOFF,
                              max_tries=self.BACKOFF_MAX_RETRIES,
                              giveup=self._exceptions_to_giveup,
                              on_backoff=backoff_handler(),
                              on_success=success_handler(),
                              on_giveup=giveup_handler())
        def _run_query(query_values, results):

            query_keys = [{self.PRIMARY_KEY: {'S': ioc}} for ioc in query_values if ioc]

            response = self._dynamodb.batch_get_item(RequestItems={
                self._table: {
                    'Keys': query_keys,
                    'ProjectionExpression': self.PROJECTION_EXPRESSION
                }
            })

            results.extend(self._deserialize(response['Responses'].get(self._table)))

            # Log this as an error for now so it can be picked up in logs
            if response['UnprocessedKeys']:
                LOGGER.error('Retrying unprocessed keys in response: %s',
                             response['UnprocessedKeys'])
                # Strip out the successful keys so only the unprocesed ones are retried.
                # This changes the list in place, so the called function sees the updated list
                self._remove_processed_keys(query_values,
                                            response['UnprocessedKeys'][self._table]['Keys'])

            return response

        results = []

        _run_query(values, results)

        return results

    @classmethod
    def _remove_processed_keys(cls, query_values, unprocesed_keys):
        keys = {elem[cls.PRIMARY_KEY] for elem in cls._deserialize(unprocesed_keys)}

        # Update the set with only unprocesed_keys
        query_values.intersection_update(keys)

    @classmethod
    def _deserialize(cls, dynamodb_data):
        """Convert dynamodb data types to python data types

        Types conversion between DynamoDB and Python.
        Reference link: http://boto3.readthedocs.io/en/latest/_modules/boto3/dynamodb/types.html
            DynamoDB                                Python
            --------                                ------
            {'NULL': True}                          None
            {'BOOL': True/False}                    True/False
            {'N': str(value)}                       Decimal(str(value))
            {'S': string}                           string
            {'B': bytes}                            Binary(bytes)
            {'NS': [str(value)]}                    set([Decimal(str(value))])
            {'SS': [string]}                        set([string])
            {'BS': [bytes]}                         set([bytes])
            {'L': list}                             list
            {'M': dict}                             dict

        Args:
            dynamodb_data (list): Contains IOC info with DynamoDB types

        Yields:
            dict: Dictionaries containing ioc_value and ioc_type
        """
        if not dynamodb_data:
            return

        for raw_data in dynamodb_data:
            yield {key: cls._deserializer.deserialize(val) for key, val in raw_data.items()}

    def _is_excluded_ioc(self, ioc_type, ioc_value):
        """Determine if we should bypass IOC lookup for specified IOC

        Args:
            ioc_type (string): Type of IOC to evaluate (md5, ip, domain, etc)
            value (string): Value of IOC to evaluate

        Returns:
            bool: True if IOC lookup should be bypassed for this value, False otherwise
        """
        if not (self._excluded_iocs and ioc_type in self._excluded_iocs):
            return False

        exclusions = self._excluded_iocs[ioc_type]

        if ioc_type == 'ip':
            # filter out *.amazonaws.com "IP"s
            return not valid_ip(ioc_value) or in_network(ioc_value, exclusions)

        return ioc_value in exclusions

    def _extract_ioc_values(self, payloads):
        """Instance method to extract IOC info from the record based on normalized keys

        Args:
          payloads (list<dict>): A list of dictionary payloads with records containing
            normalized data

        Returns:
          dict: Map of ioc values to the source record and type of ioc
        """
        ioc_values = defaultdict(list)
        for payload in payloads:
            record = payload['record']
            if Normalizer.NORMALIZATION_KEY not in record:
                continue
            normalized_values = record[Normalizer.NORMALIZATION_KEY]
            for normalized_key, values in normalized_values.items():
                # Look up mapped IOC type based on normalized CEF type
                ioc_type = self._ioc_config.get(normalized_key)
                if not ioc_type:
                    LOGGER.debug('Skipping undefined IOC type for normalized key: %s',
                                 normalized_key)
                    continue

                for value in values:
                    # Skip excluded IOCs
                    if self._is_excluded_ioc(ioc_type, value):
                        continue

                    ioc_values[value].append((ioc_type, record))

        return ioc_values

    @staticmethod
    def _setup_excluded_iocs(excluded):
        if not excluded:
            return None

        excluded = {itype: set(iocs) for itype, iocs in excluded.items()}

        # Try to load IP addresses
        if 'ip' in excluded:
            excluded['ip'] = {IPNetwork(ip) for ip in excluded['ip']}

        return excluded

    @classmethod
    def load_from_config(cls, config):
        """Public class constructor method to return instance of ThreatIntel class

        Args:
            config (dict): Config read from 'conf/' directory

        Returns:
            ThreatIntel: Class to be used for threat intelligence logic
        """
        if 'threat_intel' not in config:
            return

        intel_config = config['threat_intel']
        if not intel_config.get('enabled'):
            return

        # Threat Intel can be disabled for any given cluster
        enabled_clusters = {
            cluster
            for cluster, values in config['clusters'].items()
            if values.get('enable_threat_intel', False)
        }

        if not enabled_clusters:
            return  # if not clusters have threat intel enabled, there's nothing to do

        # Convert the current IOC mapping to be in the format
        # {'normalized_key': 'ioc_type'} for simpler lookups
        ioc_config = {
            key: ioc_type
            for ioc_type, keys in intel_config['normalized_ioc_types'].items() for key in keys
        }

        return cls(table=intel_config['dynamodb_table_name'],
                   enabled_clusters=enabled_clusters,
                   ioc_types_map=ioc_config,
                   excluded_iocs=intel_config.get('excluded_iocs'))

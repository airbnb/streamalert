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
import os

import backoff
import boto3
from boto3.dynamodb.types import TypeDeserializer
from botocore.exceptions import ClientError, ParamValidationError
from netaddr import IPAddress

from stream_alert.shared import NORMALIZATION_KEY
from stream_alert.shared.backoff_handlers import (
    backoff_handler,
    success_handler,
    giveup_handler
)

from stream_alert.rule_processor import LOGGER


# DynamoDB Table settings
MAX_QUERY_CNT = 100
PRIMARY_KEY = 'ioc_value'
SUB_TYPE_KEY = 'sub_type'
PROJECTION_EXPRESSION = '{},{}'.format(PRIMARY_KEY, SUB_TYPE_KEY)

class StreamIoc(object):
    """Class to store IOC info"""
    def __init__(self, **kwargs):
        """Initialize StreamIoc instance and store useful information

        Keyword arguments:
            value (str): IOC value
            ioc_type (str): Type of IOC, 'domain', 'ip' or 'md5'
            sub_type (str): sub type of IOC.
                Example, 'mal_ip' is the sub_type of 'ip'.
            associated_record (dict): Original record carry IOC value.
            is_ioc (bool): Indicate is the value in DynamoDB IOC table or not. If
                True, it means it is malicious IOC, otherwise it is False (default)
        """
        self.value = kwargs.get('value', None)
        self.ioc_type = kwargs.get('ioc_type', None)
        self.sub_type = kwargs.get('sub_type', None)
        self.associated_record = kwargs.get('associated_record', None)
        self.is_ioc = kwargs.get('is_ioc', False)

def exceptions_to_giveup(err):
    """Function to decide if giveup backoff or not."""
    error_code = {
        'AccessDeniedException',
        'ProvisionedThroughputExceededException',
        'ResourceNotFoundException'
    }
    return err.response['Error']['Code'] in error_code

class StreamThreatIntel(object):
    """Load intelligence from csv.gz files into a dictionary."""
    IOC_KEY = 'streamalert:ioc'

    EXCEPTIONS_TO_BACKOFF = (ClientError,)
    BACKOFF_MAX_RETRIES = 3

    # Class variable stores Data Normalization types mapping.
    __normalized_types = {}

    # Class variable stores mapping between CEF normalized types and IOC types
    __normalized_ioc_types_mapping = {}

    def __init__(self, table, region='us-east-1'):
        self.dynamodb = boto3.client('dynamodb', region)
        self._table = table

    def threat_detection(self, records):
        """Public instance method to run threat intelligence against normalized records

        The records will be modified in-place by inserting IOC information if the
        records contain malicious IOC(s).

        Args:
            records (list): A list of payload instance with normalized records.

        Returns:
            list: A list of payload instances including IOC information.
        """
        ioc_collections = []
        if not records:
            return ioc_collections

        # Extract information from the records for IOC detection
        for record in records:
            ioc_collections.extend(self._extract_ioc_from_record(record))

        # Query DynamoDB IOC type to verify if the extracted info are malicious IOC(s)
        self._process_ioc(ioc_collections)

        # IOC info will be inserted to the records if they contains malicious IOC(s)
        for ioc in ioc_collections:
            if ioc.is_ioc:
                self._insert_ioc_info(ioc.associated_record.pre_parsed_record,
                                      ioc.ioc_type,
                                      ioc.value)

        records_with_ioc = [ioc.associated_record for ioc in ioc_collections if ioc.is_ioc]
        return records_with_ioc

    def _insert_ioc_info(self, rec, ioc_type, ioc_value):
        """Instance method to insert ioc info to a record.
        It also removes ioc info duplication.

        Args:
            rec (dict): The parsed payload of a log
            ioc_type (str): IOC type, can be 'ip', 'domain' or 'md5'
            ioc_value (str): Malicious IOC value

        Returns:
            (None): A record will be modified in-place with IOC info inserted.
            Example that a record will be inserted with new field "streamalert:ioc":
                "streamalert:ioc": {
                    "ip": [4.3.2.1", "1.2.3.4"],
                    "domain" : ["evil1.com", "evil2.com"]
                  }
        """
        if self.IOC_KEY in rec:
            if (ioc_type in rec[self.IOC_KEY] and
                    ioc_value not in rec[self.IOC_KEY][ioc_type]):
                rec[self.IOC_KEY][ioc_type].append(ioc_value)
            else:
                rec[self.IOC_KEY][ioc_type] = [ioc_value]
        else:
            rec.update({self.IOC_KEY: {ioc_type: [ioc_value]}})

    def _extract_ioc_from_record(self, record):
        """Instance method to extract IOC info from the record based on normalized keys

        Args:
            record (dict): A list of payload instance with normalized records.

        Returns:
            list: Return a list of StreamIoc instances.
        """
        ioc_value_type_tuples = set()
        for datatype in record.pre_parsed_record[NORMALIZATION_KEY]:
            # Lookup mapped IOC type based on normalized CEF type from Class variable.
            ioc_type = self.__normalized_ioc_types_mapping.get(datatype, None)

            # A new StreamIoc instance will be created when normalized CEF type
            # has mapped IOC type.
            if ioc_type:
                for original_keys in record.pre_parsed_record[NORMALIZATION_KEY][datatype]:
                    value = record.pre_parsed_record
                    if isinstance(original_keys, list):
                        for original_key in original_keys:
                            value = value[original_key]
                    if value:
                        # Threat Intel will only check against public IP addresses
                        # while processing IP IOCs.
                        if ioc_type == 'ip' and not self.is_public_ip(value):
                            continue
                        ioc_value_type_tuples.add((value, ioc_type))
        return [StreamIoc(value=str(value).lower(), ioc_type=ioc_type, associated_record=record)
                for value, ioc_type in ioc_value_type_tuples]

    @classmethod
    def load_from_config(cls, config):
        """Public class method to map datatype to IOC type

        Args:
            config (dict): A dict read from 'conf/' directory

        Returns:
            No return. Class variables will be set after config been processed.
        """
        if config.get('types'):
            cls._process_types_config(config['types'])

        # Threat Intel will be disabled for the cluster if it is explicitly
        # disabled in cluster config located in conf/clusters/ directory
        cluster = os.environ.get('CLUSTER', '')
        if cluster and not (config['clusters'][cluster]['modules']['stream_alert']
                            ['rule_processor'].get('enable_threat_intel', True)):
            return False

        if (config.get('global')
                and config['global'].get('threat_intel')
                and config['global']['threat_intel'].get('enabled')
                and config['global']['threat_intel'].get('dynamodb_table')):
            return cls(config['global']['threat_intel']['dynamodb_table'],
                       config['global']['account'].get('region', 'us-east-1'))

        return False

    @classmethod
    def _process_types_config(cls, config):
        """Class method to extract normlaized types and IOC types fron types conf

        Args:
            config (dict): StreamAlert config contains global and types settings.
        """
        normalized_ioc_types_mapping = {}
        normalized_types_mapping = {}
        for log_src, mapping in config.iteritems():
            sub_normalized_types = {}
            for norm_type, orig_types in mapping.iteritems():
                qualified, norm_type, ioc_type = cls._validate_type_mapping(norm_type)
                # if the normalized type string contains ioc type, add
                # normalized type and its ioc type to the dict
                if qualified:
                    normalized_ioc_types_mapping[norm_type] = ioc_type

                sub_normalized_types[norm_type] = orig_types
            normalized_types_mapping[log_src] = sub_normalized_types

        # Class variable stores mapping between CEF normalized types and IOC types
        cls.__normalized_ioc_types_mapping = normalized_ioc_types_mapping
        # Class variable stores Data Normalization types mapping.
        cls.__normalized_types = normalized_types_mapping

    @staticmethod
    def _validate_type_mapping(mapping_str):
        """Static method to extract normalized type and IOC type from qualified str

        Args:
            mapping_str (str): A qualified string has pattern 'normalized_type:ioc_type'

        Returns:
            A tuple(bool, str, str)
            bool: First return indicate if the string a qualifited string contains
                both normalized CEF type and IOC type.
            str: Second return is normalized type.
            str: Last return is IOC type.
        """
        normalized_type = None
        ioc_type = None

        splitted_str = mapping_str.split(':')
        if len(splitted_str) == 1:
            normalized_type = splitted_str[0]
        elif len(splitted_str) == 2:
            normalized_type = splitted_str[0]
            ioc_type = splitted_str[1].split('_')[-1]
        else:
            LOGGER.info('Key %s in conf/types.json is incorrect', mapping_str)
            return False, None, None

        if normalized_type and ioc_type:
            return True, normalized_type, ioc_type

        return False, normalized_type, None

    def _process_ioc(self, ioc_collections):
        """Check if any info is malicious by querying DynamoDB IOC table

        Args:
            ioc_collections (list): A list of StreamIoc instances.
        """
        LOGGER.debug('[Threat Inel] Rule Processor queries %d IOCs', len(ioc_collections))
        # Segment data before calling DynamoDB table with batch_get_item.
        for subset in self._segment(ioc_collections):
            query_values = []
            for ioc in subset:
                if ioc.value not in query_values:
                    query_values.append(ioc.value)

            query_result = []

            query_error_msg = 'An error occured while quering dynamodb table. Error is: %s'
            try:
                result, unprocesed_keys = self._query(query_values)
                query_result.extend(result)
            except ClientError as err:
                LOGGER.error(query_error_msg, err.response)
                return
            except ParamValidationError as err:
                LOGGER.error(query_error_msg, err)
                return

            # If there are unprocessed keys, we will re-query once with unprocessed
            # keys only
            if unprocesed_keys:
                deserializer = self._deserialize(unprocesed_keys[self._table]['Keys'])
                query_values = [elem[PRIMARY_KEY] for elem in deserializer]
                query_error_msg = 'An error occured while processing unprocesed_keys. Error is: %s'
                try:
                    result, _ = self._query(query_values)
                    query_result.extend(result)
                except ClientError as err:
                    LOGGER.error(query_error_msg, err.response)
                    return
                except ParamValidationError as err:
                    LOGGER.error(query_error_msg, err)
                    return

            for value in ioc_collections:
                for ioc in query_result:
                    if value.value == ioc[PRIMARY_KEY]:
                        value.sub_type = ioc[SUB_TYPE_KEY]
                        value.is_ioc = True
                        continue

    @staticmethod
    def _segment(ioc_collections):
        """Static method to segment ioc_collections in to smaller set.
        Batch query to dynamodb supports up to 100 items.

        Args:
            ioc_collections (list): A list of StreamIoc instances

        Returns:
            list: List of subset of StreamIoc instances
        """
        result = []
        end = len(ioc_collections)
        for index in range(0, end, MAX_QUERY_CNT):
            result.append(ioc_collections[index:min(index+MAX_QUERY_CNT, end)])
        return result

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
        @backoff.on_exception(backoff.expo,
                              self.EXCEPTIONS_TO_BACKOFF,
                              max_tries=self.BACKOFF_MAX_RETRIES,
                              giveup=exceptions_to_giveup,
                              on_backoff=backoff_handler,
                              on_success=success_handler,
                              on_giveup=giveup_handler)
        def _query(values):
            result = []
            query_keys = [{PRIMARY_KEY: {'S': ioc}} for ioc in values if ioc]
            response = self.dynamodb.batch_get_item(
                RequestItems={
                    self._table: {
                        'Keys': query_keys,
                        'ProjectionExpression': PROJECTION_EXPRESSION
                    }
                },
            )

            if response.get('Responses'):
                result.extend(self._deserialize(response['Responses'].get(self._table)))

            return result, response.get('UnprocessedKeys')

        return _query(values)

    @staticmethod
    def _deserialize(dynamodb_data):
        """Static method to convert dynamodb data type to python data type
        Types convention between DynamoDB and Python.
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

        Returns:
            list: A list of Python dictionary type containing ioc_value and ioc_type
        """
        result = []
        if not dynamodb_data:
            return result

        deserializer = TypeDeserializer()
        for raw_data in dynamodb_data:
            python_data = {}
            for key, val in raw_data.iteritems():
                python_data[key] = deserializer.deserialize(val)
            result.append(python_data)
        return result

    @classmethod
    def normalized_type_mapping(cls):
        """Get normalized CEF types mapping to original keys from the records."""
        return cls.__normalized_types

    @staticmethod
    def is_public_ip(ip_address):
        try:
            ip_addr = IPAddress(str(ip_address))
            # We also need to filter multicast ip which is a private ip. For example,
            # multicast ip '239.192.0.1', is a private ip.
            return ip_addr.is_unicast() and not ip_addr.is_private()
        except: # pylint: disable=bare-except
            return False

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
import logging
import os
from abc import ABCMeta, abstractmethod, abstractproperty

from streamalert.shared.logger import get_logger

LOGGER = get_logger(__name__)
LOGGER_DEBUG_ENABLED = LOGGER.isEnabledFor(logging.DEBUG)


class PayloadRecord:
    """PayloadRecord for extracted records from within a payload

    Attributes:
        data (str|dict): Raw payload record data being parsed
        parser: Instance of classifier.parsers.ParserBase used to properly parse the data
        log_schema_type (str): Fully qualified log type (ie: osquery:diff)
        log_type (str): Top-level log type (ie: 'osquery' in osquery:diff)
        log_subtype (str): Log sub-type, if defined (ie: 'diff' in osquery:diff)
        parsed_records (list): List of successfully parsed records from this payload record
        invalid_records (list): If some records from this payload record parsed successfully,
            but others failed, this contains the list of failed records
    """
    def __init__(self, record_data):
        self._record_data = record_data
        self._parser = None
        self.service = None
        self.resource = None

    def __bool__(self):
        """Valid if there is a parser, and the parser itself is valid

        ParserBase implements __nonzero__ as well, so return the result of it
        """
        return self._parser is not None

    def __len__(self):
        return (len(json.dumps(self._record_data, separators=(',', ':'))) if isinstance(
            self._record_data, dict) else len(self._record_data))

    def __repr__(self):
        try:
            record_data = json.dumps(self._record_data)
            invalid_records = json.dumps(self.invalid_records)
        except (TypeError, ValueError):
            record_data = self._record_data
            invalid_records = self.invalid_records
            LOGGER.debug('A PayloadRecord has data that is not serializable as JSON')

        if not self:
            return f'<{self.__class__.__name__} valid:{bool(self)}; raw record:{record_data};>'

        if self.invalid_records:
            return (
                f'<{self.__class__.__name__} valid:{bool(self)}; log type:{self.log_schema_type}; '
                f'parsed records:{len(self.parsed_records)}; '
                f'invalid records:{len(self.invalid_records)} ({invalid_records}); raw record:{record_data};>'
            )
        return (
            f'<{self.__class__.__name__} valid:{bool(self)}; log type:{self.log_schema_type}; parsed records:{len(self.parsed_records)};>'
        )

    @property
    def data(self):
        return self._record_data

    @property
    def parser(self):
        return self._parser

    @parser.setter
    def parser(self, parser):
        self._parser = parser

    @property
    def parsed_records(self):
        return self.parser.parsed_records if self else []

    @property
    def invalid_records(self):
        return self.parser.invalid_parses if self else []

    @property
    def log_schema_type(self):
        return self.parser.log_schema_type if self else None

    @property
    def log_type(self):
        return self.parser.log_schema_type.split(':')[0] if self else None

    @property
    def log_subtype(self):
        return self.parser.log_schema_type.split(':')[-1] if self else None

    @property
    def data_type(self):
        return self.parser.type() if self else None

    @property
    def sqs_messages(self):
        """Return a dictionary for the SQS message. JSON serialization should be done by caller"""
        return [
            {   # TODO: consider adding a record UUID to this payload
                'cluster': os.environ['CLUSTER'],
                'log_schema_type': self.log_schema_type,
                'record': record,
                'service': self.service,
                'resource': self.resource,
                'data_type': self.data_type,
            } for record in self.parsed_records
        ]


class RegisterInput:
    """Class to be used as a decorator to register all StreamPayload subclasses"""
    _payload_classes = {}

    def __new__(cls, payload_class):
        RegisterInput._payload_classes[payload_class.service()] = payload_class
        return payload_class

    @classmethod
    def load_for_service(cls, service, resource, raw_record):
        """Returns the right StreamPayload subclass for this service

        Args:
            service (str): service name to load class for
            resource (str): resource for this service
            raw_record (str): record raw payload data

        Returns:
            StreamPayload: Loaded subclass of StreamPayload for the proper payload type
        """
        payload = cls._get_payload_class(service)
        return payload(resource=resource, raw_record=raw_record) if payload else False

    @classmethod
    def _get_payload_class(cls, service):
        """Returns the subclass that should handle this particular service's records

        Args:
            service (str): The service identifier for this payload

        Returns:
            StreamPayload: Subclass of StreamPayload to use for processing incoming records
        """
        try:
            return cls._payload_classes[service]
        except KeyError:
            LOGGER.error('Requested payload service [%s] does not exist', service)


class StreamPayload(metaclass=ABCMeta):
    """StreamAlert payload object for incoming records

    Attributes:
        resource (str): The name of the resource from which this log originated.
            Can be a kinesis stream name, SNS topic, or S3 bucket name.
        raw_record: The record from the AWS Lambda Records dictionary.
        fully_classified (bool): Whether the payload has been successfully
            and completely classified.
    """
    def __init__(self, resource, raw_record):
        self.raw_record = raw_record
        self.resource = resource
        self.fully_classified = True

    def __bool__(self):
        return self.fully_classified

    def __repr__(self):
        if self:
            return f'<{self.__class__.__name__} valid:{bool(self)}; resource:{self.resource};>'

        try:
            raw_record = json.dumps(self.raw_record)
        except (TypeError, ValueError):
            raw_record = self.raw_record
            LOGGER.debug('A StreamPayload has data that is not serializable as JSON')

        return f'<{self.__class__.__name__} valid:{bool(self)}; resource:{self.resource}; raw record:{raw_record};>'

    @classmethod
    def load_from_raw_record(cls, raw_record):
        """Extract the originating AWS service and resource from a raw record

        Each raw record contains a set of keys that represent its source.
        A Kinesis record will contain a 'kinesis' key, while a S3 record
        contains 's3', and an SNS record contains an 'Sns' key, and so on

        This method also supports loading an S3 event notification that is received via SNS.

        Args:
            raw_record (dict): A raw record as a dictionary

        Returns:
            StreamPayload: Loaded subclass of StreamPayload for the proper payload type
        """
        # Sns is capitalized below because this is how AWS stores it within the Record
        # Other services above, like s3, are not stored like this. Do not alter it!
        resource_mapper = {
            'kinesis': lambda r: r['eventSourceARN'].split('/')[-1],
            's3': lambda r: r['s3']['bucket']['name'],
            'Sns': lambda r: r['Sns']['TopicArn'].split(':')[-1],
            'streamalert_app': lambda r: r['streamalert_app']
        }

        service, resource = None, None
        # check raw record for either kinesis, s3, or apps keys
        for svc, map_function in resource_mapper.items():
            if svc in raw_record:
                # map the resource name from a record
                resource = map_function(raw_record)
                service = svc
                break

        # If this is an s3 event notification via SNS, extract the bucket from the record
        if ('Sns' in raw_record and raw_record['Sns'].get('Type') == 'Notification'
                and raw_record['Sns'].get('Subject') == 'Amazon S3 Notification'):

            service = 's3'

            # Assign the s3 event notification data to the raw_record and extract the resource
            raw_record = json.loads(raw_record['Sns']['Message'])['Records'][0]
            resource = resource_mapper[service](raw_record)

        if not (service and resource):
            LOGGER.error(
                'No valid service (%s) or resource (%s) found in payload\'s raw '
                'record, skipping: %s', service, resource, raw_record)
            return False

        return RegisterInput.load_for_service(service.lower(), resource, raw_record)

    @classmethod
    @abstractproperty
    def service(cls):
        """Read only service property enforced on subclasses.

        Returns:
            str: The service name for this payload type.
        """

    @abstractmethod
    def _pre_parse(self):
        """Pre-parsing method that should be implemented by all subclasses

        Yields:
            Instances of PayloadRecord back to the caller containing the current log data
        """

    @staticmethod
    def _cleanup():
        """Cleanup method to be implemented if any post-parsing operations should be performed"""

    def pre_parse(self):
        """Public pre-parsing method that wraps the subclass _pre_parse method

        This adds to the values returned by the subclass methods

        Yields:
            Instances of PayloadRecord back to the caller containing the current log data
        """
        for payload in self._pre_parse():
            payload.service = self.service()
            payload.resource = self.resource
            yield payload

        self._cleanup()

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
from abc import ABCMeta, abstractmethod, abstractproperty
import json
import logging

from stream_alert.shared.logger import get_logger


LOGGER = get_logger(__name__)
LOGGER_DEBUG_ENABLED = LOGGER.isEnabledFor(logging.DEBUG)


class PayloadRecord(object):
    """PayloadRecord for extracted records from within a payload"""

    def __init__(self, record_data):
        self._record_data = record_data
        self.log_name = None
        self.schema = None
        self.data_type = None
        self.classified = False
        self._parsed_data = None

    @property
    def data(self):
        return self._record_data

    @property
    def parsed_data(self):
        return self._parsed_data

    @parsed_data.setter
    def parsed_data(self, data):
        self._parsed_data = data

    def new_sub_record(self):
        """Return a new sub record that is a child of this same raw record data"""
        # Do NOT copy/deep copy the original record
        # Each record should just reference the same original record, and
        # copying would result in memory exhaustion. The original record
        # is never altered after instantiation, so just reference it here
        record = type(self)(self._record_data)
        record.data_type = self.data_type
        return record


class RegisterInput(object):
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
        if not payload:
            return False

        return payload(resource=resource, raw_record=raw_record)

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


class StreamPayload(object):
    """StreamAlert payload object for incoming records

    Attributes:
        resource (str): The name of the resource from which this log originated.
            Can be a kinesis stream name, SNS topic, or S3 bucket name.
        raw_record: The record from the AWS Lambda Records dictionary.
        log_source (str): The name of the logging application which the data
            originated from.  This could be osquery, auditd, etc.
        records (list): A list of parsed and typed PayloadRecord(s).
        data_type (str): The data type of the record - json, csv, syslog, etc.
        fully_classified (bool): Whether the payload has been successfully
            and completely classified.
    """
    __metaclass__ = ABCMeta

    def __init__(self, resource, raw_record):
        self.raw_record = raw_record
        self.resource = resource
        self.log_source = None
        self.records = None
        self.data_type = None
        self.fully_classified = True

    def __nonzero__(self):
        return all([self.resource, self.data_type, self.log_source,
                    self.records, self.fully_classified])

    # For forward compatibility to Python3
    __bool__ = __nonzero__

    def __repr__(self):
        return '<{} valid:{} log_source:{} resource:{} type:{} record:{}>'.format(
            self.__class__.__name__,
            bool(self),
            self.log_source,
            self.resource,
            self.data_type,
            self.records
        )

    @property
    def log_type(self):
        return self.log_source.split(':')[0]

    @property
    def log_subtype(self):
        return self.log_source.split(':')[-1]

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
            'stream_alert_app': lambda r: r['stream_alert_app']
        }

        service, resource = None, None
        # check raw record for either kinesis, s3, or apps keys
        for svc, map_function in resource_mapper.iteritems():
            if svc in raw_record:
                # map the resource name from a record
                resource = map_function(raw_record)
                service = svc
                break

        # If this is an s3 event notification via SNS, extract the bucket from the record
        if ('Sns' in raw_record and
                raw_record['Sns'].get('Type') == 'Notification' and
                raw_record['Sns'].get('Subject') == 'Amazon S3 Notification'):

            service = 's3'

            # Assign the s3 event notification data to the raw_record and extract the resource
            raw_record = json.loads(raw_record['Sns']['Message'])['Records'][0]
            resource = resource_mapper[service](raw_record)

        if not (service and resource):
            LOGGER.error('No valid service (%s) or resource (%s) found in payload\'s raw '
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
    def pre_parse(self):
        """Pre-parsing method that should be implemented by all subclasses

        Yields:
            Instances of PayloadRecord back to the caller containing the current log data
        """

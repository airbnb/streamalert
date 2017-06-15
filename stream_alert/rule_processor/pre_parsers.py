'''
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
'''
import base64
import gzip
import logging
import os
import tempfile
import time
import urllib

import boto3

logging.basicConfig()
LOGGER = logging.getLogger('StreamAlert')

class S3ObjectSizeError(Exception):
    pass

class StreamPreParsers(object):
    """A collection of pre-parsers to get data for classificaiton

    The pre-parser's job is to read raw records from whichever
    source invoked AWS Lambda (Kinesis, S3, etc), and perform all
    necessary actions to get either a string or a collection of strings
    """
    @classmethod
    def pre_parse_kinesis(cls, raw_record):
        """Decode a Kinesis record.

        Args:
            raw_record (dict): A Kinesis event record.

        Returns: (string) Base64 decoded data.
        """
        return base64.b64decode(raw_record['kinesis']['data'])

    @classmethod
    def pre_parse_s3(cls, raw_record):
        """Given an S3 record, download and parse the data.

        Args:
            raw_record (dict): A S3 event record.

        Returns:
            (list) Lines from the downloaded s3 object
        """
        client = boto3.client('s3', region_name=raw_record['awsRegion'])
        unquote = lambda data: urllib.unquote(data).decode('utf8')
        bucket = unquote(raw_record['s3']['bucket']['name'])
        key = unquote(raw_record['s3']['object']['key'])
        size = int(raw_record['s3']['object']['size'])
        downloaded_s3_object = cls._download_s3_object(client, bucket, key, size)

        return downloaded_s3_object, size

    @classmethod
    def pre_parse_sns(cls, raw_record):
        """Decode an SNS record.

        Args:
            raw_record (dict): An SNS message.

        Returns: (string) SNS message data.
        """
        return raw_record['Sns']['Message']

    @classmethod
    def read_s3_file(cls, downloaded_s3_object):
        """Parse a downloaded file from S3

        Supports reading both gzipped files and plaintext files.

        Args:
            downloaded_s3_object (string): A full path to the downloaded file.

        Yields:
            [generator] A generator that yields lines from the downloaded s3 object
        """
        _, extension = os.path.splitext(downloaded_s3_object)

        if extension == '.gz':
            for line in gzip.open(downloaded_s3_object, 'r'):
                yield line.rstrip()
        else:
            for line in open(downloaded_s3_object, 'r'):
                yield line.rstrip()

        # aws lambda apparently does not reallocate disk space when files are
        # removed using os.remove(), so we must truncate them before removal
        with open(downloaded_s3_object, 'w'):
            pass

        # remove the file
        os.remove(downloaded_s3_object)
        if not os.path.exists(downloaded_s3_object):
            LOGGER.debug('Removed temp file - %s', downloaded_s3_object)

    @classmethod
    def _download_s3_object(cls, client, bucket, key, size):
        """Download an object from S3.

        Verifies the S3 object is less than or equal to 128MB, and
        stores into a temp file.  Lambda can only execute for a
        maximum of 300 seconds, and the file to download
        greatly impacts that time.

        Args:
            client: boto3 s3 client object
            bucket (string): s3 bucket to download object from
            key (string): key of s3 object
            size (int): size of s3 object in bytes

        Returns:
            (string) The downloaded path of the S3 object.
        """
        size_kb = size / 1024
        size_mb = size_kb / 1024
        if size_mb > 128:
            raise S3ObjectSizeError('S3 object to download is above 128MB')

        LOGGER.debug('/tmp directory contents:%s ', os.listdir('/tmp'))
        LOGGER.debug(os.popen('df -h /tmp | tail -1').read().strip())

        if size_mb:
            display_size = '{}MB'.format(size_mb)
        else:
            display_size = '{}KB'.format(size_kb)

        LOGGER.info('Starting download from S3: %s/%s [%s]', bucket, key, display_size)

        suffix = key.replace('/', '-')
        _, downloaded_s3_object = tempfile.mkstemp(suffix=suffix)
        with open(downloaded_s3_object, 'wb') as data:
            start_time = time.time()
            client.download_fileobj(bucket, key, data)

        end_time = time.time() - start_time
        LOGGER.info('Completed download in %s seconds', round(end_time, 2))

        return downloaded_s3_object

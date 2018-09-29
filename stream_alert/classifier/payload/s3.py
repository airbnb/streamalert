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
import json
import logging
import urllib
import gzip
import os
import tempfile
import subprocess
import time

import boto3
from botocore.exceptions import ClientError
import jsonlines

from stream_alert.classifier.payload.payload_base import (
    PayloadRecord,
    RegisterInput,
    StreamPayload
)
from stream_alert.shared import CLASSIFIER_FUNCTION_NAME as FUNCTION_NAME
from stream_alert.shared.logger import get_logger
from stream_alert.shared.metrics import MetricLogger


LOGGER = get_logger(__name__)
LOGGER_DEBUG_ENABLED = LOGGER.isEnabledFor(logging.DEBUG)


class S3PayloadError(Exception):
    """Exception for S3Payload errors"""


@RegisterInput
class S3Payload(StreamPayload):
    """S3Payload class"""

    @property
    def bucket(self):
        return self.raw_record['s3']['bucket']['name']

    @property
    def key(self):
        return self.raw_record['s3']['object']['key']

    @property
    def size(self):
        return int(self.raw_record['s3']['object']['size'])

    @property
    def region(self):
        return self.raw_record['awsRegion']

    @property
    def display_size(self):
        """Calculate and format a size for printing"""
        size_kb = round(self.size / 1024.0, 2)
        size_mb = round(size_kb / 1024.0, 2)
        return '{}MB'.format(size_mb) if size_mb else '{}KB'.format(size_kb)

    @classmethod
    def service(cls):
        return 's3'

    @classmethod
    def _unquote(cls, data):
        # Use the urllib unquote method to decode any url encoded characters
        # (ie - %26 --> &) from the bucket and key names
        return urllib.unquote(data).decode('utf-8')

    def _check_size(self):
        """Ensure the S3 file's size is not too large to download into the Lambda environment

        Returns:
            bool: True if the file is smaller than 128 MB, False otherwise
        """
        # size == 0 or greater than 128MB
        if self.size == 0 or (self.size > 128 * 1024 * 1024):
            raise S3PayloadError('S3 object {}/{} has an invalid size and cannot be downloaded'
                                 'from S3: {}'.format(self.bucket, self.key, self.display_size))

    @staticmethod
    def _shred_temp_directory():
        """Delete all objects in the container's temp directory"""
        LOGGER.debug('Shredding temp directory')

        for root, dirs, files in os.walk(tempfile.gettempdir(), topdown=False):
            for name in files:
                subprocess.check_call([  # nosec
                    'shred', '--force', '--iterations=1',
                    '--remove', os.path.join(root, name)])
            for name in dirs:
                os.rmdir(os.path.join(root, name))  # nosec

    @staticmethod
    def _gz_reader(open_file):
        open_file.seek(0)
        reader = gzip.GzipFile(fileobj=open_file, mode='r')
        try:
            # Test to ensure this is gzip data, then rewind
            reader.read(1)
            reader.rewind()
        except IOError:
            # Fall back on the default reader
            reader = open_file
            reader.seek(0)

        # Return either the gzip reader or the original reader
        return reader

    @staticmethod
    def _jsonlines_reader(open_file):
        open_file.seek(0)
        reader = None
        try:
            json_lines = jsonlines.Reader(open_file)
            json_lines.read()
            reader = json_lines
        except ValueError:
            reader = open_file

        open_file.seek(0)
        return reader

    @classmethod
    def _read_downloaded_object(cls, open_file):
        """Read the contents of the downloaded S3 file using the open file handle

        Args:
            open_file (file-like object): File handle from which to read the data

        Yields:
            tuple: line number, contents of the line being read
        """
        reader = cls._gz_reader(open_file)
        try:
            # Try to just load the reader as regular json first
            yield 1, json.load(reader)
            return
        except ValueError:
            pass

        # Iterate over the lines, returning each
        # This could be dicts from a jsonlines.Reader, or raw strings
        for line_num, line in enumerate(cls._jsonlines_reader(reader), start=1):
            yield line_num, line.strip() if isinstance(line, basestring) else line

    def _read_file(self):
        """Download and read the contents of the S3 file

        Yields:
            tuple: line number, contents of the line being read
        """
        # Shred the temp dir before downloading
        self._shred_temp_directory()
        bucket = self._unquote(self.bucket)
        key = self._unquote(self.key)

        # Use tempfile.TemporaryFile to do the download
        # This will automatically close/get garbage collected upon completion
        with tempfile.TemporaryFile() as download:
            client = boto3.resource('s3', region_name=self.region).Bucket(bucket)
            start_time = time.time()
            LOGGER.info('[S3Payload] Starting download from S3: %s/%s [%s]', bucket, key, self.size)

            try:
                client.download_fileobj(key, download)
            except (IOError, ClientError):
                LOGGER.exception('Failed to download object from S3')
                return

            total_time = time.time() - start_time
            LOGGER.info('Completed download in %s seconds', round(total_time, 2))

            # Log a metric on how long this object took to download
            MetricLogger.log_metric(FUNCTION_NAME, MetricLogger.S3_DOWNLOAD_TIME, total_time)

            for line_num, line in self._read_downloaded_object(download):
                yield line_num, line

            # Reading was a success, so truncate the file contents and return
            download.seek(0)
            download.truncate()

    def pre_parse(self):
        """Pre-parsing method for S3 objects

        Downloads the s3 object into the system's temp directory for reading. The
        file is kept open as a tempfile.TemporaryFile to ensure proper cleanup
        when reading finishes.

        Yields:
            Instances of PayloadRecord back to the caller containing the current log data
        """
        self._check_size()

        line_num = 0
        for line_num, data in self._read_file():
            yield PayloadRecord(data)

        MetricLogger.log_metric(FUNCTION_NAME, MetricLogger.TOTAL_S3_RECORDS, line_num)

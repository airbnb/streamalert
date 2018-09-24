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
import logging
from urllib import unquote
import gzip
import os
import tempfile
import subprocess
import time

import boto3

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


class S3ObjectSizeError(Exception):
    """Exception indicating the S3 object is too large to process"""


@RegisterInput
class S3Payload(StreamPayload):
    """S3Payload class"""
    s3_object_size = 0

    @classmethod
    def service(cls):
        return 's3'

    def pre_parse(self):
        """Pre-parsing method for S3 objects that will download the s3 object,
        open it for reading and iterate over lines (records) in the file.
        This yields back references of this S3Payload instance to the caller
        with a propertly set `pre_parsed_record` for this record.

        Yields:
            Instances of `self` back to the caller with the
                proper `pre_parsed_record` set. Conforms to the interface of
                returning a generator, providing the ability to support
                multi-record like this (s3).
        """
        s3_file_path = self._get_object()
        if not s3_file_path:
            return

        line_num, processed_size = 0, 0
        for line_num, data in self._read_downloaded_s3_object(s3_file_path):
            yield PayloadRecord(data)

            # Only do the extra calculations below if debug logging is enabled
            if not LOGGER_DEBUG_ENABLED:
                continue

            # Add the current data to the total processed size
            # +1 to account for line feed
            processed_size += (len(data) + 1)

            # Log a debug message on every 100 lines processed
            if line_num % 100 == 0:
                avg_record_size = ((processed_size - 1) / line_num)
                if avg_record_size:
                    approx_record_count = self.s3_object_size / avg_record_size
                    LOGGER.debug(
                        'Processed %s S3 records out of an approximate total of %s '
                        '(average record size: %s bytes, total size: %s bytes)',
                        line_num,
                        approx_record_count,
                        avg_record_size,
                        self.s3_object_size)

        MetricLogger.log_metric(FUNCTION_NAME, MetricLogger.TOTAL_S3_RECORDS, line_num)

    def _download_object(self, region, bucket, key):
        """Download an object from S3.

        Verifies the S3 object is less than or equal to 128MB, and
        downloads it into a temp file.  Lambda can only execute for a
        maximum of 300 seconds, and the file to download
        greatly impacts that time.

        Args:
            region (str): AWS region to use for boto client instance.
            bucket (str): S3 bucket to download object from.
            key (str): Key of s3 object.

        Returns:
            str: The downloaded path of the S3 object.
        """
        size_kb = round(self.s3_object_size / 1024.0, 2)
        size_mb = round(size_kb / 1024.0, 2)
        display_size = '{}MB'.format(size_mb) if size_mb else '{}KB'.format(size_kb)

        # File size checks before downloading
        if size_kb == 0:
            return
        elif size_mb > 128:
            raise S3ObjectSizeError('[S3Payload] The S3 object {}/{} is too large [{}] to download '
                                    'from S3'.format(bucket, key, display_size))

        # Shred the temp dir before downloading
        self._shred_temp_directory()
        # Bandit warns about using a shell process, ignore with #nosec
        LOGGER.debug(os.popen('df -h /{} | tail -1'.format(  #nosec
            tempfile.gettempdir())).read().strip())
        LOGGER.info('[S3Payload] Starting download from S3: %s/%s [%s]', bucket, key, display_size)

        # Convert the S3 object name to store as a file in the Lambda container
        suffix = key.replace('/', '-')
        file_descriptor, downloaded_s3_object = tempfile.mkstemp(suffix=suffix)

        with open(downloaded_s3_object, 'wb') as data:
            client = boto3.client('s3', region_name=region)
            start_time = time.time()
            client.download_fileobj(bucket, key, data)

        # Explicitly call os.close on the underlying open file descriptor
        # Addresses https://github.com/airbnb/streamalert/issues/587
        os.close(file_descriptor)

        total_time = time.time() - start_time
        LOGGER.info('Completed download in %s seconds', round(total_time, 2))

        # Log a metric on how long this object took to download
        MetricLogger.log_metric(FUNCTION_NAME, MetricLogger.S3_DOWNLOAD_TIME, total_time)

        return downloaded_s3_object

    def _get_object(self):
        """Given an S3 record, download and parse the data.

        Returns:
            str: Path to the downloaded s3 object.
        """
        # Use the urllib unquote method to decode any url encoded characters
        # (ie - %26 --> &) from the bucket and key names
        unquoted = lambda(data): unquote(data).decode('utf-8')
        region = self.raw_record['awsRegion']

        bucket = unquoted(self.raw_record['s3']['bucket']['name'])
        key = unquoted(self.raw_record['s3']['object']['key'])
        self.s3_object_size = int(self.raw_record['s3']['object']['size'])

        LOGGER.debug('Pre-parsing record from S3. Bucket: %s, Key: %s, Size: %d',
                     bucket, key, self.s3_object_size)

        try:
            return self._download_object(region, bucket, key)
        except IOError:
            LOGGER.exception('[S3Payload] The following error occurred while downloading')
            return

    @staticmethod
    def _shred_temp_directory():
        """Delete all objects in the container's temp directory"""
        LOGGER.debug('Shredding temp directory')

        for root, dirs, files in os.walk(tempfile.gettempdir(), topdown=False):
            for name in files:
                subprocess.check_call([  #nosec
                    'shred', '--force', '--iterations=1',
                    '--remove', os.path.join(root, name)])
            for name in dirs:
                os.rmdir(os.path.join(root, name))  #nosec

    @staticmethod
    def _read_downloaded_s3_object(s3_object):
        """Read lines from a downloaded file from S3

        Supports reading both gzipped files and plaintext files.

        Args:
            s3_object (str): A full path to the downloaded file.

        Yields:
            (str) Lines from the downloaded s3 object.
        """
        _, extension = os.path.splitext(s3_object)

        if extension == '.gz':
            with gzip.open(s3_object, 'r') as s3_file:
                for num, line in enumerate(s3_file, start=1):
                    yield num, line.rstrip()
        else:
            with open(s3_object, 'r') as s3_file:
                for num, line in enumerate(s3_file, start=1):
                    yield num, line.rstrip()

        # AWS Lambda apparently does not reallocate disk space when files are
        # removed using os.remove(), so we must truncate them before removal
        with open(s3_object, 'w'):
            pass

        os.remove(s3_object)
        if not os.path.exists(s3_object):
            LOGGER.debug('Removed temp S3 file: %s', s3_object)
        else:
            LOGGER.error('Failed to remove temp S3 file: %s', s3_object)

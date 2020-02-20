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
import gzip
import os
import tempfile

import boto3

from mock import patch
from moto import mock_s3
from nose.tools import assert_equal, assert_raises
from pyfakefs import fake_filesystem_unittest

from streamalert.classifier.payload.s3 import S3Payload, S3PayloadError


class TestS3Payload:
    """S3Payload tests"""
    # pylint: disable=no-self-use,protected-access,attribute-defined-outside-init

    def setup(self):
        """S3Payload - Setup"""
        self._bucket = 'test_bucket_name'
        self._key = 'test_object_name'
        self._size = 100
        self._record = self._record_data()
        self._payload = S3Payload(None, self._record)

    def _record_data(self):
        """Helper for getting record data"""
        return {
            'awsRegion': 'us-east-1',
            's3': {
                'bucket': {
                    'name':  self._bucket
                },
                'object': {
                    'key': self._key,
                    'size': self._size
                }
            }
        }

    def test_bucket_property(self):
        """S3Payload - Bucket Property"""
        assert_equal(self._payload.bucket, self._bucket)

    def test_key_property(self):
        """S3Payload - Key Property"""
        assert_equal(self._payload.key, self._key)

    def test_size_property(self):
        """S3Payload - Size Property"""
        assert_equal(self._payload.size, self._size)

    def test_display_size_property(self):
        """S3Payload - Dispaly Size Property"""
        assert_equal(self._payload.display_size, '0.1KB')

    def test_unquote(self):
        """S3Payload - Unquote"""
        assert_equal(S3Payload._unquote('this%26that'), 'this&that')

    def test_check_size_exception_large(self):
        """S3Payload - Check Size, Too Large Raises Exception"""
        self._payload.raw_record['s3']['object']['size'] = 1024 * 1024 * 129  # 129 MB
        assert_raises(S3PayloadError, self._payload._check_size)

    def test_check_size_exception_zero(self):
        """S3Payload - Check Size, Zero Raises Exception"""
        self._payload.raw_record['s3']['object']['size'] = 0
        assert_raises(S3PayloadError, self._payload._check_size)

    def test_gz_reader(self):
        """S3Payload - GZ Reader"""
        record = {'key': 'value'}
        json_line = (json.dumps(record, separators=(',', ':')) + '\n').encode()
        with tempfile.SpooledTemporaryFile(max_size=10*1024) as reader:
            writer = gzip.GzipFile(filename='test', fileobj=reader)
            writer.writelines([
                json_line,
                json_line
            ])
            writer.close()
            reader.seek(0)
            gz_reader = S3Payload._gz_reader(reader)
            assert_equal(isinstance(gz_reader, gzip.GzipFile), True)
            assert_equal(gz_reader.read(), json_line + json_line)

    def test_gz_reader_non_gz(self):
        """S3Payload - GZ Reader, Non-gzip"""
        record = {'key': 'value'}
        json_line = (json.dumps(record, separators=(',', ':')) + '\n').encode()
        with tempfile.SpooledTemporaryFile(max_size=10*1024) as reader:
            reader.writelines([
                json_line,
                json_line
            ])
            reader.seek(0)
            non_gz_reader = S3Payload._gz_reader(reader)
            assert_equal(reader == non_gz_reader, True)

    def test_jsonlines_reader(self):
        """S3Payload - JSON Lines Reader"""
        record = {'key': 'value'}
        json_line = (json.dumps(record, separators=(',', ':')) + '\n').encode()
        with tempfile.SpooledTemporaryFile(max_size=10*1024) as reader:
            reader.writelines([
                json_line,
                json_line
            ])
            reader.seek(0)
            line_reader = S3Payload._jsonlines_reader(reader)
            assert_equal(reader != line_reader, True)

    def test_jsonlines_reader_fallback(self):
        """S3Payload - JSON Lines Reader, Fallback"""
        with tempfile.SpooledTemporaryFile(max_size=10*1024) as reader:
            reader.write('non-json-value\n'.encode())
            reader.seek(0)
            line_reader = S3Payload._jsonlines_reader(reader)
            assert_equal(reader == line_reader, True)

    def test_read_downloaded_object(self):
        """S3Payload - Read Downloaded Object"""
        record = {'key': 'value'}
        with tempfile.SpooledTemporaryFile(max_size=10*1024) as reader:
            reader.write(json.dumps(record, indent=2).encode())
            reader.seek(0)
            read_lines = list(S3Payload._read_downloaded_object(reader))
            assert_equal(read_lines, [(1, record)])

    def test_read_downloaded_object_fallback(self):
        """S3Payload - Read Downloaded Object, Fallback"""
        value = 'non-json-value\n'.encode()
        with tempfile.SpooledTemporaryFile(max_size=10*1024) as reader:
            reader.write(value)
            reader.seek(0)
            read_lines = list(S3Payload._read_downloaded_object(reader))
            assert_equal(read_lines, [(1, value)])

    @mock_s3
    def test_read_file(self):
        """S3Payload - Read File"""
        value = 'test_data'.encode()
        boto3.resource('s3').Bucket(self._bucket).create()
        boto3.resource('s3').Bucket(self._bucket).put_object(
            Key=self._key,
            Body=value
        )

        payload = S3Payload(None, self._record)
        read_lines = list(payload._read_file())
        assert_equal(read_lines, [(1, value)])

    @mock_s3
    @patch('logging.Logger.exception')
    def test_read_file_error(self, log_mock):
        """S3Payload - Read File, Exception"""
        boto3.resource('s3').Bucket(self._bucket).create()
        list(S3Payload(None, self._record)._read_file())
        log_mock.assert_called_with('Failed to download object from S3')

    def test_pre_parse(self):
        """S3Payload - Pre Parse"""
        with patch.object(S3Payload, '_read_file') as reader:
            reader.side_effect = [
                [
                    (1, {'key_01': 'value_01'}),
                    (2, {'key_02': 'value_02'})
                ]
            ]

            expected_result = [
                {'key_01': 'value_01'},
                {'key_02': 'value_02'}
            ]

            payload = S3Payload(None, self._record)
            result = [rec._record_data for rec in list(payload.pre_parse())]
            assert_equal(result, expected_result)


class TestCleanup(fake_filesystem_unittest.TestCase):
    """Test cleanup, including shredding of the tmp directory"""
    # pylint: disable=protected-access

    def setUp(self):
        self.setUpPyfakefs()
        temp_dir = tempfile.gettempdir()
        self.temp_file = os.path.join(temp_dir, 'file.json')
        self.temp_dir = os.path.join(temp_dir, 'sub_folder')

        # Create a file and folder to remove
        self.fs.create_file(self.temp_file)
        self.fs.create_dir(self.temp_dir)

    @patch('os.rmdir')
    @patch('subprocess.check_call')
    def test_cleanup(self, subproc_mock, os_mock):
        """S3Payload - Cleanup"""
        with patch.dict(os.environ, {'LAMBDA_RUNTIME_DIR': '/var/runtime'}):
            S3Payload._cleanup()
            subproc_mock.assert_called_with(
                ['shred', '--force', '--iterations=1', '--remove', self.temp_file]
            )

        os_mock.assert_called_with(self.temp_dir)

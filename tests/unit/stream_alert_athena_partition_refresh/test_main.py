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
# pylint: disable=attribute-defined-outside-init,protected-access
import os

from mock import call, Mock, patch
from nose.tools import assert_equal

from stream_alert.athena_partition_refresh.main import AthenaRefresher
from stream_alert.shared.config import load_config


@patch('logging.Logger.error')
def test_init_logging_bad(log_mock):
    """Athena Parition Refresh Init - Logging, Bad Level"""
    level = 'IFNO'
    with patch.dict(os.environ, {'LOGGER_LEVEL': level}):
        import stream_alert.athena_partition_refresh
        reload(stream_alert.athena_partition_refresh)

        message = str(call('Defaulting to INFO logging: %s',
                           ValueError('Unknown level: \'IFNO\'',)))

        assert_equal(str(log_mock.call_args_list[0]), message)


@patch('stream_alert.athena_partition_refresh.LOGGER.setLevel')
def test_init_logging_int_level(log_mock):
    """Athena Parition Refresh Init - Logging, Integer Level"""
    with patch.dict(os.environ, {'LOGGER_LEVEL': '10'}):
        import stream_alert.athena_partition_refresh
        reload(stream_alert.athena_partition_refresh)
        log_mock.assert_called_with(10)

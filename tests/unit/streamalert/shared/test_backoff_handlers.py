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
from unittest.mock import Mock, patch

from streamalert.shared.backoff_handlers import (backoff_handler,
                                                 giveup_handler,
                                                 success_handler)


def _get_details(with_wait=False):
    """Return a details dict that conforms to what the backoff handlers expected

    Only the on_backoff handler will contain a 'wait' value
    """
    details = {'elapsed': 1.2345, 'tries': 3, 'target': Mock(__name__='func')}
    if with_wait:
        details['wait'] = 1.0
    return details


@patch('logging.Logger.debug')
def test_backoff_handler_debug(log_mock):
    """Backoff Handlers - Backoff Handler, Debug"""
    on_backoff = backoff_handler()
    on_backoff(_get_details(True))
    log_mock.assert_called()


@patch('logging.Logger.info')
def test_backoff_handler_info(log_mock):
    """Backoff Handlers - Backoff Handler, Info"""
    on_backoff = backoff_handler(False)
    on_backoff(_get_details(True))
    log_mock.assert_called()


@patch('logging.Logger.debug')
def test_giveup_handler_debug(log_mock):
    """Backoff Handlers - Giveup Handler, Debug"""
    on_giveup = giveup_handler(True)
    on_giveup(_get_details())
    log_mock.assert_called()


@patch('logging.Logger.info')
def test_giveup_handler_info(log_mock):
    """Backoff Handlers - Giveup Handler, Info"""
    on_giveup = giveup_handler()
    on_giveup(_get_details())
    log_mock.assert_called()


@patch('logging.Logger.debug')
def test_success_handler_debug(log_mock):
    """Backoff Handlers - Success Handler, Debug"""
    on_success = success_handler(True)
    on_success(_get_details())
    log_mock.assert_called()


@patch('logging.Logger.info')
def test_success_handler_info(log_mock):
    """Backoff Handlers - Success Handler, Info"""
    on_success = success_handler()
    on_success(_get_details())
    log_mock.assert_called()

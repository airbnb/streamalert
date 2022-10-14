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
from streamalert.shared.logger import get_logger

LOGGER = get_logger(__name__)


def backoff_handler(debug_only=True):
    """Backoff logging handler for when polling occurs.

    Args:
        details (dict): Backoff context containing the number of tries,
            target function currently executing, kwargs, args, value,
            and wait time.
    """
    def _wrapped(details):
        message = '[Backoff]: Calling \'{}\' again in {:f} seconds with {:d} tries so far'.format(
            details['target'].__name__, details['wait'], details['tries'])
        if not debug_only:
            LOGGER.info(message)
        else:
            LOGGER.debug(message)

    return _wrapped


def success_handler(debug_only=False):
    """Backoff logging handler for when backoff succeeds.

    Args:
        details (dict): Backoff context containing the number of tries,
            target function currently executing, kwargs, args, value,
            and wait time.
    """
    def _wrapped(details):
        message = '[Backoff]: Successfully called \'{}\' after {:f} seconds and {:d} tries'.format(
            details['target'].__name__,
            details['elapsed'],
            details['tries'],
        )
        # We will only want to log backoff on_success when tries more than 1.
        if not debug_only and int(details['tries']) > 1:
            LOGGER.info(message)
        else:
            LOGGER.debug(message)

    return _wrapped


def giveup_handler(debug_only=False):
    """Backoff logging handler for when backoff gives up.

    Args:
        details (dict): Backoff context containing the number of tries,
            target function currently executing, kwargs, args, value,
            and wait time.
    """
    def _wrapped(details):
        message = '[Backoff]: Giving up calling \'{}\' after {:f} seconds and {:d} tries'.format(
            details['target'].__name__, details['elapsed'], details['tries'])
        if not debug_only:
            LOGGER.info(message)
        else:
            LOGGER.debug(message)

    return _wrapped

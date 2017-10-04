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

from stream_alert.shared import LOGGER


def backoff_handler(details):
    """Backoff logging handler for when polling occurs.

    Args:
        details (dict): Backoff context containing the number of tries,
            target function currently executing, kwargs, args, value,
            and wait time.
    """
    LOGGER.info('[Backoff]: Trying again in %f seconds after %d tries calling %s',
                details['wait'],
                details['tries'],
                details['target'].__name__)


def success_handler(details):
    """Backoff logging handler for when backoff succeeds.

    Args:
        details (dict): Backoff context containing the number of tries,
            target function currently executing, kwargs, args, value,
            and wait time.
    """
    LOGGER.debug('[Backoff]: Completed after %d tries calling %s',
                 details['tries'],
                 details['target'].__name__)


def giveup_handler(details):
    """Backoff logging handler for when backoff gives up.

    Args:
        details (dict): Backoff context containing the number of tries,
            target function currently executing, kwargs, args, value,
            and wait time.
    """
    LOGGER.info('[Backoff]: Exiting after %d tries calling %s',
                details['tries'],
                details['target'].__name__)

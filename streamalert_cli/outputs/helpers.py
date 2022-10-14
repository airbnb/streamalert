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


def output_exists(config, props, service, log_message=True):
    """Determine if this service and destination combo has already been created

    Args:
        config (dict): The outputs config that has been read from disk
        props (OrderedDict): Contains various OutputProperty items
        service (str): The service for which the user is adding a configuration
        log_message (bool): Optionally log the error message

    Returns:
        [boolean] True if the service/destination exists already
    """
    if service in config and props['descriptor'].value in config[service]:
        if log_message:
            LOGGER.error(
                'This descriptor %s is already configured for %s. '
                'Please select a new and unique descriptor', props['descriptor'].value, service)
        return True

    return False

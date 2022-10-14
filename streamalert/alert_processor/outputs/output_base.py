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
from abc import ABCMeta, abstractmethod
from collections import namedtuple

import backoff
import requests
import urllib3
from requests.exceptions import Timeout as ReqTimeout

from streamalert.alert_processor.outputs.credentials.provider import \
    OutputCredentialsProvider
from streamalert.shared.backoff_handlers import (backoff_handler,
                                                 giveup_handler,
                                                 success_handler)
from streamalert.shared.helpers.boto import REGION
from streamalert.shared.logger import get_logger

LOGGER = get_logger(__name__)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
OutputProperty = namedtuple('OutputProperty',
                            'description, value, input_restrictions, mask_input, cred_requirement')
OutputProperty.__new__.__defaults__ = ('', '', {' ', ':'}, False, False)


class OutputRequestFailure(Exception):
    """OutputRequestFailure handles any HTTP failures"""
    def __init__(self, response):
        super().__init__()
        self.response = response


def retry_on_exception(exceptions):
    """Decorator function to attempt retry based on passed exceptions"""
    def real_decorator(func):
        """Actual decorator to retry on exceptions"""
        @backoff.on_exception(
            backoff.expo,
            exceptions,  # This is a tuple with exceptions
            max_tries=OutputDispatcher.MAX_RETRY_ATTEMPTS,
            jitter=backoff.full_jitter,
            on_backoff=backoff_handler(),
            on_success=success_handler(),
            on_giveup=giveup_handler())
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)

        return wrapper

    return real_decorator


class StreamAlertOutput:
    """Class to be used as a decorator to register all OutputDispatcher subclasses"""
    _outputs = {}

    def __new__(cls, output):
        StreamAlertOutput._outputs[output.__service__] = output
        return output

    @classmethod
    def create_dispatcher(cls, service, config):
        """Returns the subclass that should handle this particular service

        Args:
            service (str): The service identifier for this output
            config (dict): The loaded output configuration dict

        Returns:
            OutputDispatcher: Subclass of OutputDispatcher to use for sending alerts
        """
        dispatcher = cls.get_dispatcher(service)
        return dispatcher(config) if dispatcher else False

    @classmethod
    def get_dispatcher(cls, service):
        """Returns the subclass that should handle this particular service

        Args:
            service (str): The service identifier for this output

        Returns:
            OutputDispatcher: Subclass of OutputDispatcher to use for sending alerts
        """
        try:
            return cls._outputs[service]
        except KeyError:
            LOGGER.error('Designated output service [%s] does not exist', service)

    @classmethod
    def get_all_outputs(cls):
        """Return a copy of the cache containing all of the output subclasses

        Returns:
            dict: Cached dictionary of all registered StreamAlertOutputs where
                the key is the service and the value is the class object
        """
        return cls._outputs.copy()


class OutputDispatcher(metaclass=ABCMeta):
    """OutputDispatcher is the base class to handle routing alerts to outputs

    Public methods:
        format_output_config: returns a formatted version of the outputs configuration
            that is to be written to disk
        get_user_defined_properties: returns any properties for this output that must be
            provided by the user. must be implemented by subclasses
        dispatch: handles the actual sending of alerts to the configured service. must
            be implemented by subclass
    """
    __service__ = NotImplemented

    # How many times it will attempt to retry something failing using backoff
    MAX_RETRY_ATTEMPTS = 5

    # _DEFAULT_REQUEST_TIMEOUT indicates how long the requests library will wait before timing
    # out for both get and post requests. This applies to both connection and read timeouts
    _DEFAULT_REQUEST_TIMEOUT = 3.05

    def __init__(self, config):
        self.region = REGION
        self.config = config

        self._credentials_provider = OutputCredentialsProvider(
            self.__service__,
            config=config,
            defaults=self._get_default_properties(),
            region=self.region)

    def _load_creds(self, descriptor):
        """Loads a dict of credentials relevant to this output descriptor

        Args:
            descriptor (str): unique identifier used to look up these credentials

        Returns:
            dict: the loaded credential info needed for sending alerts to this service
                or None if nothing gets loaded
        """
        return self._credentials_provider.load_credentials(descriptor)

    @classmethod
    def _log_status(cls, success, descriptor):
        """Log the status of sending the alerts

        Args:
            success (bool or dict): Indicates if the dispatching of alerts was successful
            descriptor (str): Service descriptor
        """
        if success:
            LOGGER.info('Successfully sent alert to %s:%s', cls.__service__, descriptor)
        else:
            LOGGER.error('Failed to send alert to %s:%s', cls.__service__, descriptor)

    @classmethod
    def _catch_exceptions(cls):
        """Classmethod that returns a tuple of the exceptions to catch"""
        default_exceptions = (OutputRequestFailure, ReqTimeout)
        if exceptions := cls._get_exceptions_to_catch():
            return default_exceptions + exceptions if isinstance(
                exceptions, tuple) else default_exceptions + (exceptions, )

        return default_exceptions

    @classmethod
    def _get_exceptions_to_catch(cls):
        """Classmethod that returns a tuple of the exceptions to catch"""

    @classmethod
    def _put_request(cls, url, params=None, headers=None, verify=True):
        """Method to return the json loaded response for this PUT request

        Args:
            url (str): Endpoint for this request
            params (dict): Payload to send with this request
            headers (dict): Dictionary containing request-specific header parameters
            verify (bool): Whether or not the server's SSL certificate should be verified
        Returns:
            dict: Contains the http response object
        """
        return requests.put(url,
                            headers=headers,
                            json=params,
                            verify=verify,
                            timeout=cls._DEFAULT_REQUEST_TIMEOUT)

    @classmethod
    def _put_request_retry(cls, url, params=None, headers=None, verify=True):
        """Method to return the json loaded response for this PUT request
        This method implements support for backoff to retry failed requests

        Args:
            url (str): Endpoint for this request
            params (dict): Payload to send with this request
            headers (dict): Dictionary containing request-specific header parameters
            verify (bool): Whether or not the server's SSL certificate should be verified
        Returns:
            dict: Contains the http response object
        Raises:
            OutputRequestFailure
        """
        @retry_on_exception(cls._catch_exceptions())
        def do_put_request():
            """Decorated nested function to perform the request with retry/backoff"""
            resp = cls._put_request(url, params, headers, verify)
            success = cls._check_http_response(resp)
            if not success:
                raise OutputRequestFailure(resp)

            return resp

        return do_put_request()

    @classmethod
    def _get_request(cls, url, params=None, headers=None, verify=True):
        """Method to return the json loaded response for this GET request

        Args:
            url (str): Endpoint for this request
            params (dict): Payload to send with this request
            headers (dict): Dictionary containing request-specific header parameters
            verify (bool): Whether or not the server's SSL certificate should be verified
        Returns:
            dict: Contains the http response object
        """
        return requests.get(url,
                            headers=headers,
                            params=params,
                            verify=verify,
                            timeout=cls._DEFAULT_REQUEST_TIMEOUT)

    @classmethod
    def _get_request_retry(cls, url, params=None, headers=None, verify=True):
        """Method to return the json loaded response for this GET request
        This method implements support for backoff to retry failed requests

        Args:
            url (str): Endpoint for this request
            params (dict): Payload to send with this request
            headers (dict): Dictionary containing request-specific header parameters
            verify (bool): Whether or not the server's SSL certificate should be verified
        Returns:
            dict: Contains the http response object
        Raises:
            OutputRequestFailure
        """
        @retry_on_exception(cls._catch_exceptions())
        def do_get_request():
            """Decorated nested function to perform the request with retry/backoff"""
            resp = cls._get_request(url, params, headers, verify)
            success = cls._check_http_response(resp)
            if not success:
                raise OutputRequestFailure(resp)

            return resp

        return do_get_request()

    @classmethod
    def _post_request(cls, url, data=None, headers=None, verify=True):
        """Method to return the json loaded response for this POST request

        Args:
            url (str): Endpoint for this request
            data (dict): Payload to send with this request
            headers (dict): Dictionary containing request-specific header parameters
            verify (bool): Whether or not the server's SSL certificate should be verified
        Returns:
            dict: Contains the http response object
        """
        return requests.post(url,
                             headers=headers,
                             json=data,
                             verify=verify,
                             timeout=cls._DEFAULT_REQUEST_TIMEOUT)

    @classmethod
    def _post_request_retry(cls, url, data=None, headers=None, verify=True):
        """Method to return the json loaded response for this POST request
        This method implements support for backoff to retry failed requests

        Args:
            url (str): Endpoint for this request
            data (dict): Payload to send with this request
            headers (dict): Dictionary containing request-specific header parameters
            verify (bool): Whether or not the server's SSL certificate should be verified
        Returns:
            dict: Contains the http response object
        Raises:
            OutputRequestFailure
        """
        @retry_on_exception(cls._catch_exceptions())
        def do_post_request():
            """Decorated nested function to perform the request with retry/backoff"""
            resp = cls._post_request(url, data, headers, verify)
            success = cls._check_http_response(resp)
            if not success:
                raise OutputRequestFailure(resp)

            return resp

        return do_post_request()

    @classmethod
    def _check_http_response(cls, response):
        """Method for checking for a valid HTTP response code

        Args:
            response (requests.Response): Response object from requests

        Returns:
            bool: Indicator of whether or not this request was successful
        """
        success = response is not None and (200 <= response.status_code <= 299)
        if not success:
            LOGGER.error('Encountered an error while sending to %s:\n%s', cls.__service__,
                         response.content)
        return success

    @classmethod
    def _get_default_properties(cls):
        """Base method for retrieving properties that should be hard-coded for this
        output service integration. This could include information such as a static
        url used for sending the alerts to this service, a static port, or other
        non-sensitive information.

        If information of this sort is needed, this should be overridden in output subclasses.

        NOTE: This should not contain any sensitive or use-case specific data. Information
        such as this should be retrieved from the user using `get_user_defined_properties()`
        so the user is prompted for the sensitive information at configuration time and said
        information is then sent to kms for encryption and s3 for storage.

        Returns:
            dict: Contains various default items for this output (ie: url)
        """

    @classmethod
    def format_output_config(cls, service_config, values):
        """Add this descriptor to the list of descriptor this service
           If the service doesn't exist, a new entry is added to an empty list

        Args:
            service_config (dict): Loaded configuration as a dictionary
            values (OrderedDict): Contains various OutputProperty items
        Returns:
            [list<string>] List of descriptors for this service
        """
        return service_config.get(cls.__service__, []) + [values['descriptor'].value]

    @classmethod
    @abstractmethod
    def get_user_defined_properties(cls):
        """Base method for retrieving properties that must be assigned by the user when
        configuring a new output for this service. This should include any information that
        is sensitive or use-case specific. For intance, if the url needed for this integration
        is unique to your situation, it should be supplied here.

        If information of this sort is needed, it should be added to the method that
        overrides this one in the subclass.

        At the very minimum, subclass functions should return an OrderedDict that contains
        the key 'descriptor' with a description of the integration being configured

        Returns:
            OrderedDict: Contains various OutputProperty items
        """

    @abstractmethod
    def _dispatch(self, alert, descriptor):
        """Send alerts to the given service.

        Args:
            alert (Alert): Alert instance which triggered a rule
            descriptor (str): Output descriptor (e.g. slack channel, pd integration)

        Returns:
            bool: True if alert was sent successfully, False otherwise
        """

    def dispatch(self, alert, output):
        """Send alerts to the given service.

        This wraps the protected subclass method of _dispatch to aid in usability

        Args:
            alert (Alert): Alert instance which triggered a rule
            output (str): Fully described output (e.g. "demisto:version1", "pagerduty:engineering"

        Returns:
            bool: True if alert was sent successfully, False otherwise
        """
        LOGGER.info('Sending %s to %s', alert, output)
        descriptor = output.split(':')[1]
        try:
            sent = bool(self._dispatch(alert, descriptor))
        except Exception:  # pylint: disable=broad-except
            LOGGER.exception('Exception when sending %s to %s. Alert:\n%s', alert, output,
                             repr(alert))
            sent = False

        self._log_status(sent, descriptor)

        return sent

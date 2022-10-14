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
import os
from collections import OrderedDict

from streamalert.alert_processor.helpers import compose_alert
from streamalert.alert_processor.outputs.output_base import (
    OutputDispatcher, OutputProperty, OutputRequestFailure, StreamAlertOutput)
from streamalert.shared.logger import get_logger

LOGGER = get_logger(__name__)


@StreamAlertOutput
class PhantomOutput(OutputDispatcher):
    """PhantomOutput handles all alert dispatching for Phantom"""
    __service__ = 'phantom'
    CONTAINER_ENDPOINT = 'rest/container'
    ARTIFACT_ENDPOINT = 'rest/artifact'

    @classmethod
    def get_user_defined_properties(cls):
        """Get properties that must be assigned by the user when configuring a new Phantom
        output.  This should be sensitive or unique information for this use-case that needs
        to come from the user.

        Every output should return a dict that contains a 'descriptor' with a description of the
        integration being configured.

        Phantom also requires a ph_auth_token that represnts an authorization token for this
        integration and a user provided url to use for alert dispatching. These values should be
        masked during input and are credential requirements.

        Returns:
            OrderedDict: Contains various OutputProperty items
        """
        return OrderedDict([
            ('descriptor',
             OutputProperty(description='a short and unique descriptor for this '
                            'Phantom integration')),
            ('ph_auth_token',
             OutputProperty(description='the auth token for this Phantom integration',
                            mask_input=True,
                            cred_requirement=True)),
            ('url',
             OutputProperty(description='the endpoint url for this Phantom integration',
                            mask_input=True,
                            input_restrictions={' '},
                            cred_requirement=True))
        ])

    @classmethod
    def _check_container_exists(cls, rule_name, container_url, headers):
        """Check to see if a Phantom container already exists for this rule

        Args:
            rule_name (str): The name of the rule that triggered the alert
            container_url (str): The constructed container url for this Phantom instance
            headers (dict): A dictionary containing header parameters

        Returns:
            int: ID of an existing Phantom container for this rule where the alerts
                will be sent or False if a matching container does not yet exists
        """
        # Limit the query to 1 page, since we only care if one container exists with
        # this name.
        params = {'_filter_name': f'"{rule_name}"', 'page_size': 1}
        try:
            resp = cls._get_request_retry(container_url, params, headers, False)
        except OutputRequestFailure:
            return False

        response = resp.json()
        return response and response.get('count') and response.get(
            'data')[0]['id'] if response else False

    @classmethod
    def _setup_container(cls, rule_name, rule_description, base_url, headers):
        """Establish a Phantom container to write the alerts to. This checks to see
        if an appropriate containers exists first and returns the ID if so.

        Args:
            rule_name (str): The name of the rule that triggered the alert
            base_url (str): The base url for this Phantom instance
            headers (dict): A dictionary containing header parameters

        Returns:
            int: ID of the Phantom container where the alerts will be sent
                or False if there is an issue getting the container id
        """
        container_url = os.path.join(base_url, cls.CONTAINER_ENDPOINT)

        if existing_id := cls._check_container_exists(rule_name, container_url, headers):
            return existing_id

        # Try to use the rule_description from the rule as the container description
        ph_container = {'name': rule_name, 'description': rule_description}
        try:
            resp = cls._post_request_retry(container_url, ph_container, headers, False)
        except OutputRequestFailure:
            return False

        response = resp.json()
        return response and response.get('id') if response else False

    def _dispatch(self, alert, descriptor):
        """Send alert to Phantom

        Publishing:
            By default this output sends the current publication in as JSON to Phantom.
            There is no "magic" field to "override" it: Simply publish what you want to send!

        Args:
            alert (Alert): Alert instance which triggered a rule
            descriptor (str): Output descriptor

        Returns:
            bool: True if alert was sent successfully, False otherwise
        """
        creds = self._load_creds(descriptor)
        if not creds:
            return False

        publication = compose_alert(alert, self, descriptor)
        record = alert.record

        headers = {"ph-auth-token": creds['ph_auth_token']}
        container_id = self._setup_container(alert.rule_name, alert.rule_description, creds['url'],
                                             headers)

        LOGGER.debug('sending alert to Phantom container with id %s', container_id)

        if not container_id:
            return False

        artifact = {
            'cef': record,
            'container_id': container_id,
            'data': publication,
            'name': 'Phantom Artifact',
            'label': 'Alert'
        }
        artifact_url = os.path.join(creds['url'], self.ARTIFACT_ENDPOINT)
        try:
            self._post_request_retry(artifact_url, artifact, headers, False)
        except OutputRequestFailure:
            return False

        return True

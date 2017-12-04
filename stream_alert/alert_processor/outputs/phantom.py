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
from collections import OrderedDict
import os

from stream_alert.alert_processor import LOGGER
from stream_alert.alert_processor.outputs.output_base import (
    OutputDispatcher,
    OutputProperty,
    OutputRequestFailure,
    StreamAlertOutput
)


@StreamAlertOutput
class PhantomOutput(OutputDispatcher):
    """PhantomOutput handles all alert dispatching for Phantom"""
    __service__ = 'phantom'
    CONTAINER_ENDPOINT = 'rest/container'
    ARTIFACT_ENDPOINT = 'rest/artifact'

    @classmethod
    def get_user_defined_properties(cls):
        """Get properties that must be asssigned by the user when configuring a new Phantom
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
        params = {
            '_filter_name': '"{}"'.format(rule_name),
            'page_size': 1
        }
        try:
            resp = cls._get_request_retry(container_url, params, headers, False)
        except OutputRequestFailure:
            return False

        response = resp.json()
        if not response:
            return False

        # If the count == 0 then we know there are no containers with this name and this
        # will evaluate to False. Otherwise there is at least one item in the list
        # of 'data' with a container id we can use
        return response and response.get('count') and response.get('data')[0]['id']

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

        # Check to see if there is a container already created for this rule name
        existing_id = cls._check_container_exists(rule_name, container_url, headers)
        if existing_id:
            return existing_id

        # Try to use the rule_description from the rule as the container description
        ph_container = {'name': rule_name, 'description': rule_description}
        try:
            resp = cls._post_request_retry(container_url, ph_container, headers, False)
        except OutputRequestFailure:
            return False

        response = resp.json()
        if not response:
            return False

        return response and response.get('id')

    def dispatch(self, **kwargs):
        """Send alert to Phantom

        Args:
            **kwargs: consists of any combination of the following items:
                descriptor (str): Service descriptor (ie: slack channel, pd integration)
                rule_name (str): Name of the triggered rule
                alert (dict): Alert relevant to the triggered rule
        """
        creds = self._load_creds(kwargs['descriptor'])
        if not creds:
            return self._log_status(False)

        headers = {"ph-auth-token": creds['ph_auth_token']}
        rule_desc = kwargs['alert']['rule_description']
        container_id = self._setup_container(kwargs['rule_name'], rule_desc,
                                             creds['url'], headers)

        LOGGER.debug('sending alert to Phantom container with id %s', container_id)

        success = False
        if container_id:
            artifact = {'cef': kwargs['alert']['record'],
                        'container_id': container_id,
                        'data': kwargs['alert'],
                        'name': 'Phantom Artifact',
                        'label': 'Alert'}
            artifact_url = os.path.join(creds['url'], self.ARTIFACT_ENDPOINT)
            try:
                success = self._post_request_retry(artifact_url, artifact, headers, False)
            except OutputRequestFailure:
                success = False

        return self._log_status(success)

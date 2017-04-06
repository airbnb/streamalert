'''
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
'''

import json
import logging
import os

from abc import abstractmethod
from collections import OrderedDict
from datetime import datetime

import boto3

from stream_alert.alert_processor.output_base import StreamOutputBase, OutputProperty

logging.basicConfig()
LOGGER = logging.getLogger('StreamOutput')

STREAM_OUTPUTS = {}

def output(cls):
    """Class decorator to register all stream outputs"""
    STREAM_OUTPUTS[cls.__service__] = cls

def get_output_dispatcher(service, region, s3_prefix):
    """Returns the subclass that should handle this particular service"""
    try:
        if service[:3] == 'aws':
            service = service.split('-')[-1]
        return STREAM_OUTPUTS[service](region, s3_prefix)
    except KeyError:
        LOGGER.error('designated output service [%s] does not exist', service)


@output
class PagerDutyOutput(StreamOutputBase):
    """PagerDutyOutput handles all alert dispatching for PagerDuty"""
    __service__ = 'pagerduty'

    @classmethod
    def get_default_properties(cls):
        """Get the standard url used for PagerDuty. This is the same for everyone, so
        is hard-coded here and does not need to be configured by the user

        Returns:
            [OrderedDict] Contains various OutputProperty items
        """
        return OrderedDict([
            ('url', 'https://events.pagerduty.com/generic/2010-04-15/create_event.json')
        ])

    def get_user_defined_properties(self):
        """Get properties that must be asssigned by the user when configuring a new PagerDuty
        output.  This should be sensitive or unique information for this use-case that needs
        to come from the user.

        Every output should return a dict that contains a 'descriptor' with a description of the
        integration being configured.

        PagerDuty also requires a service_key that represnts this integration. This
        value should be masked during input and is a credential requirement.

        Returns:
            [OrderedDict] Contains various OutputProperty items
        """
        return OrderedDict([
            ('descriptor',
             OutputProperty(description='a short and unique descriptor for this '
                                        'PagerDuty integration')),
            ('service_key',
             OutputProperty(description='the service key for this PagerDuty integration',
                            mask_input=True,
                            cred_requirement=True))
        ])

    def dispatch(self, **kwargs):
        """Send alert to Pagerduty

        Args:
            **kwargs: consists of any combination of the following items:
                descriptor [string]: Service descriptor (ie: slack channel, pd integration)
                rule_name [string]: Name of the triggered rule
                alert [dict]: Alert relevant to the triggered rule
        """
        creds = self._load_creds(kwargs['descriptor'])
        message = 'StreamAlert Rule Triggered - {}'.format(kwargs['rule_name'])
        values_json = json.dumps({
            'service_key': creds['service_key'],
            'event_type': 'trigger',
            'incident_key': kwargs['rule_name'],
            'description': message,
            'details': kwargs['alert'],
            'client': 'StreamAlert'
        })

        resp = self._request_helper(creds['url'], values_json)
        success = self._check_http_response(resp)

        self._log_status(success)


@output
class PhantomOutput(StreamOutputBase):
    """PhantomOutput handles all alert dispatching for Phantom"""
    __service__ = 'phantom'

    def get_user_defined_properties(self):
        """Get properties that must be asssigned by the user when configuring a new Phantom
        output.  This should be sensitive or unique information for this use-case that needs
        to come from the user.

        Every output should return a dict that contains a 'descriptor' with a description of the
        integration being configured.

        Phantom also requires a ph_auth_token that represnts an authorization token for this
        integration and a user provided url to use for alert dispatching. These values should be
        masked during input and are credential requirements.

        Returns:
            [OrderedDict] Contains various OutputProperty items
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

    def _setup_container(self, rule_name, container_url, headers):
        """Establish a Phantom container to write the alerts to

        Args:
            rule_name [string]: The name of the rule that triggered the alert
            container_url [string]: The contructed endpoint url for Phantom containers
            headers [dict]: A dictionary containing header parameters

        Returns:
            [integer] ID of the Phantom container where the alerts will be sent
        """
        message = 'StreamAlert Rule Triggered - {}'.format(rule_name)
        ph_container = {'name' : message,
                        'description' : message}
        container_string = json.dumps(ph_container)
        resp = self._request_helper(container_url, container_string, headers, False)

        if not self._check_http_response(resp):
            self._log_status(False)
            return False

        try:
            resp_dict = json.loads(resp.read())
        except ValueError as err:
            logging.error('An error occurred while decoding message to JSON: %s', err)
            return False

        return resp_dict and resp_dict['id']

    def dispatch(self, **kwargs):
        """Send alert to Phantom

        Args:
            **kwargs: consists of any combination of the following items:
                descriptor [string]: Service descriptor (ie: slack channel, pd integration)
                rule_name [string]: Name of the triggered rule
                alert [dict]: Alert relevant to the triggered rule
        """
        creds = self._load_creds(kwargs['descriptor'])
        if not creds:
            self._log_status(False)
            return

        headers = {"ph-auth-token": creds['ph_auth_token']}
        container_url = os.path.join(creds['url'], 'rest/container/')
        container_id = self._setup_container(kwargs['rule_name'], container_url, headers)

        success = False
        if container_id:
            artifact = {'cef' : kwargs['alert']['record'],
                        'container_id' : container_id,
                        'data' : kwargs['alert'],
                        'name' : 'Phantom Artifact',
                        'label' : 'Alert'}
            artifact_string = json.dumps(artifact)
            artifact_url = os.path.join(creds['url'], 'rest/artifact/')
            resp = self._request_helper(artifact_url, artifact_string, headers, False)

            success = self._check_http_response(resp)

        self._log_status(success)


@output
class SlackOutput(StreamOutputBase):
    """SlackOutput handles all alert dispatching for Slack"""
    __service__ = 'slack'

    def get_user_defined_properties(self):
        """Get properties that must be asssigned by the user when configuring a new Slack
        output.  This should be sensitive or unique information for this use-case that needs
        to come from the user.

        Every output should return a dict that contains a 'descriptor' with a description of the
        integration being configured.

        Slack also requires a user provided 'webhook' url that is comprised of the slack api url
        and the unique integration key for this output. This value should be should be masked
        during input and is a credential requirement.

        Returns:
            [OrderedDict] Contains various OutputProperty items
        """
        return OrderedDict([
            ('descriptor',
             OutputProperty(description='a short and unique descriptor for this Slack integration'
                                        '(ie: channel, group, etc)')),
            ('url',
             OutputProperty(description='the full Slack webhook url, including the secret',
                            cred_requirement=True))
        ])

    def dispatch(self, **kwargs):
        """Send alert text to Slack

        Args:
            **kwargs: consists of any combination of the following items:
                descriptor [string]: Service descriptor (ie: slack channel, pd integration)
                rule_name [string]: Name of the triggered rule
                alert [dict]: Alert relevant to the triggered rule
        """
        creds = self._load_creds(kwargs['descriptor'])
        url = os.path.join(creds['url'])

        slack_message = json.dumps({'text': '```{}```'.format(
            json.dumps(kwargs['alert'], indent=4)
        )})

        resp = self._request_helper(url, slack_message)
        success = self._check_http_response(resp)

        self._log_status(success)

class AWSOutput(StreamOutputBase):
    """Subclass to be inherited from for all AWS service outputs"""
    def format_output_config(self, service_config, values):
        """Format the output configuration for this AWS service to be written to disk
        AWS services are stored as a dictionary within the config instead of a list so
        we have access to the AWS arn for Terraform

        Args:
            service_config [dict]: The actual outputs config that has been read in
            values [OrderedDict]: Contains all the OutputProperty items for this service
        """
        return dict(service_config.get(self.__config_service__, {}),
                    **{values['descriptor'].value: values['arn'].value})

    @abstractmethod
    def dispatch(self, **kwargs):
        """Placeholder for implementation in the subclasses"""
        pass


@output
class S3Output(AWSOutput):
    """S3Output handles all alert dispatching for AWS S3"""
    __service__ = 's3'
    __config_service__ = 'aws-s3'

    def get_user_defined_properties(self):
        """Get properties that must be asssigned by the user when configuring a new S3
        output.  This should be sensitive or unique information for this use-case that needs
        to come from the user.

        Every output should return a dict that contains a 'descriptor' with a description of the
        integration being configured.

        S3 also requires a user provided AWS arn to be used for this service output. This
        value should not be masked during input and is not a credential requirement
        that needs encrypted.

        Returns:
            [OrderedDict] Contains various OutputProperty items
        """
        return OrderedDict([
            ('descriptor',
             OutputProperty(description=
                            'a short and unique descriptor for this S3 bucket (ie: bucket name)')),
            ('arn',
             OutputProperty(description='the AWS arn to use for this S3 bucket'))
        ])

    def dispatch(self, **kwargs):
        """Send alert to an S3 bucket

        Organizes alert into the following folder structure:
            service/entity/rule_name/datetime.json
        The alert gets dumped to a JSON string

        Args:
            **kwargs: consists of any combination of the following items:
                descriptor [string]: Service descriptor (ie: slack channel, pd integration)
                rule_name [string]: Name of the triggered rule
                alert [dict]: Alert relevant to the triggered rule
        """
        alert = kwargs['alert']
        service = alert['metadata']['source']['service']
        entity = alert['metadata']['source']['entity']
        current_date = datetime.now()
        alert_string = json.dumps(alert)

        client = boto3.client(self.__service__, region_name=self.region)
        resp = client.put_object(
            Body=alert_string,
            Bucket=self._format_s3_bucket('streamalerts'),
            Key='{}/{}/{}/dt={}/streamalerts_{}.json'.format(
                service,
                entity,
                kwargs['rule_name'],
                current_date.strftime('%Y-%m-%d-%H-%M'),
                current_date.isoformat('-')
            )
        )

        self._log_status(resp)

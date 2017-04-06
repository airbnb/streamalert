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

from collections import OrderedDict
from datetime import datetime

import boto3

from stream_alert.alert_processor.output_base import OutputBase, OutputProperty

logging.basicConfig()
LOGGER = logging.getLogger('StreamOutput')

STREAM_OUTPUTS = {}

def streamoutput(cls):
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


@streamoutput
class PagerDutyOutput(OutputBase):
    """PagerDutyOutput handles all alert dispatching for PagerDuty"""
    __service__ = 'pagerduty'

    @classmethod
    def get_default_properties(cls):
        """Get properties that are hard coded for this output service integration

        Returns:
            [OrderedDict] Contains various OutputProperty items
        """
        return OrderedDict([
            ('url', 'https://events.pagerduty.com/generic/2010-04-15/create_event.json')
        ])

    @classmethod
    def get_user_defined_properties(cls):
        """Get properties that must be asssigned by the user for a PagerDuty integration

        Returns:
            [OrderedDict] Contains various OutputProperty items
        """
        return OrderedDict([
            ('descriptor',
             OutputProperty(description='a short and unique descriptor for this '
                                        'PagerDuty integration')),
            ('service_key',
             OutputProperty(description='the service key for this PagerDuty integration',
                            is_secret=True))
        ])

    def dispatch(self, descriptor, rule_name, alert):
        """Send alert to Pagerduty

        Args:
            descriptor [string]: Service descriptor (ie: slack channel, pd integration)
            rule_name [string]: The name of the triggered rule
            alert [dict]: The alert relevant to the triggered rule
        """
        creds = self._load_creds(descriptor)
        message = "StreamAlert Rule Triggered - {}".format(rule_name)
        values_json = json.dumps({
            "service_key": creds['service_key'],
            "event_type": "trigger",
            "incident_key": rule_name,
            "description": message,
            "details": alert,
            "client": "StreamAlert"
        })

        resp = self._request_helper(creds['url'], values_json)
        success = self._check_http_response(resp)

        self._log_status(success)


@streamoutput
class PhantomOutput(OutputBase):
    """PhantomOutput handles all alert dispatching for Phantom"""
    __service__ = 'phantom'

    @classmethod
    def get_user_defined_properties(cls):
        """Get properties that must be asssigned by the user for a Phantom integration

        Returns:
            [OrderedDict] Contains various OutputProperty items
        """
        return OrderedDict([
            ('descriptor',
             OutputProperty(description='a short and unique descriptor for this '
                                        'Phantom integration')),
            ('ph_auth_token',
             OutputProperty(description='the auth token for this Phantom integration',
                            is_secret=True,
                            cred_requirement=True)),
            ('url',
             OutputProperty(description='the endpoint url for this Phantom integration',
                            is_secret=True,
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
        message = "StreamAlert Rule Triggered - {}".format(rule_name)
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

    def dispatch(self, descriptor, rule_name, alert):
        """Send alert to Phantom

        Args:
            descriptor [string]: Service descriptor (ie: slack channel, pd integration)
            rule_name [string]: The name of the triggered rule
            alert [dict]: The alert relevant to the triggered rule
        """

        creds = self._load_creds(descriptor)
        if not creds:
            self._log_status(False)
            return

        headers = {"ph-auth-token": creds['ph_auth_token']}
        container_url = os.path.join(creds['url'], 'rest/container/')
        container_id = self._setup_container(rule_name, container_url, headers)

        success = False
        if container_id:
            artifact = {"cef" : alert['record'],
                        "container_id" : container_id,
                        "data" : alert,
                        "name" : "Phantom Artifact",
                        "label" : "Alert"}
            artifact_string = json.dumps(artifact)
            artifact_url = os.path.join(creds['url'], 'rest/artifact/')
            resp = self._request_helper(artifact_url, artifact_string, headers, False)

            success = self._check_http_response(resp)

        self._log_status(success)


@streamoutput
class SlackOutput(OutputBase):
    """SlackOutput handles all alert dispatching for Slack"""
    __service__ = 'slack'

    @classmethod
    def get_user_defined_properties(cls):
        """Get properties that must be asssigned by the user for a Slack integration

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

    def dispatch(self, descriptor, _, alert):
        """Send alert text to Slack

        Args:
            descriptor [string]: Service descriptor (ie: slack channel, pd integration)
            alert [dict]: The alert relevant to the triggered rule
        """
        creds = self._load_creds(descriptor)
        url = os.path.join(creds['url'])

        slack_message = json.dumps({'text': '```{}```'.format(
            json.dumps(alert, indent=4)
        )})

        resp = self._request_helper(url, slack_message)
        success = self._check_http_response(resp)

        self._log_status(success)

class AWSOutput(OutputBase):
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


@streamoutput
class S3Output(AWSOutput):
    """S3Output handles all alert dispatching for AWS S3"""
    __service__ = 's3'
    __config_service__ = 'aws-s3'

    @classmethod
    def get_user_defined_properties(cls):
        """Get properties that must be asssigned by the user for an AWS S3 bucket integration

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

    def dispatch(self, _, rule_name, alert):
        """Send alert to an S3 bucket

        Organizes alert into the following folder structure:
            service/entity/rule_name/datetime.json
        The alert gets dumped to a JSON string

        Args:
            rule_name [string]: The name of the triggered rule
            alert [dict]: The alert relevant to the triggered rule
        """
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
                rule_name,
                current_date.strftime('%Y-%m-%d-%H-%M'),
                current_date.isoformat('-')
            )
        )

        self._log_status(resp)

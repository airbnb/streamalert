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
from abc import abstractmethod
import cgi
from collections import OrderedDict
from datetime import datetime
import json
import os
import urllib
import uuid

import boto3

from stream_alert.alert_processor import LOGGER
from stream_alert.alert_processor.output_base import OutputProperty, StreamOutputBase

# STREAM_OUTPUTS will contain each subclass of the StreamOutputBase
# All included subclasses are designated using the '@output' class decorator
# The keys are the name of the service and the value is the class itself
# {cls.__service__: <cls>}
STREAM_OUTPUTS = {}


def output(cls):
    """Class decorator to register all stream outputs"""
    STREAM_OUTPUTS[cls.__service__] = cls


def get_output_dispatcher(service, region, function_name, config):
    """Returns the subclass that should handle this particular service"""
    try:
        return STREAM_OUTPUTS[service](region, function_name, config)
    except KeyError:
        LOGGER.error('designated output service [%s] does not exist', service)


@output
class PagerDutyOutput(StreamOutputBase):
    """PagerDutyOutput handles all alert dispatching for PagerDuty"""
    __service__ = 'pagerduty'

    @classmethod
    def _get_default_properties(cls):
        """Get the standard url used for PagerDuty. This value the same for everyone, so
        is hard-coded here and does not need to be configured by the user

        Returns:
            dict: Contains various default items for this output (ie: url)
        """
        return {
            'url': 'https://events.pagerduty.com/generic/2010-04-15/create_event.json'
        }

    def get_user_defined_properties(self):
        """Get properties that must be asssigned by the user when configuring a new PagerDuty
        output.  This should be sensitive or unique information for this use-case that needs
        to come from the user.

        Every output should return a dict that contains a 'descriptor' with a description of the
        integration being configured.

        PagerDuty also requires a service_key that represnts this integration. This
        value should be masked during input and is a credential requirement.

        Returns:
            OrderedDict: Contains various OutputProperty items
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
                descriptor (str): Service descriptor (ie: slack channel, pd integration)
                rule_name (str): Name of the triggered rule
                alert (dict): Alert relevant to the triggered rule
        """
        creds = self._load_creds(kwargs['descriptor'])
        if not creds:
            return self._log_status(False)

        message = 'StreamAlert Rule Triggered - {}'.format(kwargs['rule_name'])
        rule_desc = kwargs['alert']['rule_description']
        details = {
            'rule_description': rule_desc,
            'record': kwargs['alert']['record']
        }
        values_json = json.dumps({
            'service_key': creds['service_key'],
            'event_type': 'trigger',
            'description': message,
            'details': details,
            'client': 'StreamAlert'
        })

        resp = self._request_helper(creds['url'], values_json)
        success = self._check_http_response(resp)

        if not success:
            response_value = json.load(resp)
            error_message = response_value['error']['message']
            detailed_errors = response_value['error']['errors']
            LOGGER.error('Encountered an error while sending to PagerDuty: %s\n%s',
                         error_message,
                         '\n'.join(detailed_errors))

        return self._log_status(success)


@output
class PhantomOutput(StreamOutputBase):
    """PhantomOutput handles all alert dispatching for Phantom"""
    __service__ = 'phantom'
    CONTAINER_ENDPOINT = 'rest/container'
    ARTIFACT_ENDPOINT = 'rest/artifact'

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

    def _check_container_exists(self, rule_name, container_url, headers):
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
        # this name. This should not be a problem, but utilize urllib.quote to
        # replace any unsafe characters in the rule_name
        query_url = '{}?_filter_name="{}"&page_size=1'.format(container_url,
                                                              urllib.quote(rule_name))

        # Passing None for the data param ensures a GET request happens
        resp = self._request_helper(query_url, None, headers, False)

        if not self._check_http_response(resp):
            return False

        try:
            resp_dict = json.loads(resp.read())
        except ValueError as err:
            LOGGER.error('An error occurred while decoding Phantom container query '
                         'response to JSON: %s', err)
            return False

        # If the count == 0 then we know there are no containers with this name and this
        # will evaluate to False. Otherwise there is at least one item in the list
        # of 'data' with a container id we can use
        return resp_dict and resp_dict['count'] and resp_dict['data'][0]['id']

    def _setup_container(self, rule_name, rule_description, base_url, headers):
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
        container_url = os.path.join(base_url, self.CONTAINER_ENDPOINT)

        # Check to see if there is a container already created for this rule name
        existing_id = self._check_container_exists(rule_name, container_url, headers)
        if existing_id:
            return existing_id

        # Try to use the rule_description from the rule as the container description
        ph_container = {'name': rule_name, 'description': rule_description}
        container_string = json.dumps(ph_container)
        resp = self._request_helper(container_url, container_string, headers, False)

        if not self._check_http_response(resp):
            return False

        try:
            resp_dict = json.loads(resp.read())
        except ValueError as err:
            LOGGER.error('An error occurred while decoding Phantom container creation '
                         'response to JSON: %s', err)
            return False

        return resp_dict and resp_dict['id']

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
            artifact_string = json.dumps(artifact)
            artifact_url = os.path.join(creds['url'], self.ARTIFACT_ENDPOINT)
            resp = self._request_helper(artifact_url, artifact_string, headers, False)

            success = self._check_http_response(resp)

        return self._log_status(success)


@output
class SlackOutput(StreamOutputBase):
    """SlackOutput handles all alert dispatching for Slack"""
    __service__ = 'slack'
    # Slack recommends no messages larger than 4000 bytes. This does not account for unicode
    MAX_MESSAGE_SIZE = 4000

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
            OrderedDict: Contains various OutputProperty items
        """
        return OrderedDict([
            ('descriptor',
             OutputProperty(description='a short and unique descriptor for this Slack integration '
                                        '(ie: channel, group, etc)')),
            ('url',
             OutputProperty(description='the full Slack webhook url, including the secret',
                            mask_input=True,
                            cred_requirement=True))
        ])

    @classmethod
    def _format_message(cls, rule_name, alert):
        """Format the message to be sent to slack.

        Args:
            rule_name (str): The name of the rule that triggered the alert
            alert: Alert relevant to the triggered rule

        Returns:
            str: formatted message with attachments to send to Slack.
                The message will look like:
                    StreamAlert Rule Triggered: rule_name
                    Rule Description:
                    This will be the docstring from the rule, sent as the rule_description

                    Record (Part 1 of 2):
                    ...
        """
        # Convert the alert we have to a nicely formatted string for slack
        alert_text = '\n'.join(cls._json_to_slack_mrkdwn(alert['record'], 0))
        # Slack requires escaping the characters: '&', '>' and '<' and cgi does just that
        alert_text = cgi.escape(alert_text)
        messages = []
        index = cls.MAX_MESSAGE_SIZE
        while alert_text != '':
            if len(alert_text) <= index:
                messages.append(alert_text)
                break

            # Find the closest line break prior to this index
            while index > 1 and alert_text[index] != '\n':
                index -= 1

            # Append the message part up until this index, and move to the next chunk
            messages.append(alert_text[:index])
            alert_text = alert_text[index+1:]

            index = cls.MAX_MESSAGE_SIZE

        header_text = '*StreamAlert Rule Triggered: {}*'.format(rule_name)
        full_message = {
            'text': header_text,
            'mrkdwn': True,
            'attachments': []
        }

        for index, message in enumerate(messages):
            title = 'Record:'
            if len(messages) > 1:
                title = 'Record (Part {} of {}):'.format(index+1, len(messages))
            rule_desc = ''
            # Only print the rule description on the first attachment
            if index == 0:
                rule_desc = alert['rule_description']
                rule_desc = '*Rule Description:*\n{}\n'.format(rule_desc)

            # Add this attachemnt to the full message array of attachments
            full_message['attachments'].append({
                'fallback': header_text,
                'color': '#b22222',
                'pretext': rule_desc,
                'title': title,
                'text': message,
                'mrkdwn_in': ['text', 'pretext']
            })

        # Return the dumped json payload to be sent to slack
        return json.dumps(full_message)

    @classmethod
    def _json_to_slack_mrkdwn(cls, json_values, indent_count):
        """Translate a json object into a more human-readable list of lines
        This will handle recursion of all nested maps and lists within the object

        Args:
            json_values: variant to be translated (could be json map, list, etc)
            indent_count (int): Number of tabs to prefix each line with

        Returns:
            list: strings that have been properly tabbed and formatted for printing
        """
        tab = '\t'
        all_lines = []
        if isinstance(json_values, dict):
            all_lines = cls._json_map_to_text(json_values, tab, indent_count)
        elif isinstance(json_values, list):
            all_lines = cls._json_list_to_text(json_values, tab, indent_count)
        else:
            all_lines.append('{}'.format(json_values))

        return all_lines

    @classmethod
    def _json_map_to_text(cls, json_values, tab, indent_count):
        """Translate a map from json (dict) into a more human-readable list of lines
        This will handle recursion of all nested maps and lists within the map

        Args:
            json_values (dict): dictionary to be iterated over and formatted
            tab (str): string value to use for indentation
            indent_count (int): Number of tabs to prefix each line with

        Returns:
            list: strings that have been properly tabbed and formatted for printing
        """
        all_lines = []
        for key, value in json_values.iteritems():
            if isinstance(value, (dict, list)) and value:
                all_lines.append('{}*{}:*'.format(tab*indent_count, key))
                all_lines.extend(cls._json_to_slack_mrkdwn(value, indent_count+1))
            else:
                new_lines = cls._json_to_slack_mrkdwn(value, indent_count+1)
                if len(new_lines) == 1:
                    all_lines.append('{}*{}:* {}'.format(tab*indent_count, key, new_lines[0]))
                elif new_lines:
                    all_lines.append('{}*{}:*'.format(tab*indent_count, key))
                    all_lines.extend(new_lines)
                else:
                    all_lines.append('{}*{}:* {}'.format(tab*indent_count, key, value))

        return all_lines

    @classmethod
    def _json_list_to_text(cls, json_values, tab, indent_count):
        """Translate a list from json into a more human-readable list of lines
        This will handle recursion of all nested maps and lists within the list

        Args:
            json_values (list): list to be iterated over and formatted
            tab (str): string value to use for indentation
            indent_count (int): Number of tabs to prefix each line with

        Returns:
            list: strings that have been properly tabbed and formatted for printing
        """
        all_lines = []
        for index, value in enumerate(json_values):
            if isinstance(value, (dict, list)) and value:
                all_lines.append('{}*[{}]*'.format(tab*indent_count, index+1))
                all_lines.extend(cls._json_to_slack_mrkdwn(value, indent_count+1))
            else:
                new_lines = cls._json_to_slack_mrkdwn(value, indent_count+1)
                if len(new_lines) == 1:
                    all_lines.append('{}*[{}]* {}'.format(tab*indent_count, index+1, new_lines[0]))
                elif new_lines:
                    all_lines.append('{}*[{}]*'.format(tab*indent_count, index+1))
                    all_lines.extend(new_lines)
                else:
                    all_lines.append('{}*[{}]* {}'.format(tab*indent_count, index+1, value))

        return all_lines

    def dispatch(self, **kwargs):
        """Send alert text to Slack

        Args:
            **kwargs: consists of any combination of the following items:
                descriptor (str): Service descriptor (ie: slack channel, pd integration)
                rule_name (str): Name of the triggered rule
                alert (dict): Alert relevant to the triggered rule
        """
        creds = self._load_creds(kwargs['descriptor'])
        if not creds:
            return self._log_status(False)

        slack_message = self._format_message(kwargs['rule_name'], kwargs['alert'])

        resp = self._request_helper(creds['url'], slack_message)
        success = self._check_http_response(resp)

        if not success:
            LOGGER.error('Encountered an error while sending to Slack: %s',
                         resp.read())

        return self._log_status(success)


class AWSOutput(StreamOutputBase):
    """Subclass to be inherited from for all AWS service outputs"""
    def format_output_config(self, service_config, values):
        """Format the output configuration for this AWS service to be written to disk
        AWS services are stored as a dictionary within the config instead of a list so
        we have access to the AWS value (arn/bucket name/etc) for Terraform

        Args:
            service_config (dict): The actual outputs config that has been read in
            values (OrderedDict): Contains all the OutputProperty items for this service

        Returns:
            dict{<string>: <string>}: Updated dictionary of descriptors and
                values for this AWS service needed for the output configuration
            NOTE: S3 requires the bucket name, not an arn, for this value.
                Instead of implementing this differently in subclasses, all AWSOutput
                subclasses should use a generic 'aws_value' to store the value for the
                descriptor used in configuration
        """
        return dict(service_config.get(self.__service__, {}),
                    **{values['descriptor'].value: values['aws_value'].value})

    @abstractmethod
    def dispatch(self, **kwargs):
        """Placeholder for implementation in the subclasses"""
        pass


@output
class S3Output(AWSOutput):
    """S3Output handles all alert dispatching for AWS S3"""
    __service__ = 'aws-s3'

    def get_user_defined_properties(self):
        """Get properties that must be asssigned by the user when configuring a new S3
        output.  This should be sensitive or unique information for this use-case that needs
        to come from the user.

        Every output should return a dict that contains a 'descriptor' with a description of the
        integration being configured.

        S3 also requires a user provided bucket name to be used for this service output. This
        value should not be masked during input and is not a credential requirement
        that needs encrypted.

        Returns:
            OrderedDict: Contains various OutputProperty items
        """
        return OrderedDict([
            ('descriptor',
             OutputProperty(
                 description='a short and unique descriptor for this S3 bucket (ie: bucket name)')),
            ('aws_value',
             OutputProperty(description='the AWS S3 bucket name to use for this S3 configuration'))
        ])

    def dispatch(self, **kwargs):
        """Send alert to an S3 bucket

        Organizes alert into the following folder structure:
            service/entity/rule_name/datetime.json
        The alert gets dumped to a JSON string

        Args:
            **kwargs: consists of any combination of the following items:
                descriptor (str): Service descriptor (ie: slack channel, pd integration)
                rule_name (str): Name of the triggered rule
                alert (dict): Alert relevant to the triggered rule
        """
        alert = kwargs['alert']
        service = alert['source_service']
        entity = alert['source_entity']

        current_date = datetime.now()

        s3_alert = alert
        # JSON dump the alert to retain a consistent alerts schema across log types.
        # This will get replaced by a UUID which references a record in a
        # different table in the future.
        s3_alert['record'] = json.dumps(s3_alert['record'])
        alert_string = json.dumps(s3_alert)

        bucket = self.config[self.__service__][kwargs['descriptor']]

        # Prefix with alerts to account for generic non-streamalert buckets
        # Produces the following key format:
        #   alerts/dt=2017-01-25-00/kinesis_my-stream_my-rule_uuid.json
        # Keys need to be unique to avoid object overwriting
        key = 'alerts/dt={}/{}_{}_{}_{}.json'.format(
            current_date.strftime('%Y-%m-%d-%H'),
            service,
            entity,
            alert['rule_name'],
            uuid.uuid4()
        )

        LOGGER.debug('Sending alert to S3 bucket %s with key %s', bucket, key)

        client = boto3.client('s3', region_name=self.region)
        resp = client.put_object(Body=alert_string,
                                 Bucket=bucket,
                                 Key=key)

        return self._log_status(resp)


@output
class LambdaOutput(AWSOutput):
    """LambdaOutput handles all alert dispatching to AWS Lambda"""
    __service__ = 'aws-lambda'

    def get_user_defined_properties(self):
        """Get properties that must be asssigned by the user when configuring a new Lambda
        output.  This should be sensitive or unique information for this use-case that needs
        to come from the user.

        Every output should return a dict that contains a 'descriptor' with a description of the
        integration being configured.

        Sending to Lambda also requires a user provided Lambda function name and optional qualifier
        (if applicabale for the user's use case). A fully-qualified AWS ARN is also acceptable for
        this value. This value should not be masked during input and is not a credential requirement
        that needs encrypted.

        Returns:
            OrderedDict: Contains various OutputProperty items
        """
        return OrderedDict([
            ('descriptor',
             OutputProperty(description='a short and unique descriptor for this Lambda function '
                                        'configuration (ie: abbreviated name)')),
            ('aws_value',
             OutputProperty(description='the AWS Lambda function name, with the optional '
                                        'qualifier (aka \'alias\'), to use for this '
                                        'configuration (ie: output_function:qualifier)',
                            input_restrictions={' '})),
        ])

    def dispatch(self, **kwargs):
        """Send alert to a Lambda function

        The alert gets dumped to a JSON string to be sent to the Lambda function

        Args:
            **kwargs: consists of any combination of the following items:
                descriptor (str): Service descriptor (ie: slack channel, pd integration)
                rule_name (str): Name of the triggered rule
                alert (dict): Alert relevant to the triggered rule
        """
        alert = kwargs['alert']
        alert_string = json.dumps(alert['record'])
        function_name = self.config[self.__service__][kwargs['descriptor']]

        # Check to see if there is an optional qualifier included here
        # Acceptable values for the output configuration are the full ARN,
        # a function name followed by a qualifier, or just a function name:
        #   'arn:aws:lambda:aws-region:acct-id:function:function-name:prod'
        #   'function-name:prod'
        #   'function-name'
        # Checking the length of the list for 2 or 8 should account for all
        # times a qualifier is provided.
        parts = function_name.split(':')
        if len(parts) == 2 or len(parts) == 8:
            function = parts[-2]
            qualifier = parts[-1]
        else:
            function = parts[-1]
            qualifier = None

        LOGGER.debug('Sending alert to Lambda function %s', function_name)

        client = boto3.client('lambda', region_name=self.region)
        # Use the qualifier if it's available. Passing an empty qualifier in
        # with `Qualifier=''` or `Qualifier=None` does not work and thus we
        # have to perform different calls to client.invoke().
        if qualifier:
            resp = client.invoke(FunctionName=function,
                                 InvocationType='Event',
                                 Payload=alert_string,
                                 Qualifier=qualifier)
        else:
            resp = client.invoke(FunctionName=function,
                                 InvocationType='Event',
                                 Payload=alert_string)

        return self._log_status(resp)

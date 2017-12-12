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
from datetime import datetime

import boto3
from botocore.exceptions import ClientError

from stream_alert_cli.logger import LOGGER_CLI


class LambdaVersion(object):
    """Publish new versions of the StreamAlert Lambda functions.

    Each Lambda function is configured with a production alias.
    This alias points to the latest published version of the
    Lambda function.

    After a Lambda package is versioned, the StreamAlert config
    is updated, and then Terraform runs to update the alias with
    the new version number.

    All StreamAlert setups should start with "$LATEST".
    """

    def __init__(self, **kwargs):
        """Initialize the version publishing

        Keyword Args:
            config (CLIConfig): Loaded StreamAlert CLI Config
            package (LambdaPackage): The created Lambda Package
        """
        self.config = kwargs['config']
        self.package = kwargs['package']

    @staticmethod
    def _version_helper(**kwargs):
        """Make the API call to publish the Lambda function

        Keyword Arguments:
            client (boto3.client): Lambda boto3 client
            function_name (str): Lambda function name to publish
            code_sha_256 (str): The SHA256 of the current $LATEST package
            date (datetime): Current time

        Returns:
            int: Version OR False if the publish fails
        """
        client = kwargs.get('client')
        if not client:
            LOGGER_CLI.error('No AWS client provided')
            return False

        try:
            version = client.publish_version(
                FunctionName=kwargs['function_name'],
                CodeSha256=kwargs['code_sha_256'],
                Description='Publish Lambda {} on {}'.format(kwargs['function_name'],
                                                             kwargs['date'])
            )['Version']
        except ClientError as err:
            LOGGER_CLI.error(err)
            return False

        return int(version)

    def _publish_helper(self, **kwargs):
        """Handle clustered or single Lambda function publishing

        Keyword Arguments:
            cluster (str): The cluster to deploy to, this is optional

        Returns:
            bool: Result of the function publishes
        """
        cluster = kwargs.get('cluster')
        # Clustered Lambda functions have a different naming pattern
        if cluster:
            region = self.config['clusters'][cluster]['region']
            function_name = '{}_{}_streamalert_{}'.format(
                self.config['global']['account']['prefix'],
                cluster,
                self.package.package_name
            )
        else:
            region = self.config['global']['account']['region']
            function_name = '{}_streamalert_{}'.format(
                self.config['global']['account']['prefix'],
                self.package.package_name
            )

        # Configure the Lambda client
        client = boto3.client('lambda', region_name=region)
        code_sha_256 = self.config['lambda'][self.package.config_key]['source_current_hash']

        # Publish the function(s)
        # TODO: move the extra logic into the LambdaPackage subclasses instead of this
        if self.package.package_name == 'stream_alert_app':
            if not 'stream_alert_apps' in self.config['clusters'][cluster]['modules']:
                return True # nothing to publish for this cluster

            for app_name, app_info in self.config['clusters'][cluster]['modules'] \
                ['stream_alert_apps'].iteritems():
                # Name follows format: '<prefix>_<cluster>_<service>_<app_name>_app'
                function_name = '_'.join([self.config['global']['account']['prefix'], cluster,
                                          app_info['type'], app_name, 'app'])
                new_version = self._publish(client, function_name, code_sha_256)
                if not new_version:
                    continue

                LOGGER_CLI.info('Published version %s for %s:%s',
                                new_version, cluster, function_name)

                app_info['current_version'] = new_version

        else:

            new_version = self._publish(client, function_name, code_sha_256)
            if not new_version:
                return False

            # Update the config
            if cluster:
                LOGGER_CLI.info('Published version %s for %s:%s',
                                new_version, cluster, function_name)
                self.config['clusters'][cluster]['modules']['stream_alert'] \
                    [self.package.package_name]['current_version'] = new_version
            else:
                LOGGER_CLI.info('Published version %s for %s',
                                new_version, function_name)
                self.config['lambda'][self.package.config_key]['current_version'] = new_version

        self.config.write()

        return True

    def _publish(self, client, function_name, code_sha_256):
        """Publish the function"""
        date = datetime.utcnow().strftime("%Y%m%d_T%H%M%S")
        LOGGER_CLI.debug('Publishing %s', function_name)
        new_version = self._version_helper(
            client=client,
            function_name=function_name,
            code_sha_256=code_sha_256,
            date=date)

        return new_version

    def publish_function(self, **kwargs):
        """Main Publish Function method

        Keyword Args:
            clustered_deploy (bool): Identifies cluster based Lambdas
            clusters (list): The list of clusters to deploy to
        """
        clustered_deploy = kwargs.get('clustered_deploy', True)
        clusters = kwargs.get('clusters', []) or self.config.clusters()

        if clustered_deploy:
            for cluster in clusters:
                if not self._publish_helper(cluster=cluster):
                    return False
        else:
            if not self._publish_helper():
                return False

        return True

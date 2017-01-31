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
import subprocess

from collections import namedtuple
from jinja2 import Environment, PackageLoader

from stream_alert_cli.package import AlertPackage, OutputPackage
from stream_alert_cli.version import LambdaVersion
from stream_alert_cli.test import stream_alert_test
from stream_alert import __version__ as stream_alert_version
from stream_alert_output import __version__ as stream_alert_output_version

class InvalidClusterName(Exception):
    pass

class StreamAlertCLI(object):
    CONFIG_FILE = 'variables.json'

    def __init__(self):
        self.config = self._load_config()

    def refresh_config(self):
        self.config = self._load_config()

    def run(self, options):
        """Main Stream Alert CLI handler.

        Args:
            options (dict): command line arguments passed from the argparser.
                Contains the following keys for terraform commands:
                    (command, subcommand, target)
                Contains the following keys for lambda commands:
                    (command, subcommand, env, func, source)
        """
        logging.info("Stream Alert CLI\nIssues? Report here: https://github.com/airbnb/streamalert/issues")
        prereqs_message = 'Terraform not found! Please install and add to' \
                          ' your $PATH:\n' \
                          '$ export PATH=$PATH:/usr/local/terraform/bin'
        terraform_check = self._cmd(['terraform', 'version'], prereqs_message, quiet=True)
        # There is no `else` since it's handled in the self._cmd call
        if terraform_check:
            if options.command == 'lambda':
                self._lambda_runner(options)
            elif options.command == 'terraform':
                self._terraform_runner(options)

    def _lambda_runner(self, options):
        """Handle all Lambda CLI operations."""
        if options.subcommand == 'deploy':
            self.deploy(options)
        elif options.subcommand == 'rollback':
            raise NotImplementedError
        elif options.subcommand == 'test':
            stream_alert_test(options)

    def _terraform_runner(self, options):
        """Handle all Lambda CLI operations."""

        if options.subcommand == 'build':
            if options.target:
                target = options.target
                targets = ['module.{}_{}'.format(target, cluster) for cluster in self.config['clusters'].keys()]
                self._tf_runner(targets=targets)
            else:
                self._tf_runner()

        elif options.subcommand == 'init':
            logging.info('Initializing StreamAlert')
            self.generate_tf_files()
            init_targets = [
                'aws_s3_bucket.lambda_source',
                'aws_s3_bucket.integration_testing',
                'aws_kms_key.stream_alert_secrets',
                'aws_kms_alias.stream_alert_secrets'
            ]
            # build init infrastructure
            self._tf_runner(targets=init_targets, refresh_state=False)

            logging.info('Building infrastructure')
            DeployOptions = namedtuple('DeployOptions', 'func, env')
            # deploy both lambda functions to staging
            self.deploy(DeployOptions('*', 'staging'))
            # create all remainder infrastructure
            self._tf_runner()
            # refresh config to get modified variables
            self.refresh_config()
            # deploy to production
            self.deploy(DeployOptions('alert', 'production'))

        elif options.subcommand == 'destroy':
            self._tf_runner(action='destroy')

        elif options.subcommand == 'status':
            self.status()

    @staticmethod
    def _cmd(args=None, error_message="An error occured while running: {args}", **kwargs):
        """Helper function to run commands with error handling"""
        if kwargs.get('quiet', None):
            stdout_option = open(os.devnull, 'w')
        else:
            stdout_option = None
        if not args:
            raise Exception('No command arguments given')
        try:
            subprocess.check_call(args, stdout=stdout_option, cwd='terraform')
        except (OSError, subprocess.CalledProcessError) as e:
            logging.warn(error_message.format(args=' '.join(args)))
            return False
        return True

    def _load_config(self):
        """Load the `variables.json` configuration file.

        Provides settings for uploading the StreamAlert lambda
        code, and publishing versions to production and
        staging environments.
        """
        if not os.path.isfile(self.CONFIG_FILE):
            return False
        with open(self.CONFIG_FILE) as data:
            return json.load(data)

    @staticmethod
    def _continue_prompt():
        """Continue prompt used before applying Terraform plans."""
        required_responses = ['yes', 'no']
        response = ''
        while response not in required_responses:
            response = raw_input('\nWould you like to continue? (yes or no): ')
        if response == 'yes':
            return True
        return False

    def _tf_runner(self, **kwargs):
        """Initalizer for StreamAlert infrastructure.

        Steps:
            - resolve modules with `terraform get`
            - run `terraform plan` for the given targets
            - if plan is successful and user confirms prompt,
              then the infrastructure is applied.

        kwargs:
            targets: a list of Terraform targets
            action: 'apply' or 'destroy'
            refresh_state: boolean to refresh remote state or not

        Returns: Boolean result of if the terraform command
                 was successful or not
        """
        targets = kwargs.get('targets', [])
        action = kwargs.get('action', None)
        refresh_state = kwargs.get('refresh_state', False)
        ACTION = 1 # The index to the terraform 'action'

        tf_opts = ['-var-file=../{}'.format(self.CONFIG_FILE)]
        tf_targets = ['-target={}'.format(x) for x in targets]
        tf_command = ['terraform', 'plan'] + tf_opts + tf_targets
        if action == 'destroy':
            tf_command.append('-destroy')

        if refresh_state:
            logging.info('Refreshing Remote State config')
            remote_state_cmd = (
                'terraform remote config '
                '-backend=s3 '
                '-backend-config="bucket={}" '
                '-backend-config="key={}" '
                '-backend-config="region={}" '
                '-backend-config="kms_key_id={}" '
                '{}'
            ).format(self.config['lambda_source_bucket_name'],
                     self.config['tfstate_s3_key'],
                     self.config['region'],
                     self.config['kms_key_alias'],
                     ' '.join(tf_opts))
            self._cmd([remote_state_cmd], quiet=True)

        logging.info('Resolving Terraform modules')
        self._cmd(['terraform', 'get'], quiet=True)

        logging.info('Planning infrastructure')
        tf_plan = self._cmd(tf_command) and self._continue_prompt()
        if not tf_plan:
            return False
        if action == 'destroy':
            logging.info('Destroying infrastructure')
            tf_command[ACTION] = action
            tf_command.remove('-destroy')
        elif action:
            tf_command[ACTION] = action
        else:
            logging.info('Creating infrastructure')
            tf_command[ACTION] = 'apply'
        self._cmd(tf_command)
        return True

    def status(self):
        """Display current AWS infrastructure built by Terraform."""
        print 'Cluster Info\n'
        for cluster, region in self.config['clusters'].iteritems():
            print '==== {} ==='.format(cluster)
            print 'Region: {}'.format(region)
            print ('Lambda settings: \n\tTimeout: {}\n\tMemory: {}'
                   '\n\tProd Version: {}').format(
                       self.config['lambda_settings'][cluster][0],
                       self.config['lambda_settings'][cluster][1],
                       self.config['lambda_function_prod_versions'][cluster])
            print 'Kinesis settings: \n\tShards: {}\n\tRetention: {}'.format(
                self.config['kinesis_settings'][cluster][0],
                self.config['kinesis_settings'][cluster][1]
            )
            print '\n'

        print 'User access keys'
        self._cmd(['terraform', 'output'])

    def generate_tf_files(self):
        """Generate all Terraform plans for declared clusters in variables.json"""
        env = Environment(loader=PackageLoader('terraform', 'templates'))
        template = env.get_template('cluster_template')
        all_buckets = self.config.get('s3_event_buckets')
        for cluster in self.config['clusters'].keys():
            if cluster == 'main':
                raise InvalidClusterName('Rename cluster main to something else!')
            if all_buckets:
                buckets = all_buckets.get(cluster)
            else:
                buckets = None
            contents = template.render(
                cluster_name=cluster,
                s3_buckets=buckets
            )
            with open('terraform/{}.tf'.format(cluster), 'w') as tf_file:
                tf_file.write(contents)

    def deploy(self, options):
        """Deploy the StreamAlert processor lambda function to staging/prod

        Staging:
            - build lambda package
            - upload to S3
            - update variables.json
            - run terraform apply

        Production:
            - publish latest version
            - update variables.json
            - run terraform apply
        """
        env = options.env
        func = options.func
        targets = ['module.stream_alert_{}'.format(x) for x in self.config['clusters'].keys()]

        if env == 'staging':
            if func == 'alert':
                alert_package = AlertPackage(
                    config=self.config,
                    version=stream_alert_version
                )
                alert_package.create_and_upload()
            elif func == 'output':
                output_package = OutputPackage(
                    config=self.config,
                    version=stream_alert_output_version
                )
                output_package.create_and_upload()
            elif func == '*':
                alert_package = AlertPackage(
                    config=self.config,
                    version=stream_alert_version
                )
                alert_package.create_and_upload()
                output_package = OutputPackage(
                    config=self.config,
                    version=stream_alert_output_version
                )
                output_package.create_and_upload()

        elif env == 'production':
            if func == 'alert':
                deploy = LambdaVersion(config=self.config)
                deploy.publish_function()
            else:
                logging.info('Unsupported production function: %s', func)

        self._tf_runner(targets=targets)

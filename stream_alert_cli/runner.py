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

from collections import namedtuple
from getpass import getpass
from jinja2 import Environment, PackageLoader

from stream_alert_cli.package import RuleProcessorPackage, AlertProcessorPackage
from stream_alert_cli.test import stream_alert_test
from stream_alert_cli.helpers import CLIHelpers
from stream_alert_cli.config import CLIConfig
from stream_alert_cli.logger import LOGGER_CLI
from stream_alert_cli.version import LambdaVersion
import stream_alert_cli.outputs as config_outputs

from stream_alert.alert_processor import __version__ as alert_processor_version
from stream_alert.alert_processor.outputs import get_output_dispatcher
from stream_alert.rule_processor import __version__ as rule_processor_version


CONFIG = CLIConfig()


class InvalidClusterName(Exception):
    """Exception for invalid cluster names"""
    pass


def cli_runner(options):
    """Main Stream Alert CLI handler

    Args:
        options (dict): command line arguments passed from the argparser.
            Contains the following keys for terraform commands:
                (command, subcommand, target)
            Contains the following keys for lambda commands:
                (command, subcommand, env, func, source)
    """
    cli_load_message = ('Issues? Report here: '
                        'https://github.com/airbnb/streamalert/issues')
    LOGGER_CLI.info(cli_load_message)

    if options.command == 'output':
        configure_output(options)

    elif options.command == 'lambda':
        lambda_runner(options)

    elif options.command == 'terraform':
        terraform_runner(options)


def lambda_runner(options):
    """Handle all Lambda CLI operations"""
    if options.subcommand == 'deploy':
        deploy(options)

    elif options.subcommand == 'rollback':
        rollback(options)

    elif options.subcommand == 'test':
        stream_alert_test(options)


def terraform_check():
    """Verify that Terraform is configured correctly"""
    prereqs_message = ('Terraform not found! Please install and add to'
                       'your $PATH:\n'
                       '$ export PATH=$PATH:/usr/local/terraform/bin')
    run_command(['terraform', 'version'],
                error_message=prereqs_message,
                quiet=True)


def terraform_runner(options):
    """Handle all Terraform CLI operations"""
    # verify terraform is installed
    terraform_check()
    # use a named tuple to match the 'processor' attribute in the argparse options
    deploy_opts = namedtuple('DeployOptions', ['processor'])

    # plan/apply our streamalert infrastructure
    if options.subcommand == 'build':
        # --target is for terraforming a specific streamalert module
        if options.target:
            target = options.target
            targets = ['module.{}_{}'.format(target, cluster)
                       for cluster in CONFIG['clusters'].keys()]
            tf_runner(targets=targets)
        else:
            tf_runner()

    # generate terraform files
    elif options.subcommand == 'generate':
        generate_tf_files()

    # initialize streamalert infrastructure from a blank state
    elif options.subcommand == 'init':
        LOGGER_CLI.info('Initializing StreamAlert')
        LOGGER_CLI.info('Generating Cluster Files')
        generate_tf_files()

        # build init infrastructure
        LOGGER_CLI.info('Building Initial Infrastructure')
        init_targets = [
            'aws_s3_bucket.lambda_source',
            'aws_s3_bucket.integration_testing',
            'aws_s3_bucket.terraform_remote_state',
            'aws_kms_key.stream_alert_secrets',
            'aws_kms_alias.stream_alert_secrets'
        ]
        tf_runner(targets=init_targets, refresh_state=False)

        LOGGER_CLI.info('Deploying Lambda Functions')
        # setup remote state
        refresh_tf_state()
        # deploy both lambda functions
        deploy(deploy_opts('all'))
        # create all remainder infrastructure
        LOGGER_CLI.info('Building Remainder Infrastructure')
        tf_runner()

    # destroy all infrastructure
    elif options.subcommand == 'destroy':
        run_command(['terraform', 'remote', 'config', '-disable'])
        tf_runner(action='destroy', refresh_state=False)

    # get a quick status on our declared infrastructure
    elif options.subcommand == 'status':
        status()


def run_command(args=None, **kwargs):
    """Alias to CLI Helpers.run_command"""
    return CLIHelpers.run_command(args, **kwargs)


def continue_prompt():
    """Continue prompt used before applying Terraform plans"""
    required_responses = {'yes', 'no'}
    response = ''
    while response not in required_responses:
        response = raw_input('\nWould you like to continue? (yes or no): ')
    if response == 'yes':
        return True
    return False


def refresh_tf_state():
    """Refresh the Terraform remote state"""
    LOGGER_CLI.info('Refreshing Remote State config')
    region = CONFIG['account']['region']
    bucket = '{}.streamalert.terraform.state'.format(CONFIG['account']['prefix'])
    s3_key = CONFIG['terraform']['tfstate_s3_key']
    kms_key_id = 'alias/{}'.format(CONFIG['account']['kms_key_alias'])

    remote_state_opts = [
        'terraform',
        'remote',
        'config',
        '-backend=s3',
        '-backend-config=bucket={}'.format(bucket),
        '-backend-config=key={}'.format(s3_key),
        '-backend-config=region={}'.format(region),
        '-backend-config=kms_key_id={}'.format(kms_key_id),
        '-backend-config=encrypt=true'
    ]

    run_command(remote_state_opts, quiet=True)


def tf_runner(**kwargs):
    """Terraform wrapper to build StreamAlert infrastructure.

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
    refresh_state = kwargs.get('refresh_state', True)
    tf_action_index = 1  # The index to the terraform 'action'

    var_files = {CONFIG.filename, 'conf/outputs.json', 'conf/inputs.json'}
    tf_opts = ['-var-file=../{}'.format(x) for x in var_files]
    tf_targets = ['-target={}'.format(x) for x in targets]
    tf_command = ['terraform', 'plan'] + tf_opts + tf_targets
    if action == 'destroy':
        tf_command.append('-destroy')

    if refresh_state:
        refresh_tf_state()

    LOGGER_CLI.info('Resolving Terraform modules')
    run_command(['terraform', 'get'], quiet=True)

    LOGGER_CLI.info('Planning infrastructure')
    tf_plan = run_command(tf_command) and continue_prompt()
    if not tf_plan:
        return False

    if action == 'destroy':
        LOGGER_CLI.info('Destroying infrastructure')
        tf_command[tf_action_index] = action
        tf_command.remove('-destroy')

    elif action:
        tf_command[tf_action_index] = action

    else:
        LOGGER_CLI.info('Creating infrastructure')
        tf_command[tf_action_index] = 'apply'

    run_command(tf_command)
    return True


def status():
    """Display current AWS infrastructure built by Terraform"""
    print 'Cluster Info\n'
    for cluster, region in CONFIG['clusters'].iteritems():
        print '==== {} ==='.format(cluster)
        print 'Region: {}'.format(region)
        print ('Lambda settings: \n\tTimeout: {}\n\tMemory: {}'
               '\n\tProd Version: {}').format(
                   CONFIG['lambda_settings'][cluster][0],
                   CONFIG['lambda_settings'][cluster][1],
                   CONFIG['lambda_function_prod_versions'][cluster])
        print 'Kinesis settings: \n\tShards: {}\n\tRetention: {}\n'.format(
            CONFIG['kinesis_settings'][cluster][0],
            CONFIG['kinesis_settings'][cluster][1]
        )

    print 'User access keys'
    run_command(['terraform', 'output'])


def rollback(options):
    """Rollback the current production AWS Lambda version by 1

    Notes:
        Ignores if the production version is $LATEST
        Only rollsback if published version is greater than 1
    """
    clusters = CONFIG['clusters'].keys()
    if options.processor == 'all':
        lambda_functions = {'rule_processor', 'alert_processor'}
    else:
        lambda_functions = {'{}_processor'.format(options.processor)}

    for cluster in clusters:
        for lambda_function in lambda_functions:
            version_key = '{}_versions'.format(lambda_function)
            current_vers = CONFIG[version_key][cluster]
            if current_vers != '$LATEST':
                current_vers = int(current_vers)
                if current_vers > 1:
                    new_vers = current_vers - 1
                    CONFIG[version_key][cluster] = new_vers
                    CONFIG.write()

    targets = ['module.stream_alert_{}'.format(x)
               for x in CONFIG['clusters'].keys()]
    tf_runner(targets=targets)

def generate_tf_files():
    """Generate all Terraform plans for the clusters in variables.json"""
    LOGGER_CLI.info('Generating Terraform files')
    env = Environment(loader=PackageLoader('terraform', 'templates'))
    template = env.get_template('cluster_template')

    all_buckets = CONFIG.get('s3_event_buckets')

    for cluster in CONFIG['clusters'].keys():
        if cluster == 'main':
            raise InvalidClusterName('Rename cluster main to something else!')

        if all_buckets:
            buckets = all_buckets.get(cluster)
        else:
            buckets = None

        contents = template.render(cluster_name=cluster, s3_buckets=buckets)
        with open('terraform/{}.tf'.format(cluster), 'w') as tf_file:
            tf_file.write(contents)


def deploy(options):
    """Deploy new versions of both Lambda functions

    Steps:
    - build lambda deployment package
    - upload to S3
    - update variables.json with uploaded package hash/key
    - publish latest version
    - update variables.json with latest published version
    - terraform apply
    """
    processor = options.processor
    # terraform apply only to the module which contains our lambda functions
    targets = ['module.stream_alert_{}'.format(x)
               for x in CONFIG['clusters'].keys()]
    packages = []

    def publish_version(packages):
        """Publish Lambda versions"""
        for package in packages:
            LambdaVersion(
                config=CONFIG,
                package=package
            ).publish_function()

    def deploy_rule_processor():
        """Create Rule Processor package and publish versions"""
        rule_package = RuleProcessorPackage(
            config=CONFIG,
            version=rule_processor_version
        )
        rule_package.create_and_upload()
        return rule_package

    def deploy_alert_processor():
        """Create Alert Processor package and publish versions"""
        alert_package = AlertProcessorPackage(
            config=CONFIG,
            version=alert_processor_version
        )
        alert_package.create_and_upload()
        return alert_package

    if processor == 'rule':
        packages.append(deploy_rule_processor())

    elif processor == 'alert':
        packages.append(deploy_alert_processor())

    elif processor == 'all':
        packages.append(deploy_rule_processor())
        packages.append(deploy_alert_processor())

    # update the source code in $LATEST
    tf_runner(targets=targets)

    # TODO(jack) write integration test to verify newly updated function

    # create production version by running a second time
    publish_version(packages)
    tf_runner(targets=targets)

def user_input(requested_info, mask, input_restrictions):
    """Prompt user for requested information

    Args:
        requested_info [string]: Description of the information needed
        mask [boolean]: Decides whether to mask input or not

    Returns:
        [string] response provided by the user
    """
    response = ''
    prompt = '\nPlease supply {}: '.format(requested_info)

    if not mask:
        while not response:
            response = raw_input(prompt)

        # Restrict having spaces or colons in items (applies to things like descriptors, etc)
        if any(x in input_restrictions for x in response):
            LOGGER_CLI.error('the supplied input should not contain any of the following: %s',
                             '"{}"'.format('", "'.join(input_restrictions)))
            return user_input(requested_info, mask, input_restrictions)
    else:
        while not response:
            response = getpass(prompt=prompt)

    return response

def configure_output(options):
    """Configure a new output for this service

    Args:
        options [argparse]: Basically a namedtuple with the service setting
    """
    region = CONFIG['account']['region']
    prefix = CONFIG['account']['prefix']

    # Retrieve the proper service class to handle dispatching the alerts of this services
    output = get_output_dispatcher(options.service,
                                   region,
                                   prefix,
                                   config_outputs.load_outputs_config())

    # If an output for this service has not been defined, the error is logged prior to this
    if not output:
        return

    # get dictionary of OutputProperty items to be used for user prompting
    props = output.get_user_defined_properties()

    for name, prop in props.iteritems():
        props[name] = prop._replace(value=user_input(prop.description,
                                                     prop.mask_input,
                                                     prop.input_restrictions))

    service = output.__service__
    config = config_outputs.load_config(props, service)
    # An empty config here means this configuration already exists,
    # so we can ask for user input again for a unique configuration
    if config is False:
        return configure_output(options)

    secrets_bucket = '{}.streamalert.secrets'.format(prefix)
    secrets_key = output.output_cred_name(props['descriptor'].value)

    # Encrypt the creds and push them to S3
    # then update the local output configuration with properties
    if config_outputs.encrypt_and_push_creds_to_s3(region, secrets_bucket, secrets_key, props):
        updated_config = output.format_output_config(config, props)
        config_outputs.update_outputs_config(config, updated_config, service)

        LOGGER_CLI.info('Successfully saved \'%s\' output configuration for service \'%s\'',
                        props['descriptor'].value,
                        options.service)
    else:
        LOGGER_CLI.error('An error occurred while saving \'%s\' '
                         'output configuration for service \'%s\'',
                         props['descriptor'].value,
                         options.service)

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
from fnmatch import fnmatch
import json
import os
import string

from stream_alert.shared.metrics import FUNC_PREFIXES
from stream_alert_cli.logger import LOGGER_CLI
from stream_alert_cli.terraform._common import (
    InvalidClusterName,
    infinitedict
)
from stream_alert_cli.terraform.app_integrations import generate_app_integrations
from stream_alert_cli.terraform.athena import generate_athena
from stream_alert_cli.terraform.cloudtrail import generate_cloudtrail
from stream_alert_cli.terraform.firehose import generate_firehose
from stream_alert_cli.terraform.flow_logs import generate_flow_logs
from stream_alert_cli.terraform.kinesis_events import generate_kinesis_events
from stream_alert_cli.terraform.kinesis_streams import generate_kinesis_streams
from stream_alert_cli.terraform.metrics import (
    generate_cloudwatch_metric_filters,
    generate_cloudwatch_metric_alarms
)
from stream_alert_cli.terraform.monitoring import generate_monitoring
from stream_alert_cli.terraform.streamalert import generate_stream_alert
from stream_alert_cli.terraform.s3_events import generate_s3_events
from stream_alert_cli.terraform.threat_intel_downloader import generate_threat_intel_downloader

DEFAULT_SNS_MONITORING_TOPIC = 'stream_alert_monitoring'
RESTRICTED_CLUSTER_NAMES = ('main', 'athena')
TERRAFORM_VERSIONS = {'application': '~> 0.10.6', 'provider': {'aws': '~> 1.5.0'}}

def generate_s3_bucket(**kwargs):
    """Generate an S3 Bucket dict

    Keyword Args:
        bucket (str): The name of the bucket
        acl (str): The S3 bucket ACL
        logging_bucket (str): The S3 bucket to send access logs to
        force_destroy (bool): To enable or disable force destroy of the bucket
        versioning (bool): To enable or disable S3 object versioning
        lifecycle_rule (dict): The S3 bucket lifecycle rule

    Returns:
        dict: S3 bucket Terraform dict to be used in clusters/main.tf.json
    """
    bucket_name = kwargs.get('bucket')
    acl = kwargs.get('acl', 'private')
    logging_bucket = kwargs.get('logging')
    logging = {
        'target_bucket': logging_bucket,
        'target_prefix': '{}/'.format(bucket_name)
    }
    force_destroy = kwargs.get('force_destroy', True)
    versioning = kwargs.get('versioning', True)
    lifecycle_rule = kwargs.get('lifecycle_rule')

    bucket = {
        'bucket': bucket_name,
        'acl': acl,
        'force_destroy': force_destroy,
        'versioning': {
            'enabled': versioning
        },
        'logging': logging
    }

    if lifecycle_rule:
        bucket['lifecycle_rule'] = lifecycle_rule

    return bucket


def generate_main(**kwargs):
    """Generate the main.tf.json Terraform dict

    Keyword Args:
        init (bool): If Terraform is running in the init phase or not
        config (CLIConfig): The loaded CLI config

    Returns:
        dict: main.tf.json Terraform dict
    """
    init = kwargs.get('init')
    config = kwargs['config']
    main_dict = infinitedict()

    # Configure provider along with the minimum version
    main_dict['provider']['aws'] = {'version': TERRAFORM_VERSIONS['provider']['aws']}

    # Configure Terraform version requirement
    main_dict['terraform']['required_version'] = TERRAFORM_VERSIONS['application']

    # Setup the Backend dependencing on the deployment phase.
    # When first setting up StreamAlert, the Terraform statefile
    # is stored locally.  After the first dependencies are created,
    # this moves to S3.
    if init:
        main_dict['terraform']['backend']['local'] = {
            'path': 'terraform.tfstate'}
    else:
        main_dict['terraform']['backend']['s3'] = {
            'bucket': '{}.streamalert.terraform.state'.format(
                config['global']['account']['prefix']),
            'key': 'stream_alert_state/terraform.tfstate',
            'region': config['global']['account']['region'],
            'encrypt': True,
            'acl': 'private',
            'kms_key_id': 'alias/{}'.format(config['global']['account']['kms_key_alias'])}

    logging_bucket = '{}.streamalert.s3-logging'.format(
        config['global']['account']['prefix'])
    logging_bucket_lifecycle = {
        'prefix': '/',
        'enabled': True,
        'transition': {
            'days': 30,
            'storage_class': 'GLACIER'}}

    # Configure initial S3 buckets
    main_dict['resource']['aws_s3_bucket'] = {
        'lambda_source': generate_s3_bucket(
            bucket=config['lambda']['rule_processor_config']['source_bucket'],
            logging=logging_bucket
        ),
        'stream_alert_secrets': generate_s3_bucket(
            bucket='{}.streamalert.secrets'.format(config['global']['account']['prefix']),
            logging=logging_bucket
        ),
        'terraform_remote_state': generate_s3_bucket(
            bucket=config['global']['terraform']['tfstate_bucket'],
            logging=logging_bucket
        ),
        'logging_bucket': generate_s3_bucket(
            bucket=logging_bucket,
            acl='log-delivery-write',
            logging=logging_bucket,
            lifecycle_rule=logging_bucket_lifecycle
        ),
        'streamalerts': generate_s3_bucket(
            bucket='{}.streamalerts'.format(config['global']['account']['prefix']),
            logging=logging_bucket
        )
    }

    # Setup Firehose Delivery Streams
    generate_firehose(config, main_dict, logging_bucket)

    # Configure global resources like Firehose alert delivery
    main_dict['module']['globals'] = {
        'source': 'modules/tf_stream_alert_globals',
        'account_id': config['global']['account']['aws_account_id'],
        'region': config['global']['account']['region'],
        'prefix': config['global']['account']['prefix']
    }

    # KMS Key and Alias creation
    main_dict['resource']['aws_kms_key']['stream_alert_secrets'] = {
        'enable_key_rotation': True,
        'description': 'StreamAlert secret management'
    }
    main_dict['resource']['aws_kms_alias']['stream_alert_secrets'] = {
        'name': 'alias/{}'.format(config['global']['account']['kms_key_alias']),
        'target_key_id': '${aws_kms_key.stream_alert_secrets.key_id}'
    }

    # Global infrastructure settings
    infrastructure_config = config['global'].get('infrastructure')
    if infrastructure_config and 'monitoring' in infrastructure_config:
        if infrastructure_config['monitoring'].get('create_sns_topic'):
            main_dict['resource']['aws_sns_topic']['stream_alert_monitoring'] = {
                'name': DEFAULT_SNS_MONITORING_TOPIC
            }

    # Add any global cloudwatch alarms to the main.tf
    monitoring_config = config['global']['infrastructure'].get('monitoring')
    if not monitoring_config:
        return main_dict

    global_metrics = monitoring_config.get('metric_alarms')
    if not global_metrics:
        return main_dict

    topic_name = (DEFAULT_SNS_MONITORING_TOPIC if infrastructure_config
                  ['monitoring'].get('create_sns_topic') else
                  infrastructure_config['monitoring'].get('sns_topic_name'))

    sns_topic_arn = 'arn:aws:sns:{region}:{account_id}:{topic}'.format(
        region=config['global']['account']['region'],
        account_id=config['global']['account']['aws_account_id'],
        topic=topic_name
    )

    formatted_alarms = {}
    # Add global metric alarms for the rule and alert processors
    for func in FUNC_PREFIXES:
        if func not in global_metrics:
            continue

        for name, settings in global_metrics[func].iteritems():
            alarm_info = settings.copy()
            alarm_info['alarm_name'] = name
            alarm_info['namespace'] = 'StreamAlert'
            alarm_info['alarm_actions'] = [sns_topic_arn]
            # Terraform only allows certain characters in resource names
            acceptable_chars = ''.join([string.digits, string.letters, '_-'])
            name = filter(acceptable_chars.__contains__, name)
            formatted_alarms['metric_alarm_{}'.format(name)] = alarm_info

    if formatted_alarms:
        main_dict['resource']['aws_cloudwatch_metric_alarm'] = formatted_alarms

    return main_dict


def generate_outputs(cluster_name, cluster_dict, config):
    """Add the outputs to the Terraform cluster dict.

    Args:
        cluster_name (str): The name of the currently generating cluster
        cluster_dict (defaultdict): The dict containing all Terraform config for
                                    a given cluster.
        config (dict): The loaded config from the 'conf/' directory

    Returns:
        bool: Result of applying all outputs
    """
    output_config = config['clusters'][cluster_name].get('outputs')
    if output_config:
        for tf_module, output_vars in output_config.items():
            for output_var in output_vars:
                cluster_dict['output']['{}_{}_{}'.format(tf_module, cluster_name, output_var)] = {
                    'value': '${{module.{}_{}.{}}}'.format(tf_module, cluster_name, output_var)}

    return True


def generate_cluster(**kwargs):
    """Generate a StreamAlert cluster file.

    Keyword Args:
        cluster_name (str): The name of the currently generating cluster
        config (dict): The loaded config from the 'conf/' directory

    Returns:
        dict: generated Terraform cluster dictionary
    """
    config = kwargs.get('config')
    cluster_name = kwargs.get('cluster_name')

    modules = config['clusters'][cluster_name]['modules']
    cluster_dict = infinitedict()

    if not generate_stream_alert(cluster_name, cluster_dict, config):
        return

    generate_cloudwatch_metric_filters(cluster_name, cluster_dict, config)

    generate_cloudwatch_metric_alarms(cluster_name, cluster_dict, config)

    if modules.get('cloudwatch_monitoring', {}).get('enabled'):
        if not generate_monitoring(cluster_name, cluster_dict, config):
            return

    if modules.get('kinesis'):
        if not generate_kinesis_streams(cluster_name, cluster_dict, config):
            return

    outputs = config['clusters'][cluster_name].get('outputs')
    if outputs:
        if not generate_outputs(cluster_name, cluster_dict, config):
            return

    if modules.get('kinesis_events'):
        if not generate_kinesis_events(cluster_name, cluster_dict, config):
            return

    cloudtrail_info = modules.get('cloudtrail')
    if cloudtrail_info:
        if not generate_cloudtrail(cluster_name, cluster_dict, config):
            return

    flow_log_info = modules.get('flow_logs')
    if flow_log_info:
        if not generate_flow_logs(cluster_name, cluster_dict, config):
            return

    s3_events_info = modules.get('s3_events')
    if s3_events_info:
        if not generate_s3_events(cluster_name, cluster_dict, config):
            return

    generate_app_integrations(cluster_name, cluster_dict, config)

    return cluster_dict


def cleanup_old_tf_files(config):
    """Cleanup old .tf files, these are now .tf.json files per Hashicorp best practices"""
    for terraform_file in os.listdir('terraform'):
        if terraform_file == 'variables.tf':
            continue

        if fnmatch(terraform_file, '*.tf'):
            # Allow to retain misc files in the terraform/ directory
            if terraform_file.split('.')[0] in config.clusters() + ['athena', 'main']:
                os.remove(os.path.join('terraform', terraform_file))


def terraform_generate(config, init=False):
    """Generate all Terraform plans for the configured clusters.

    Keyword Args:
        config (dict): The loaded config from the 'conf/' directory
        init (bool): Indicates if main.tf.json is generated for `terraform init`

    Returns:
        bool: Result of cluster generating
    """
    cleanup_old_tf_files(config)

    # Setup the main.tf.json file
    LOGGER_CLI.debug('Generating cluster file: main.tf.json')
    with open('terraform/main.tf.json', 'w') as tf_file:
        json.dump(
            generate_main(init=init, config=config),
            tf_file,
            indent=2,
            sort_keys=True
        )

    # Return early during the init process, clusters are not needed yet
    if init:
        return True

    # Setup cluster files
    for cluster in config.clusters():
        if cluster in RESTRICTED_CLUSTER_NAMES:
            raise InvalidClusterName(
                'Rename cluster "main" or "athena" to something else!')

        LOGGER_CLI.debug('Generating cluster file: %s.tf.json', cluster)
        cluster_dict = generate_cluster(cluster_name=cluster, config=config)
        if not cluster_dict:
            LOGGER_CLI.error(
                'An error was generated while creating the %s cluster', cluster)
            return False

        with open('terraform/{}.tf.json'.format(cluster), 'w') as tf_file:
            json.dump(
                cluster_dict,
                tf_file,
                indent=2,
                sort_keys=True
            )

    # Setup Athena if it is enabled
    generate_global_lambda_settings(
        config,
        config_name='athena_partition_refresh_config',
        config_generate_func=generate_athena,
        tf_tmp_file='terraform/athena.tf.json',
        message='Removing old Athena Terraform file'
    )

    # Setup Threat Intel Downloader Lambda function if it is enabled
    generate_global_lambda_settings(
        config,
        config_name='threat_intel_downloader_config',
        config_generate_func=generate_threat_intel_downloader,
        tf_tmp_file='terraform/ti_downloader.tf.json',
        message='Removing old Threat Intel Downloader Terraform file'
    )

    return True

def generate_global_lambda_settings(config, **kwargs):
    """Generate settings of global Lambda funcitons, Athena and Threat Intel Downloader
    Args:
        config (dict): lambda function settings read from 'conf/' directory

    Keyword Args:
        config_name (str): keyname of lambda function settings in config.
        config_generate_func (func): method to generate lambda function settings.
        tf_tmp_file (str): filename of terraform file, generated by CLI.
        message (str): Message will be logged by LOGGER.
    """
    config_name = kwargs.get('config_name')
    tf_tmp_file = kwargs.get('tf_tmp_file')
    if config_name and config['lambda'].get(config_name) and tf_tmp_file:
        if config['lambda'].get(config_name)['enabled']:
            generated_config = kwargs.get('config_generate_func')(config=config)
            if generated_config:
                with open(tf_tmp_file, 'w') as tf_file:
                    json.dump(generated_config, tf_file, indent=2, sort_keys=True)
        else:
            if os.path.isfile(tf_tmp_file):
                LOGGER_CLI.info(kwargs.get('message'))
                os.remove(tf_tmp_file)

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
    DEFAULT_SNS_MONITORING_TOPIC,
    enabled_firehose_logs,
    InvalidClusterName,
    infinitedict
)
from stream_alert_cli.terraform.athena import generate_athena
from stream_alert_cli.terraform.cloudtrail import generate_cloudtrail
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

DEFAULT_SNS_MONITORING_TOPIC = 'stream_alert_monitoring'
RESTRICTED_CLUSTER_NAMES = ('main', 'athena')

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

    # Configure provider
    main_dict['provider']['aws'] = {}

    # Configure Terraform version requirement
    main_dict['terraform']['required_version'] = '> 0.9.4'

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

    # Conditionally configure Firehose
    if config['global']['infrastructure'].get('firehose', {}).get('enabled'):
        firehose_config = config['global']['infrastructure']['firehose']
        firehose_s3_bucket_suffix = firehose_config.get('s3_bucket_suffix',
                                                        'streamalert.data')
        firehose_s3_bucket_name = '{}.{}'.format(config['global']['account']['prefix'],
                                                 firehose_s3_bucket_suffix)

        # Add the main Firehose module
        main_dict['module']['kinesis_firehose'] = {
            'source': 'modules/tf_stream_alert_kinesis_firehose',
            'account_id': config['global']['account']['aws_account_id'],
            'region': config['global']['account']['region'],
            'prefix': config['global']['account']['prefix'],
            'logs': enabled_firehose_logs(config),
            'buffer_size': config['global']['infrastructure']\
                           ['firehose'].get('buffer_size', 5),
            'buffer_interval': config['global']['infrastructure']\
                               ['firehose'].get('buffer_interval', 300),
            'compression_format': config['global']['infrastructure']\
                               ['firehose'].get('buffer_interval', 'Snappy'),
            's3_logging_bucket': logging_bucket,
            's3_bucket_name': firehose_s3_bucket_name
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
        if not func in global_metrics:
            continue

        for name, settings in global_metrics[func].iteritems():
            alarm_info = settings.copy()
            alarm_info['alarm_name'] = name
            alarm_info['namespace'] = 'StreamAlert'
            alarm_info['alarm_actions'] = [sns_topic_arn]
            # Terraform only allows certain characters in resource names, so strip the name
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

    if modules['cloudwatch_monitoring']['enabled']:
        if not generate_monitoring(cluster_name, cluster_dict, config):
            return

    if not generate_kinesis_streams(cluster_name, cluster_dict, config):
        return

    outputs = config['clusters'][cluster_name].get('outputs')
    if outputs:
        if not generate_outputs(cluster_name, cluster_dict, config):
            return

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

    return cluster_dict


def cleanup_old_tf_files():
    """Cleanup old .tf files, these are now .tf.json files per Hashicorp best practices"""
    for terraform_file in os.listdir('terraform'):
        if terraform_file == 'variables.tf':
            continue

        if fnmatch(terraform_file, '*.tf'):
            os.remove(os.path.join('terraform', terraform_file))


def terraform_generate(**kwargs):
    """Generate all Terraform plans for the configured clusters.

    Keyword Args:
        config (dict): The loaded config from the 'conf/' directory
        init (bool): Indicates if main.tf.json is generated for `terraform init`

    Returns:
        bool: Result of cluster generating
    """
    config = kwargs.get('config')
    init = kwargs.get('init', False)

    cleanup_old_tf_files()

    # Setup the main.tf.json file
    LOGGER_CLI.debug('Generating cluster file: main.tf.json')
    main_json = json.dumps(
        generate_main(init=init, config=config),
        indent=2,
        sort_keys=True
    )
    with open('terraform/main.tf.json', 'w') as tf_file:
        tf_file.write(main_json)

    # Return early during the init process, clusters are not needed yet
    if init:
        return True

    # Setup cluster files
    for cluster in config.clusters():
        if cluster in RESTRICTED_CLUSTER_NAMES:
            raise InvalidClusterName('Rename cluster "main" or "athena" to something else!')

        LOGGER_CLI.debug('Generating cluster file: %s.tf.json', cluster)
        cluster_dict = generate_cluster(cluster_name=cluster, config=config)
        if not cluster_dict:
            LOGGER_CLI.error(
                'An error was generated while creating the %s cluster', cluster)
            return False

        cluster_json = json.dumps(
            cluster_dict,
            indent=2,
            sort_keys=True
        )
        with open('terraform/{}.tf.json'.format(cluster), 'w') as tf_file:
            tf_file.write(cluster_json)

    # Setup Athena if it is enabled
    athena_config = config['lambda'].get('athena_partition_refresh_config')
    if athena_config:
        athena_file = 'terraform/athena.tf.json'
        if athena_config['enabled']:
            athena_json = json.dumps(
                generate_athena(config=config),
                indent=2,
                sort_keys=True
            )
            if athena_json:
                with open(athena_file, 'w') as tf_file:
                    tf_file.write(athena_json)
        # Remove Athena file if it's disabled
        else:
            if os.path.isfile(athena_file):
                LOGGER_CLI.info('Removing old Athena Terraform file')
                os.remove(athena_file)

    return True

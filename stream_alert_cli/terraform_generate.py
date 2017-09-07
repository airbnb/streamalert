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
from collections import defaultdict
import json
import os

from stream_alert.shared import metrics
from stream_alert_cli.logger import LOGGER_CLI

RESTRICTED_CLUSTER_NAMES = ('main', 'athena')


class InvalidClusterName(Exception):
    """Exception for invalid cluster names"""
    pass


def infinitedict():
    """Create arbitrary levels of dictionary key/values"""
    return defaultdict(infinitedict)


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
        dict: S3 bucket Terraform dict to be used in clusters/main.tf
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
    """Generate the main.tf Terraform dict

    Keyword Args:
        init (bool): If Terraform is running in the init phase or not
        config (CLIConfig): The loaded CLI config

    Returns:
        dict: main.tf Terraform dict
    """
    init = kwargs.get('init')
    config = kwargs.get('config')

    main_dict = infinitedict()

    # Configure provider
    main_dict['provider']['aws'] = {}

    # Configure Terraform version requirement
    main_dict['terraform']['required_version'] = '> 0.9.4'

    # Setup the Backend
    if init:
        main_dict['terraform']['backend']['local'] = {
            'path': 'terraform.tfstate'
        }
    else:
        main_dict['terraform']['backend']['s3'] = {
            'bucket': '{}.streamalert.terraform.state'.format(
                config['global']['account']['prefix']),
            'key': 'stream_alert_state/terraform.tfstate',
            'region': config['global']['account']['region'],
            'encrypt': True,
            'acl': 'private',
            'kms_key_id': 'alias/{}'.format(config['global']['account']['kms_key_alias'])
        }

    logging_bucket = '{}.streamalert.s3-logging'.format(
        config['global']['account']['prefix'])
    logging_bucket_lifecycle = {
        'prefix': '/',
        'enabled': True,
        'transition': {
            'days': 30,
            'storage_class': 'GLACIER'
        }
    }
    # Configure init S3 buckets
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

    main_dict['resource']['aws_kms_key']['stream_alert_secrets'] = {
        'enable_key_rotation': True,
        'description': 'StreamAlert secret management'
    }

    main_dict['resource']['aws_kms_alias']['stream_alert_secrets'] = {
        'name': 'alias/{}'.format(config['global']['account']['kms_key_alias']),
        'target_key_id': '${aws_kms_key.stream_alert_secrets.key_id}'
    }

    infrastructure_config = config['global'].get('infrastructure')
    if infrastructure_config and 'monitoring' in infrastructure_config:
        if infrastructure_config['monitoring'].get('create_sns_topic'):
            main_dict['resource']['aws_sns_topic']['stream_alert_monitoring'] = {
                'name': 'stream_alert_monitoring'
            }

    return main_dict


def generate_stream_alert(cluster_name, cluster_dict, config):
    """Add the StreamAlert module to the Terraform cluster dict.

    Args:
        cluster_name (str): The name of the currently generating cluster
        cluster_dict (defaultdict): The dict containing all Terraform config for a given cluster.
        config (dict): The loaded config from the 'conf/' directory

    JSON Input from the config:

        "stream_alert": {
          "alert_processor": {
            "current_version": "$LATEST",
            "log_level": "info",
            "memory": 128,
            "outputs": {
              "aws-lambda": [
                "lambda_function_name"
              ],
              "aws-s3": [
                "s3.bucket.name"
              ]
            },
            "timeout": 10,
            "vpc_config": {
              "security_group_ids": [
                "sg-id"
              ],
              "subnet_ids": [
                "subnet-id"
              ]
            }
          },
          "rule_processor": {
            "current_version": "$LATEST",
            "inputs": {
              "aws-sns": [
                "sns_topic_arn"
              ]
            },
            "log_level": "info",
            "memory": 128,
            "timeout": 10
          }
        }

    Returns:
        bool: Result of applying the stream_alert module
    """
    account = config['global']['account']
    modules = config['clusters'][cluster_name]['modules']

    cluster_dict['module']['stream_alert_{}'.format(cluster_name)] = {
        'source': 'modules/tf_stream_alert',
        'account_id': account['aws_account_id'],
        'region': config['clusters'][cluster_name]['region'],
        'prefix': account['prefix'],
        'cluster': cluster_name,
        'kms_key_arn': '${aws_kms_key.stream_alert_secrets.arn}',
        'rule_processor_enable_metrics': modules['stream_alert'] \
            ['rule_processor']['enable_metrics'],
        'rule_processor_log_level': modules['stream_alert'] \
            ['rule_processor'].get('log_level', 'info'),
        'rule_processor_memory': modules['stream_alert']['rule_processor']['memory'],
        'rule_processor_timeout': modules['stream_alert']['rule_processor']['timeout'],
        'rule_processor_version': modules['stream_alert']['rule_processor']['current_version'],
        'rule_processor_config': '${var.rule_processor_config}',
        'alert_processor_config': '${var.alert_processor_config}',
        'alert_processor_enable_metrics': modules['stream_alert'] \
            ['alert_processor']['enable_metrics'],
        'alert_processor_log_level': modules['stream_alert'] \
            ['alert_processor'].get('log_level', 'info'),
        'alert_processor_memory': modules['stream_alert']['alert_processor']['memory'],
        'alert_processor_timeout': modules['stream_alert']['alert_processor']['timeout'],
        'alert_processor_version': modules['stream_alert']['alert_processor']['current_version']
    }

    # Add Alert Processor output config from the loaded cluster file
    output_config = modules['stream_alert']['alert_processor'].get('outputs')
    if output_config:
        # Mapping of Terraform input variables to output config variables
        output_mapping = {
            'output_lambda_functions': 'aws-lambda',
            'output_s3_buckets': 'aws-s3'
        }
        for tf_key, output in output_mapping.iteritems():
            if output in output_config:
                cluster_dict['module']['stream_alert_{}'.format(cluster_name)].update({
                    tf_key: modules['stream_alert']['alert_processor']['outputs'][output]
                })

    # Add Rule Processor input config from the loaded cluster file
    input_config = modules['stream_alert']['rule_processor'].get('inputs')
    if input_config:
        input_mapping = {
            'input_sns_topics': 'aws-sns'
        }
        for tf_key, input_key in input_mapping.iteritems():
            if input_key in input_config:
                cluster_dict['module']['stream_alert_{}'.format(cluster_name)].update({
                    tf_key: input_config[input_key]
                })

    # Add the Alert Processor VPC config from the loaded cluster file
    vpc_config = modules['stream_alert']['alert_processor'].get('vpc_config')
    if vpc_config:
        cluster_dict['module']['stream_alert_{}'.format(cluster_name)].update({
            'alert_processor_vpc_enabled': True,
            'alert_processor_vpc_subnet_ids': vpc_config['subnet_ids'],
            'alert_processor_vpc_security_group_ids': vpc_config['security_group_ids']
        })

    return True

def generate_cloudwatch_log_metrics(cluster_name, cluster_dict, config):
    """Add the CloudWatch Metric Filters module to the Terraform cluster dict.

    Args:
        cluster_name (str): The name of the currently generating cluster
        cluster_dict (defaultdict): The dict containing all Terraform config for a given cluster.
        config (dict): The loaded config from the 'conf/' directory

    Returns:
        bool: Result of applying the cloudwatch metric filters to the stream_alert module
    """
    stream_alert_config = config['clusters'][cluster_name]['modules']['stream_alert']

    current_metrics = metrics.MetricLogger.get_available_metrics()

    # Add metric filters for the rule and alert processor
    # The funcs dict acts as a simple map to a human-readable name
    funcs = {metrics.ALERT_PROCESSOR_NAME: 'AlertProcessor',
             metrics.RULE_PROCESSOR_NAME: 'RuleProcessor'}

    for func in funcs:
        if func not in current_metrics:
            continue

        if func not in stream_alert_config:
            LOGGER_CLI.error('Function for metrics \'%s\' is not defined in stream alert config. '
                             'Options are: %s', func,
                             ', '.join('\'{}\''.format(key) for key in stream_alert_config))
            continue

        if not stream_alert_config[func].get('enable_metrics'):
            continue

        metric_prefix = funcs[func]
        filter_pattern_idx, filter_value_idx = 0, 1

        # Add filters for the cluster and aggregate
        # Use a list of strings that represnt the following comma separated values:
        #   <filter_name>,<filter_pattern>,<value>
        filters = []
        for metric, settings in current_metrics[func].items():
            filters.extend([
                '{},{},{}'.format(
                    '{}-{}-{}'.format(metric_prefix, metric, cluster_name.upper()),
                    settings[filter_pattern_idx],
                    settings[filter_value_idx]),
                '{},{},{}'.format(
                    '{}-{}'.format(metric_prefix, metric),
                    settings[filter_pattern_idx],
                    settings[filter_value_idx])
            ])

        cluster_dict['module']['stream_alert_{}'.format(cluster_name)] \
            ['{}_metric_filters'.format(func)] = filters


def generate_cloudwatch_monitoring(cluster_name, cluster_dict, config):
    """Add the CloudWatch Monitoring module to the Terraform cluster dict.

    Args:
        cluster_name (str): The name of the currently generating cluster
        cluster_dict (defaultdict): The dict containing all Terraform config for a given cluster.
        config (dict): The loaded config from the 'conf/' directory

    Returns:
        bool: Result of applying the cloudwatch_monitoring module
    """
    prefix = config['global']['account']['prefix']
    infrastructure_config = config['global'].get('infrastructure')
    sns_topic_arn = None

    if infrastructure_config and 'monitoring' in infrastructure_config:
        if infrastructure_config['monitoring'].get('create_sns_topic'):
            sns_topic_arn = 'arn:aws:sns:{region}:{account_id}:{topic}'.format(
                region=config['global']['account']['region'],
                account_id=config['global']['account']['aws_account_id'],
                topic='stream_alert_monitoring'
            )
        elif infrastructure_config['monitoring'].get('sns_topic_name'):
            sns_topic_arn = 'arn:aws:sns:{region}:{account_id}:{topic}'.format(
                region=config['global']['account']['region'],
                account_id=config['global']['account']['aws_account_id'],
                topic=infrastructure_config['monitoring']['sns_topic_name']
            )
    else:
        LOGGER_CLI.error('Invalid config: Make sure you declare global infrastructure options!')
        return False

    lambda_functions = [
        '{}_{}_streamalert_rule_processor'.format(prefix, cluster_name),
        '{}_{}_streamalert_alert_processor'.format(prefix, cluster_name)
    ]
    # Conditionally add the Athena Lambda function for CloudWatch Alarms
    if config['lambda'].get('athena_partition_refresh_config', {}).get('enabled'):
        lambda_functions.append('{}_streamalert_athena_partition_refresh'.format(
            prefix
        ))

    cluster_dict['module']['cloudwatch_monitoring_{}'.format(cluster_name)] = {
        'source': 'modules/tf_stream_alert_monitoring',
        'sns_topic_arn': sns_topic_arn,
        'lambda_functions': lambda_functions,
        'kinesis_stream': '{}_{}_stream_alert_kinesis'.format(prefix, cluster_name)
    }

    return True


def generate_kinesis(cluster_name, cluster_dict, config):
    """Add the Kinesis module to the Terraform cluster dict.

    Args:
        cluster_name (str): The name of the currently generating cluster
        cluster_dict (defaultdict): The dict containing all Terraform config for
                                    a given cluster.
        config (dict): The loaded config from the 'conf/' directory

    Returns:
        bool: Result of applying the kinesis module
    """
    logging_bucket = '{}.streamalert.s3-logging'.format(
        config['global']['account']['prefix'])
    firehose_suffix = config['clusters'][cluster_name]['modules']['kinesis']['firehose'][
        's3_bucket_suffix']
    prefix = config['global']['account']['prefix']
    modules = config['clusters'][cluster_name]['modules']

    cluster_dict['module']['kinesis_{}'.format(cluster_name)] = {
        'source': 'modules/tf_stream_alert_kinesis',
        'account_id': config['global']['account']['aws_account_id'],
        'region': config['clusters'][cluster_name]['region'],
        'cluster_name': cluster_name,
        'firehose_s3_bucket_name': '{}.{}.{}'.format(config['global']['account']['prefix'],
                                                     cluster_name.replace('_', '.'),
                                                     firehose_suffix),
        'stream_name': '{}_{}_stream_alert_kinesis'.format(prefix, cluster_name),
        'firehose_name': '{}_{}_stream_alert_firehose'.format(prefix, cluster_name),
        'username': '{}_{}_stream_alert_user'.format(prefix, cluster_name),
        'shards': modules['kinesis']['streams']['shards'],
        'retention': modules['kinesis']['streams']['retention'],
        's3_logging_bucket': logging_bucket
    }

    return True


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
    for tf_module, output_vars in config['clusters'][cluster_name]['outputs'].iteritems():
        for output_var in output_vars:
            cluster_dict['output']['{}_{}_{}'.format(tf_module, cluster_name, output_var)] = {
                'value': '${{module.{}_{}.{}}}'.format(tf_module, cluster_name, output_var)}

    return True


def generate_kinesis_events(cluster_name, cluster_dict, config):
    """Add the Kinesis Events module to the Terraform cluster dict.

    Args:
        cluster_name (str): The name of the currently generating cluster
        cluster_dict (defaultdict): The dict containing all Terraform config for
                                    a given cluster.
        config (dict): The loaded config from the 'conf/' directory

    Returns:
        bool: Result of applying the kinesis_events module
    """
    kinesis_events_enabled = bool(
        config['clusters'][cluster_name]['modules']['kinesis_events']['enabled'])
    # Kinesis events module
    cluster_dict['module']['kinesis_events_{}'.format(cluster_name)] = {
        'source': 'modules/tf_stream_alert_kinesis_events',
        'lambda_production_enabled': kinesis_events_enabled,
        'lambda_role_id': '${{module.stream_alert_{}.lambda_role_id}}'.format(cluster_name),
        'lambda_function_arn': '${{module.stream_alert_{}.lambda_arn}}'.format(cluster_name),
        'kinesis_stream_arn': '${{module.kinesis_{}.arn}}'.format(cluster_name),
        'role_policy_prefix': cluster_name
    }

    return True


def generate_cloudtrail(cluster_name, cluster_dict, config):
    """Add the CloudTrail module to the Terraform cluster dict.

    Args:
        cluster_name (str): The name of the currently generating cluster
        cluster_dict (defaultdict): The dict containing all Terraform config for a given cluster.
        config (dict): The loaded config from the 'conf/' directory

    Returns:
        bool: Result of applying the cloudtrail module
    """
    modules = config['clusters'][cluster_name]['modules']
    cloudtrail_enabled = bool(modules['cloudtrail']['enabled'])
    existing_trail_default = False
    existing_trail = modules['cloudtrail'].get('existing_trail', existing_trail_default)
    is_global_trail_default = True
    is_global_trail = modules['cloudtrail'].get(
        'is_global_trail', is_global_trail_default)
    event_pattern_default = {
        'account': [config['global']['account']['aws_account_id']]
    }
    event_pattern = modules['cloudtrail'].get('event_pattern', event_pattern_default)

    # From here:
    # http://docs.aws.amazon.com/AmazonCloudWatch/latest/events/CloudWatchEventsandEventPatterns.html
    valid_event_pattern_keys = {
        'version',
        'id',
        'detail-type',
        'source',
        'account',
        'time',
        'region',
        'resources',
        'detail'
    }
    if not set(event_pattern.keys()).issubset(valid_event_pattern_keys):
        LOGGER_CLI.error('Invalid CloudWatch Event Pattern!')
        return False

    cluster_dict['module']['cloudtrail_{}'.format(cluster_name)] = {
        'account_id': config['global']['account']['aws_account_id'],
        'cluster': cluster_name,
        'kinesis_arn': '${{module.kinesis_{}.arn}}'.format(cluster_name),
        'prefix': config['global']['account']['prefix'],
        'enable_logging': cloudtrail_enabled,
        'source': 'modules/tf_stream_alert_cloudtrail',
        's3_logging_bucket': '{}.streamalert.s3-logging'.format(
            config['global']['account']['prefix']),
        'existing_trail': existing_trail,
        'is_global_trail': is_global_trail,
        'event_pattern': json.dumps(event_pattern)
    }

    return True


def generate_flow_logs(cluster_name, cluster_dict, config):
    """Add the VPC Flow Logs module to the Terraform cluster dict.

    Args:
        cluster_name (str): The name of the currently generating cluster
        cluster_dict (defaultdict): The dict containing all Terraform config for a given cluster.
        config (dict): The loaded config from the 'conf/' directory

    Returns:
        bool: Result of applying the flow_logs module
    """
    modules = config['clusters'][cluster_name]['modules']
    flow_log_group_name_default = '{}_{}_streamalert_flow_logs'.format(
        config['global']['account']['prefix'],
        cluster_name
    )
    flow_log_group_name = modules['flow_logs'].get(
        'log_group_name', flow_log_group_name_default)

    if modules['flow_logs']['enabled']:
        cluster_dict['module']['flow_logs_{}'.format(cluster_name)] = {
            'source': 'modules/tf_stream_alert_flow_logs',
            'destination_stream_arn': '${{module.kinesis_{}.arn}}'.format(cluster_name),
            'flow_log_group_name': flow_log_group_name}
        for flow_log_input in ('vpcs', 'subnets', 'enis'):
            input_data = modules['flow_logs'].get(flow_log_input)
            if input_data:
                cluster_dict['module']['flow_logs_{}'.format(
                    cluster_name)][flow_log_input] = input_data
        return True

    LOGGER_CLI.info('Flow logs disabled, nothing to do')
    return False


def generate_s3_events(cluster_name, cluster_dict, config):
    """Add the S3 Events module to the Terraform cluster dict.

    Args:
        cluster_name (str): The name of the currently generating cluster
        cluster_dict (defaultdict): The dict containing all Terraform config for a given cluster.
        config (dict): The loaded config from the 'conf/' directory

    Returns:
        bool: Result of applying the s3_events module
    """
    modules = config['clusters'][cluster_name]['modules']
    s3_bucket_id = modules['s3_events'].get('s3_bucket_id')

    if not s3_bucket_id:
        LOGGER_CLI.error(
            'Config Error: Missing S3 bucket in %s s3_events module',
            cluster_name)
        return False

    cluster_dict['module']['s3_events_{}'.format(cluster_name)] = {
        'source': 'modules/tf_stream_alert_s3_events',
        'lambda_function_arn': '${{module.stream_alert_{}.lambda_arn}}'.format(cluster_name),
        'lambda_function_name': '{}_{}_stream_alert_processor'.format(
            config['global']['account']['prefix'],
            cluster_name),
        's3_bucket_id': s3_bucket_id,
        's3_bucket_arn': 'arn:aws:s3:::{}'.format(s3_bucket_id),
        'lambda_role_id': '${{module.stream_alert_{}.lambda_role_id}}'.format(cluster_name),
        'lambda_role_arn': '${{module.stream_alert_{}.lambda_role_arn}}'.format(cluster_name)}

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

    generate_cloudwatch_log_metrics(cluster_name, cluster_dict, config)

    if modules['cloudwatch_monitoring']['enabled']:
        if not generate_cloudwatch_monitoring(cluster_name, cluster_dict, config):
            return

    if not generate_kinesis(cluster_name, cluster_dict, config):
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


def generate_athena(config):
    """Generate Athena Terraform.

    Args:
        config (dict): The loaded config from the 'conf/' directory

    Returns:
        dict: Athena dict to be marshalled to JSON
    """
    athena_dict = infinitedict()
    athena_config = config['lambda']['athena_partition_refresh_config']

    data_buckets = set()
    for refresh_type in athena_config['refresh_type']:
        data_buckets.update(set(athena_config['refresh_type'][refresh_type]))

    athena_dict['module']['stream_alert_athena'] = {
        'source': 'modules/tf_stream_alert_athena',
        'lambda_handler': athena_config['handler'],
        'lambda_memory': athena_config.get('memory', '128'),
        'lambda_timeout': athena_config.get('timeout', '60'),
        'lambda_s3_bucket': athena_config['source_bucket'],
        'lambda_s3_key': athena_config['source_object_key'],
        'lambda_log_level': athena_config.get('log_level', 'info'),
        'athena_data_buckets': list(data_buckets),
        'refresh_interval': athena_config.get('refresh_interval', 'rate(10 minutes)'),
        'current_version': athena_config['current_version'],
        'enable_metrics': athena_config.get('enable_metrics', False),
        'prefix': config['global']['account']['prefix']
    }

    if not athena_config.get('enable_metrics', False):
        return athena_dict

    # Check to see if there are any metrics configured for the athena function
    current_metrics = metrics.MetricLogger.get_available_metrics()
    if metrics.ATHENA_PARTITION_REFRESH_NAME not in current_metrics:
        return athena_dict

    metric_prefix = 'AthenaRefresh'
    filter_pattern_idx, filter_value_idx = 0, 1

    # Add filters for the cluster and aggregate
    # Use a list of strings that represnt the following comma separated values:
    #   <filter_name>,<filter_pattern>,<value>
    filters = ['{},{},{}'.format('{}-{}'.format(metric_prefix, metric),
                                 settings[filter_pattern_idx],
                                 settings[filter_value_idx])
               for metric, settings in
               current_metrics[metrics.ATHENA_PARTITION_REFRESH_NAME].iteritems()]

    athena_dict['module']['stream_alert_athena']['athena_metric_filters'] = filters

    return athena_dict


def terraform_generate(**kwargs):
    """Generate all Terraform plans for the configured clusters.

    Keyword Args:
        config (dict): The loaded config from the 'conf/' directory
        init (bool): Indicates if main.tf is generated for `terraform init`

    Returns:
        bool: Result of cluster generating
    """
    config = kwargs.get('config')
    init = kwargs.get('init', False)

    # Setup the main.tf file
    LOGGER_CLI.debug('Generating cluster file: main.tf')
    main_json = json.dumps(
        generate_main(init=init, config=config),
        indent=2,
        sort_keys=True
    )
    with open('terraform/main.tf', 'w') as tf_file:
        tf_file.write(main_json)

    # Return early during the init process, clusters are not needed yet
    if init:
        return True

    # Setup cluster files
    for cluster in config.clusters():
        if cluster in RESTRICTED_CLUSTER_NAMES:
            raise InvalidClusterName('Rename cluster "main" or "athena" to something else!')

        LOGGER_CLI.debug('Generating cluster file: %s.tf', cluster)
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
        with open('terraform/{}.tf'.format(cluster), 'w') as tf_file:
            tf_file.write(cluster_json)

    # Setup Athena if it is enabled
    athena_config = config['lambda'].get('athena_partition_refresh_config')
    if athena_config:
        athena_file = 'terraform/athena.tf'
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

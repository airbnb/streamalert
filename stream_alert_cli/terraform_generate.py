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
import sys

from collections import defaultdict

from stream_alert_cli.logger import LOGGER_CLI


class InvalidClusterName(Exception):
    """Exception for invalid cluster names"""
    pass


def infinitedict():
    """Create arbitrary levels of dictionary key/values"""
    return defaultdict(infinitedict)


def generate_s3_bucket(**kwargs):
    """Generate an S3 Bucket dict

    Keyword Args:
        bucket [string]: The name of the bucket
        acl [string]: The S3 bucket ACL
        logging_bucket [string]: The S3 bucket to send access logs to
        force_destroy [bool]: To enable or disable force destroy of the bucket
        versioning [bool]: To enable or disable S3 object versioning
        lifecycle_rule [dict]: The S3 bucket lifecycle rule

    Returns:
        [dict] S3 bucket Terraform dict to be used in clusters/main.tf
    """
    bucket_name = kwargs.get('bucket')
    acl = kwargs.get('acl', 'private')
    logging_bucket = kwargs.get('logging')
    logging = {
        'target_bucket': logging_bucket,
        'target_prefix': '{}/'.format(bucket_name)
    }
    force_destroy = kwargs.get('force_destroy', False)
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
        init [string]: If Terraform is running in the init phase or not
        config [CLIConfig]: The loaded CLI config

    Returns:
        [dict] main.tf Terraform dict
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
            'bucket': '{}.streamalert.terraform.state'.format(config['global']['account']['prefix']),
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

    return main_dict


def generate_stream_alert(cluster_name, cluster_dict, config):
    """Add the StreamAlert module to the Terraform cluster dict.

    Args:
        cluster_name [string]: The name of the currently generating cluster
        cluster_dict [defaultdict]: The dict containing all Terraform config for
                                    a given cluster.
        config [dict]: The loaded config from the 'conf/' directory

    JSON Input from the config:

        "stream_alert": {
          "alert_processor": {
            "current_version": "$LATEST",
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
            "memory": 128,
            "timeout": 10
          }
        }
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
        'rule_processor_memory': modules['stream_alert']['rule_processor']['memory'],
        'rule_processor_timeout': modules['stream_alert']['rule_processor']['timeout'],
        'rule_processor_version': modules['stream_alert']['rule_processor']['current_version'],
        'rule_processor_config': '${var.rule_processor_config}',
        'alert_processor_config': '${var.alert_processor_config}',
        'alert_processor_memory': modules['stream_alert']['alert_processor']['memory'],
        'alert_processor_timeout': modules['stream_alert']['alert_processor']['timeout'],
        'alert_processor_version': modules['stream_alert']['alert_processor']['current_version'],
        's3_logging_bucket': '{}.streamalert.s3-logging'.format(
            config['global']['account']['prefix'])
    }

    # Add Alert Processor output config
    output_config = modules['stream_alert']['alert_processor'].get('outputs')
    if output_config:
        output_mapping = {
            'output_lambda_functions': 'aws-lambda',
            'output_s3_buckets': 'aws-s3'
        }
        for tf_key, output in output_mapping.iteritems():
            if output in output_config:
                cluster_dict['module']['stream_alert_{}'.format(cluster_name)].update({
                    tf_key: modules['stream_alert']['alert_processor']['outputs'][output]
                })

    # Add Rule Processor input config
    input_config = modules['stream_alert']['rule_processor'].get('inputs')
    if input_config:
        cluster_dict['module']['stream_alert_{}'.format(cluster_name)].update({
            'input_sns_topics': input_config['aws-sns']
        })

    # Add the Alert Processor VPC config
    vpc_config = modules['stream_alert']['alert_processor'].get('vpc_config')
    if vpc_config:
        cluster_dict['module']['stream_alert_{}'.format(cluster_name)].update({
            'alert_processor_vpc_enabled': True,
            'alert_processor_vpc_subnet_ids': vpc_config['subnet_ids'],
            'alert_processor_vpc_security_group_ids': vpc_config['security_group_ids']
        })


def generate_cloudwatch_monitoring(cluster_name, cluster_dict, config):
    """Add the CloudWatch Monitoring module to the Terraform cluster dict.

    Args:
        cluster_name [string]: The name of the currently generating cluster
        cluster_dict [defaultdict]: The dict containing all Terraform config for
                                    a given cluster.
        config [dict]: The loaded config from the 'conf/' directory
    """
    prefix = config['global']['account']['prefix']
    cluster_dict['module']['cloudwatch_monitoring_{}'.format(cluster_name)] = {
        'source': 'modules/tf_stream_alert_monitoring',
        'sns_topic_arn': '${{module.stream_alert_{}.sns_topic_arn}}'.format(cluster_name),
        'lambda_functions': [
            '{}_{}_streamalert_rule_processor'.format(prefix, cluster_name),
            '{}_{}_streamalert_alert_processor'.format(prefix, cluster_name)
        ],
        'kinesis_stream': '{}_{}_stream_alert_kinesis'.format(prefix, cluster_name)
    }


def generate_kinesis(cluster_name, cluster_dict, config):
    """Add the Kinesis module to the Terraform cluster dict.

    Args:
        cluster_name [string]: The name of the currently generating cluster
        cluster_dict [defaultdict]: The dict containing all Terraform config for
                                    a given cluster.
        config [dict]: The loaded config from the 'conf/' directory
    """
    logging_bucket = '{}.streamalert.s3-logging'.format(
        config['global']['account']['prefix'])
    firehose_suffix = config['clusters'][cluster_name]['modules']['kinesis']['firehose']['s3_bucket_suffix']
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


def generate_outputs(cluster_name, cluster_dict, config):
    """Add the outputs to the Terraform cluster dict.

    Args:
        cluster_name [string]: The name of the currently generating cluster
        cluster_dict [defaultdict]: The dict containing all Terraform config for
                                    a given cluster.
        config [dict]: The loaded config from the 'conf/' directory
    """
    for module, output_vars in config['clusters'][cluster_name]['outputs'].iteritems():
        for output_var in output_vars:
            cluster_dict['output']['{}_{}_{}'.format(module, cluster_name, output_var)] = {
                'value': '${{module.{}_{}.{}}}'.format(module, cluster_name, output_var)}


def generate_kinesis_events(cluster_name, cluster_dict, config):
    """Add the Kinesis Events module to the Terraform cluster dict.

    Args:
        cluster_name [string]: The name of the currently generating cluster
        cluster_dict [defaultdict]: The dict containing all Terraform config for
                                    a given cluster.
        config [dict]: The loaded config from the 'conf/' directory
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


def generate_cloudtrail(cluster_name, cluster_dict, config):
    """Add the CloudTrail module to the Terraform cluster dict.

    Args:
        cluster_name [string]: The name of the currently generating cluster
        cluster_dict [defaultdict]: The dict containing all Terraform config for
                                    a given cluster.
        config [dict]: The loaded config from the 'conf/' directory
    """
    modules = config['clusters'][cluster_name]['modules']
    cloudtrail_enabled = bool(modules['cloudtrail']['enabled'])
    existing_trail_default = False
    existing_trail = modules['cloudtrail'].get('existing_trail', existing_trail_default)
    is_global_trail_default = True
    is_global_trail = modules['cloudtrail'].get('is_global_trail', is_global_trail_default)
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
        sys.exit(1)

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


def generate_flow_logs(cluster_name, cluster_dict, config):
    """Add the VPC Flow Logs module to the Terraform cluster dict.

    Args:
        cluster_name [string]: The name of the currently generating cluster
        cluster_dict [defaultdict]: The dict containing all Terraform config for
                                    a given cluster.
        config [dict]: The loaded config from the 'conf/' directory
    """
    modules = config['clusters'][cluster_name]['modules']
    if modules['flow_logs']['enabled']:
        cluster_dict['module']['flow_logs_{}'.format(cluster_name)] = {
            'source': 'modules/tf_stream_alert_flow_logs',
            'destination_stream_arn': '${{module.kinesis_{}.arn}}'.format(cluster_name),
            'flow_log_group_name': modules['flow_logs']['log_group_name']}
        for flow_log_input in ('vpcs', 'subnets', 'enis'):
            input_data = modules['flow_logs'].get(flow_log_input)
            if input_data:
                cluster_dict['module']['flow_logs_{}'.format(
                    cluster_name)][flow_log_input] = input_data


def generate_s3_events(cluster_name, cluster_dict, config):
    """Add the S3 Events module to the Terraform cluster dict.

    Args:
        cluster_name [string]: The name of the currently generating cluster
        cluster_dict [defaultdict]: The dict containing all Terraform config for
                                    a given cluster.
        config [dict]: The loaded config from the 'conf/' directory
    """
    modules = config['clusters'][cluster_name]['modules']
    s3_bucket_id = modules['s3_events'].get('s3_bucket_id')
    if s3_bucket_id:
        cluster_dict['module']['s3_events_{}'.format(cluster_name)] = {
            'source': 'modules/tf_stream_alert_s3_events',
            'lambda_function_arn': '${{module.stream_alert_{}.lambda_arn}}'.format(cluster_name),
            'lambda_function_name': '{}_{}_stream_alert_processor'.format(
                config['global']['account']['prefix'],
                cluster_name),
            's3_bucket_id': s3_bucket_id,
            's3_bucket_arn': 'arn:aws:s3:::{}'.format(s3_bucket_id)}
    else:
        LOGGER_CLI.error(
            'Config Error: Missing S3 bucket in %s s3_events module',
            cluster_name)
        sys.exit(1)


def generate_cluster(**kwargs):
    """Generate a StreamAlert cluster file.

    Keyword Args:
        cluster_name [string]: The name of the currently generating cluster
        config [dict]: The loaded config from the 'conf/' directory
    """
    config = kwargs.get('config')
    cluster_name = kwargs.get('cluster_name')

    account = config['global']['account']

    modules = config['clusters'][cluster_name]['modules']
    cluster_dict = infinitedict()

    generate_stream_alert(cluster_name, cluster_dict, config)

    if modules['cloudwatch_monitoring']['enabled']:
        generate_cloudwatch_monitoring(cluster_name, cluster_dict, config)

    generate_kinesis(cluster_name, cluster_dict, config)

    outputs = config['clusters'][cluster_name].get('outputs')
    if outputs:
        generate_outputs(cluster_name, cluster_dict, config)

    generate_kinesis_events(cluster_name, cluster_dict, config)

    cloudtrail_info = modules.get('cloudtrail')
    if cloudtrail_info:
        generate_cloudtrail(cluster_name, cluster_dict, config)

    flow_log_info = modules.get('flow_logs')
    if flow_log_info:
        generate_flow_logs(cluster_name, cluster_dict, config)

    s3_events_info = modules.get('s3_events')
    if s3_events_info:
        generate_s3_events(cluster_name, cluster_dict, config)

    return cluster_dict


def terraform_generate(**kwargs):
    """Generate all Terraform plans for the configured clusters.

    Keyword Args:
        config [dict]: The loaded config from the 'conf/' directory
        init [bool]: Indicates if main.tf is generated for `terraform init`
    """
    config = kwargs.get('config')
    init = kwargs.get('init', False)

    # Setup main
    LOGGER_CLI.info('Generating cluster file: main.tf')
    main_json = json.dumps(
        generate_main(init=init, config=config),
        indent=2,
        sort_keys=True
    )
    with open('terraform/main.tf', 'w') as tf_file:
        tf_file.write(main_json)

    # Break out early during the init process, clusters aren't needed yet
    if init:
        return True

    # Setup clusters
    for cluster in config.clusters():
        if cluster == 'main':
            raise InvalidClusterName('Rename cluster "main" to something else!')

        LOGGER_CLI.info('Generating cluster file: %s.tf', cluster)
        cluster_json = json.dumps(
            generate_cluster(cluster_name=cluster, config=config),
            indent=2,
            sort_keys=True
        )
        with open('terraform/{}.tf'.format(cluster), 'w') as tf_file:
            tf_file.write(cluster_json)

    return True

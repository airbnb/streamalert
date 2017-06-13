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

from collections import defaultdict

from stream_alert_cli.logger import LOGGER_CLI


class InvalidClusterName(Exception):
    """Exception for invalid cluster names"""
    pass

def infinitedict():
    """Create arbitrary levels of dictionary key/values"""
    return defaultdict(infinitedict)

def generate_s3_bucket(**kwargs):
    bucket = kwargs.get('bucket')
    acl = kwargs.get('acl', 'private')
    logging_bucket = kwargs.get('logging')
    logging = {
        'target_bucket': logging_bucket,
        'target_prefix': '{}/'.format(bucket)
    }
    force_destroy = kwargs.get('force_destroy', True)
    versioning = kwargs.get('versioning', {'enabled': True})

    return {
        'bucket': bucket,
        'acl': acl,
        'force_destroy': force_destroy,
        'versioning': versioning,
        'logging': logging
    }

def generate_main(**kwargs):
    init = kwargs.get('init')
    config = kwargs.get('config')

    main_dict = infinitedict()

    # Configure provider
    main_dict['provider']['aws'] = {}

    # Configure Terraform version requirement
    main_dict['terraform']['required_version'] = '> 0.9.0'

    # Setup the Backend
    if init:
        main_dict['terraform']['backend']['local'] = {
            'path': 'terraform.tfstate'
        }
    else:
        main_dict['terraform']['backend']['s3'] = {
            'bucket': '{}.streamalert.terraform.state'.format(config['global']['account']['prefix']),
            'key': 'stream_alert_state/terraform.tfstate',
            'region': 'us-east-1',
            'encrypt': True,
            'acl': 'private',
            'kms_key_id': 'alias/{}'.format(config['global']['account']['kms_key_alias'])
        }

    logging_bucket = '{}.streamalert.s3-logging'.format(config['global']['account']['prefix'])
    # Configure init S3 buckets
    main_dict['resource']['aws_s3_bucket'] = {
        'lambda_source': generate_s3_bucket(
            bucket='{}.streamalert.source'.format(config['global']['account']['prefix']),
            logging=logging_bucket
        ),
        'stream_alert_secrets': generate_s3_bucket(
            bucket='{}.streamalert.secrets'.format(config['global']['account']['prefix']),
            logging=logging_bucket
        ),
        'terraform_state': generate_s3_bucket(
            bucket=config['global']['terraform']['tfstate_bucket'],
            logging=logging_bucket
        ),
        'logging_bucket': generate_s3_bucket(
            bucket=logging_bucket,
            acl='log-delivery-write',
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

    return main_dict

def generate_cluster(**kwargs):
    config = kwargs.get('config')
    cluster_name = kwargs.get('cluster_name')
    account = config['global']['account']
    prefix = account['prefix']
    account_id = account['aws_account_id']
    firehose_suffix = config['clusters'][cluster_name]['modules']['kinesis']['firehose']['s3_bucket_suffix']
    modules = config['clusters'][cluster_name]['modules']
    cluster_dict = infinitedict()

    # Main StreamAlert module
    cluster_dict['module']['stream_alert_{}'.format(cluster_name)] = {
      'source': 'modules/tf_stream_alert',
      'account_id': account_id,
      'region': config['clusters'][cluster_name]['region'],
      'prefix': prefix,
      'cluster': cluster_name,
      'kms_key_arn': '${aws_kms_key.stream_alert_secrets.arn}',
      'rule_processor_memory': modules['stream_alert']['rule_processor']['memory'],
      'rule_processor_timeout': modules['stream_alert']['rule_processor']['timeout'],
      'rule_processor_version': modules['stream_alert']['rule_processor']['current_version'],
      'rule_processor_config': '${var.rule_processor_config}',
      'alert_processor_config': '${var.alert_processor_config}',
      'alert_processor_memory': modules['stream_alert']['alert_processor']['memory'],
      'alert_processor_timeout': modules['stream_alert']['alert_processor']['timeout'],
      'alert_processor_version': modules['stream_alert']['alert_processor']['current_version']
    }

    # Add Alert Processor output config conditionally to the StreamAlert module
    output_config =  modules['stream_alert']['alert_processor'].get('outputs')
    if output_config:
        cluster_dict['module']['stream_alert_{}'.format(cluster_name)].update({
            'output_lambda_functions': modules['stream_alert']['alert_processor']['outputs']['aws-lambda'],
            'output_s3_buckets':  modules['stream_alert']['alert_processor']['outputs']['aws-s3']
        })

    # Add Alert Processor input config conditionally to the StreamAlert module
    input_config =  modules['stream_alert']['rule_processor'].get('inputs')
    if input_config:
        cluster_dict['module']['stream_alert_{}'.format(cluster_name)].update({
            'input_sns_topics': input_config['aws-sns']
        })

    # Add the VPC config conditionally to the StreamAlert module
    vpc_config = modules['stream_alert']['alert_processor'].get('vpc_config')
    if vpc_config:
        cluster_dict['module']['stream_alert_{}'.format(cluster_name)].update({
            'alert_processor_vpc_enabled': True,
            'alert_processor_vpc_subnet_ids': vpc_config['subnet_ids'],
            'alert_processor_vpc_security_group_ids': vpc_config['security_group_ids']
        })

    if modules['cloudwatch_monitoring']['enabled']:
        # CloudWatch monitoring module
        cluster_dict['module']['cloudwatch_monitoring_{}'.format(cluster_name)] = {
          'source': 'modules/tf_stream_alert_monitoring',
          'sns_topic_arn': '${{module.stream_alert_{}.sns_topic_arn}}'.format(cluster_name),
          'lambda_functions': [
            '{}_{}_streamalert_rule_processor'.format(prefix, cluster_name),
            '{}_{}_streamalert_alert_processor'.format(prefix, cluster_name)
          ],
          'kinesis_stream': '{}_{}_stream_alert_kinesis'.format(prefix, cluster_name)
        }

    # Kinesis module
    cluster_dict['module']['kinesis_{}'.format(cluster_name)] = {
        'source': 'modules/tf_stream_alert_kinesis',
        'account_id': account_id,
        'region': config['clusters'][cluster_name]['region'],
        'cluster_name': cluster_name,
        'firehose_s3_bucket_name': '{}.{}.{}'.format(prefix, cluster_name, firehose_suffix),
        'stream_name': '{}_{}_stream_alert_kinesis'.format(prefix, cluster_name),
        'firehose_name': '{}_{}_stream_alert_firehose'.format(prefix, cluster_name),
        'username': '{}_{}_stream_alert_user'.format(prefix, cluster_name),
        'shards': modules['kinesis']['streams']['shards'],
        'retention': modules['kinesis']['streams']['retention']
    }

    outputs = config['clusters'][cluster_name].get('outputs')
    if outputs:
        # Add outputs
        for module, output_vars in outputs.iteritems():
            for output_var in output_vars:
                cluster_dict['output']['{}_{}_{}'.format(module, cluster_name, output_var)] = {
                    'value': '${{module.{}_{}.{}}}'.format(module, cluster_name, output_var)
                }

    kinesis_events_enabled = bool(modules['kinesis_events']['enabled'])
    # Kinesis events module
    cluster_dict['module']['kinesis_events_{}'.format(cluster_name)] = {
        'source': 'modules/tf_stream_alert_kinesis_events',
        'lambda_production_enabled': kinesis_events_enabled,
        'lambda_role_id': '${{module.stream_alert_{}.lambda_role_id}}'.format(cluster_name),
        'lambda_function_arn': '${{module.stream_alert_{}.lambda_arn}}'.format(cluster_name),
        'kinesis_stream_arn': '${{module.kinesis_{}.arn}}'.format(cluster_name),
        'role_policy_prefix': cluster_name
    }

    cloudtrail_info = modules.get('cloudtrail')
    if cloudtrail_info:
        cloudtrail_enabled = bool(cloudtrail_info['enabled'])
        cluster_dict['module']['cloudtrail_{}'.format(cluster_name)] = {
            'account_id': account_id,
            'cluster': cluster_name,
            'kinesis_arn': '${{module.kinesis_{}.arn}}'.format(cluster_name),
            'prefix': prefix,
            'enable_logging': cloudtrail_enabled,
            'source': 'modules/tf_stream_alert_cloudtrail'
        }

    flow_log_info = modules.get('flow_logs')
    if flow_log_info:
        if flow_log_info['enabled']:
            cluster_dict['module']['flow_logs_{}'.format(cluster_name)] = {
                'source': 'modules/tf_stream_alert_flow_logs',
                'destination_stream_arn': '${{module.kinesis_{}.arn}}'.format(cluster_name),
                'flow_log_group_name': flow_log_info['log_group_name']
            }
            for input in ('vpcs', 'subnets', 'enis'):
                input_data = flow_log_info.get(input)
                if input_data:
                    cluster_dict['module']['flow_logs_{}'.format(cluster_name)][input] = input_data

    return cluster_dict

def terraform_generate(**kwargs):
    """Generate all Terraform plans for the clusters in variables.json"""
    config = kwargs.get('config')
    init = kwargs.get('init', False)

    # Setup main
    LOGGER_CLI.info('Generating cluster file: main.tf')
    main_json = json.dumps(
        generate_main(init=init, config=config),
        indent=4,
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
            indent=4,
            sort_keys=True
        )
        with open('terraform/{}.tf'.format(cluster), 'w') as tf_file:
            tf_file.write(cluster_json)

    return True

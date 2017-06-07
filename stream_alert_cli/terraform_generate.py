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
    force_destroy = kwargs.get('force_destroy', True)
    versioning = kwargs.get('versioning', {'enabled': True})
    
    return {
        'bucket': bucket,
        'acl': acl,
        'force_destroy': force_destroy,
        'versioning': versioning
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
            'bucket': '{}.streamalert.terraform.state'.format(config['account']['prefix']),
            'key': 'stream_alert_state/terraform.tfstate',
            'region': 'us-east-1',
            'encrypt': True,
            'acl': 'private',
            'kms_key_id': 'alias/{}'.format(config['account']['kms_key_alias'])
        }

    main_dict['resource']['aws_s3_bucket'] = {
        'lambda_source': generate_s3_bucket(
            bucket='{}.streamalert.source'.format(config['account']['prefix'])
        ),
        'stream_alert_secrets': generate_s3_bucket(
            bucket='{}.streamalert.secrets'.format(config['account']['prefix'])
        ),
        'terraform_state': generate_s3_bucket(
            bucket='{}.streamalert.terraform.state'.format(config['account']['prefix'])
        )
    }

    main_dict['resource']['aws_kms_key']['stream_alert_secrets'] = {
        'enable_key_rotation': True,
        'description': 'StreamAlert secret management'
    }

    main_dict['resource']['aws_kms_alias']['stream_alert_secrets'] = {
        'name': 'alias/{}'.format(config['account']['kms_key_alias']),
        'target_key_id': '${aws_kms_key.stream_alert_secrets.key_id}'
    }

    return main_dict

def generate_cluster(**kwargs):
    config = kwargs.get('config')
    cluster_name = kwargs.get('cluster_name')

    prefix = config['account']['prefix']
    firehose_suffix = config['firehose']['s3_bucket_suffix']
    cluster_dict = infinitedict()

    # Main StreamAlert module
    cluster_dict['module']['stream_alert_{}'.format(cluster_name)] = {
      'source': 'modules/tf_stream_alert',
      'account_id': '${lookup(var.account, "aws_account_id")}',
      'region': '${{lookup(var.clusters, "{}")}}'.format(cluster_name),
      'prefix': '${lookup(var.account, "prefix")}',
      'cluster': cluster_name,
      'kms_key_arn': '${aws_kms_key.stream_alert_secrets.arn}',
      'rule_processor_config': '${var.rule_processor_config}',
      'rule_processor_lambda_config': '${var.rule_processor_lambda_config}',
      'rule_processor_versions': '${var.rule_processor_versions}',
      'alert_processor_config': '${var.alert_processor_config}',
      'alert_processor_lambda_config': '${var.alert_processor_lambda_config}',
      'alert_processor_versions': '${var.alert_processor_versions}',
      'output_lambda_functions': '${var.aws-lambda}',
      'output_s3_buckets': '${var.aws-s3}',
      'input_sns_topics': '${var.aws-sns}'
    }

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

    # Add outputs
    for output in ('username', 'access_key_id', 'secret_key'):        
        cluster_dict['output']['kinesis_{}_{}'.format(cluster_name, output)] = {
            'value': '${{module.kinesis_{}.{}}}'.format(cluster_name, output)
        }

    # Kinesis module
    cluster_dict['module']['kinesis_{}'.format(cluster_name)] = {
        'source': 'modules/tf_stream_alert_kinesis',
        'account_id': '${lookup(var.account, "aws_account_id")}',
        'region': '${{lookup(var.clusters, "{}")}}'.format(cluster_name),
        'cluster_name': cluster_name,
        'firehose_s3_bucket_name': '{}.{}.{}'.format(prefix, cluster_name, firehose_suffix),
        'stream_name': '{}_{}_stream_alert_kinesis'.format(prefix, cluster_name),
        'firehose_name': '{}_{}_stream_alert_firehose'.format(prefix, cluster_name),
        'username': '{}_{}_stream_alert_user'.format(prefix, cluster_name),
        'stream_config': '${{var.kinesis_streams_config["{}"]}}'.format(cluster_name)
    }

    # Kinesis events module
    cluster_dict['module']['kinesis_events_{}'.format(cluster_name)] = {
        'source': 'modules/tf_stream_alert_kinesis_events',
        'lambda_production_enabled': True,
        'lambda_role_id': '${{module.stream_alert_{}.lambda_role_id}}'.format(cluster_name),
        'lambda_function_arn': '${{module.stream_alert_{}.lambda_arn}}'.format(cluster_name),
        'kinesis_stream_arn': '${{module.kinesis_{}.arn}}'.format(cluster_name),
        'role_policy_prefix': cluster_name
    }

    return cluster_dict

def terraform_generate(**kwargs):
    """Generate all Terraform plans for the clusters in variables.json"""
    LOGGER_CLI.info('Generating Terraform files')
    config = kwargs.get('config')
    init = kwargs.get('init', False)

    # Setup main
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
    for cluster in config['clusters'].keys():
        if cluster == 'main':
            raise InvalidClusterName('Rename cluster "main" to something else!')
    
        cluster_json = json.dumps(
            generate_cluster(cluster_name=cluster, config=config),
            indent=4,
            sort_keys=True
        )
        with open('terraform/{}.tf'.format(cluster), 'w') as tf_file:
            tf_file.write(cluster_json)

    return True

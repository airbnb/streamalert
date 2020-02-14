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

from streamalert.shared.logger import get_logger
from streamalert_cli.helpers import check_credentials
from streamalert_cli.terraform.common import (
    InvalidClusterName,
    infinitedict,
    monitoring_topic_name,
    s3_access_logging_bucket,
)
from streamalert_cli.terraform.alert_merger import generate_alert_merger
from streamalert_cli.terraform.alert_processor import generate_alert_processor
from streamalert_cli.terraform.apps import generate_apps
from streamalert_cli.terraform.athena import generate_athena
from streamalert_cli.terraform.cloudtrail import generate_cloudtrail
from streamalert_cli.terraform.cloudwatch_destinations import (
    generate_cloudwatch_destinations,
)
from streamalert_cli.terraform.cloudwatch_events import generate_cloudwatch_events
from streamalert_cli.terraform.firehose import generate_firehose
from streamalert_cli.terraform.flow_logs import generate_flow_logs
from streamalert_cli.terraform.helpers import terraform_check
from streamalert_cli.terraform.kinesis_events import generate_kinesis_events
from streamalert_cli.terraform.kinesis_streams import generate_kinesis_streams
from streamalert_cli.terraform.metrics import (
    generate_aggregate_cloudwatch_metric_alarms,
    generate_aggregate_cloudwatch_metric_filters,
    generate_cluster_cloudwatch_metric_filters,
    generate_cluster_cloudwatch_metric_alarms
)
from streamalert_cli.terraform.monitoring import generate_monitoring
from streamalert_cli.terraform.rule_promotion import generate_rule_promotion
from streamalert_cli.terraform.classifier import generate_classifier
from streamalert_cli.terraform.rules_engine import generate_rules_engine
from streamalert_cli.terraform.s3_events import generate_s3_events
from streamalert_cli.terraform.threat_intel_downloader import generate_threat_intel_downloader
from streamalert_cli.utils import CLICommand

RESTRICTED_CLUSTER_NAMES = ('main', 'athena')
TERRAFORM_VERSION = '~> 0.12.9'
TERRAFORM_PROVIDER_VERSION = '~> 2.28.1'

LOGGER = get_logger(__name__)


def _terraform_defaults(region):
    return infinitedict({
        'terraform': {
            'required_version': TERRAFORM_VERSION,
        },
        'provider': {
            'aws': {
                'region': region,
                'version': TERRAFORM_PROVIDER_VERSION,
            },
        },
    })


def generate_s3_bucket(bucket, logging, **kwargs):
    """Generate an S3 Bucket dict

    Args:
        bucket (str): The name of the bucket
        logging (str): The S3 bucket to send access logs to

    Keyword Args:
        acl (str): The S3 bucket ACL
        force_destroy (bool): To enable or disable force destroy of the bucket
        sse_algorithm (str): Server-side encryption algorithm 'AES256' or 'aws:kms' (default)
        versioning (bool): To enable or disable S3 object versioning
        lifecycle_rule (dict): The S3 bucket lifecycle rule

    Returns:
        dict: S3 bucket Terraform dict to be used in clusters/main.tf.json
    """
    sse_algorithm = kwargs.get('sse_algorithm', 'aws:kms')

    s3_bucket = {
        'bucket': bucket,
        'acl': kwargs.get('acl', 'private'),
        'force_destroy': kwargs.get('force_destroy', True),
        'versioning': {
            'enabled': kwargs.get('versioning', True)
        },
        'logging': {
            'target_bucket': logging,
            'target_prefix': '{}/'.format(bucket)
        },
        'server_side_encryption_configuration': {
            'rule': {
                'apply_server_side_encryption_by_default': {
                    'sse_algorithm': sse_algorithm
                }
            }
        },
        'policy': json.dumps({
            'Version': '2012-10-17',
            'Statement': [
                {
                    'Sid': 'ForceSSLOnlyAccess',
                    'Effect': 'Deny',
                    'Principal': '*',
                    'Action': 's3:*',
                    'Resource': [
                        'arn:aws:s3:::{}/*'.format(bucket),
                        'arn:aws:s3:::{}'.format(bucket)
                    ],
                    'Condition': {
                        'Bool': {
                            'aws:SecureTransport': 'false'
                        }
                    }
                }
            ]
        })
    }

    if sse_algorithm == 'aws:kms':
        s3_bucket['server_side_encryption_configuration']['rule'][
            'apply_server_side_encryption_by_default']['kms_master_key_id'] = (
                '${aws_kms_key.server_side_encryption.key_id}')

    lifecycle_rule = kwargs.get('lifecycle_rule')
    if lifecycle_rule:
        s3_bucket['lifecycle_rule'] = lifecycle_rule

    return s3_bucket


def generate_main(config, init=False):
    """Generate the main.tf.json Terraform dict

    Args:
        config (CLIConfig): The loaded CLI config
        init (bool): Terraform is running in the init phase or not (optional)

    Returns:
        dict: main.tf.json Terraform dict
    """
    main_dict = _terraform_defaults(config['global']['account']['region'])

    logging_bucket, create_logging_bucket = s3_access_logging_bucket(config)

    # Setup the Backend depending on the deployment phase.
    # When first setting up StreamAlert, the Terraform statefile
    # is stored locally.  After the first dependencies are created,
    # this moves to S3.
    if init:
        main_dict['terraform']['backend']['local'] = {
            'path': 'terraform.tfstate',
        }
    else:
        main_dict['terraform']['backend']['s3'] = {
            'bucket': config['global'].get('terraform', {}).get(
                'tfstate_bucket',
                '{}-streamalert-terraform-state'.format(config['global']['account']['prefix'])
            ),
            'key': config['global'].get('terraform', {}).get(
                'tfstate_s3_key',
                'streamalert_state/terraform.tfstate'
            ),
            'region': config['global']['account']['region'],
            'encrypt': True,
            'dynamodb_table': '{}_streamalert_terraform_state_lock'.format(
                config['global']['account']['prefix']
            ),
            'acl': 'private',
            'kms_key_id': 'alias/{}'.format(
                config['global']['account'].get(
                    'kms_key_alias',
                    '{}_streamalert_secrets'.format(config['global']['account']['prefix'])
                )
            ),
        }

    # Configure initial S3 buckets
    main_dict['resource']['aws_s3_bucket'] = {
        'streamalert_secrets': generate_s3_bucket(
            # FIXME (derek.wang) DRY out by using OutputCredentialsProvider?
            bucket='{}-streamalert-secrets'.format(config['global']['account']['prefix']),
            logging=logging_bucket
        ),
        'streamalerts': generate_s3_bucket(
            bucket=(
                config['global']['infrastructure'].get('alerts_firehose', {}).get('bucket_name')
                or '{}-streamalerts'.format(config['global']['account']['prefix'])
            ),
            logging=logging_bucket
        )
    }

    # Create bucket for S3 access logs (if applicable)
    if create_logging_bucket:
        main_dict['resource']['aws_s3_bucket']['logging_bucket'] = generate_s3_bucket(
            bucket=logging_bucket,
            logging=logging_bucket,
            acl='log-delivery-write',
            lifecycle_rule={
                'prefix': '/',
                'enabled': True,
                'transition': {
                    'days': 365,
                    'storage_class': 'GLACIER'
                }
            },
            sse_algorithm='AES256'  # SSE-KMS doesn't seem to work with access logs
        )

    # Create bucket for Terraform state (if applicable)
    if config['global'].get('terraform', {}).get('create_bucket', True):
        main_dict['resource']['aws_s3_bucket']['terraform_remote_state'] = generate_s3_bucket(
            bucket=config['global'].get('terraform', {}).get(
                'tfstate_bucket',
                '{}-streamalert-terraform-state'.format(config['global']['account']['prefix'])
            ),
            logging=logging_bucket
        )

    # Setup Firehose Delivery Streams
    generate_firehose(logging_bucket, main_dict, config)

    # Configure global resources like Firehose alert delivery and alerts table
    main_dict['module']['globals'] = _generate_global_module(config)

    # KMS Key and Alias creation
    main_dict['resource']['aws_kms_key']['server_side_encryption'] = {
        'enable_key_rotation': True,
        'description': 'StreamAlert S3 Server-Side Encryption',
        'policy': json.dumps({
            'Version': '2012-10-17',
            'Statement': [
                {
                    'Sid': 'Enable IAM User Permissions',
                    'Effect': 'Allow',
                    'Principal': {
                        'AWS': 'arn:aws:iam::{}:root'.format(
                            config['global']['account']['aws_account_id']
                        )
                    },
                    'Action': 'kms:*',
                    'Resource': '*'
                },
                {
                    'Sid': 'Allow principals in the account to use the key',
                    'Effect': 'Allow',
                    'Principal': '*',
                    'Action': ['kms:Decrypt', 'kms:GenerateDataKey*', 'kms:Encrypt'],
                    'Resource': '*',
                    'Condition': {
                        'StringEquals': {
                            'kms:CallerAccount': config['global']['account']['aws_account_id']
                        }
                    }
                }
            ]
        })
    }
    main_dict['resource']['aws_kms_alias']['server_side_encryption'] = {
        'name': 'alias/{}_server-side-encryption'.format(config['global']['account']['prefix']),
        'target_key_id': '${aws_kms_key.server_side_encryption.key_id}'
    }

    main_dict['resource']['aws_kms_key']['streamalert_secrets'] = {
        'enable_key_rotation': True,
        'description': 'StreamAlert secret management'
    }
    main_dict['resource']['aws_kms_alias']['streamalert_secrets'] = {
        'name': 'alias/{}'.format(
            config['global']['account'].get(
                'kms_key_alias',
                '{}_streamalert_secrets'.format(config['global']['account']['prefix'])
            )
        ),
        'target_key_id': '${aws_kms_key.streamalert_secrets.key_id}'
    }

    # Global infrastructure settings
    topic_name, create_topic = monitoring_topic_name(config)
    if create_topic:
        main_dict['resource']['aws_sns_topic']['monitoring'] = {
            'name': topic_name
        }

    return main_dict


def generate_cluster(config, cluster_name):
    """Generate a StreamAlert cluster file.

    Args:
        config (dict): The loaded config from the 'conf/' directory
        cluster_name (str): The name of the currently generating cluster

    Returns:
        dict: generated Terraform cluster dictionary
    """
    modules = config['clusters'][cluster_name]['modules']
    cluster_dict = infinitedict()

    generate_classifier(cluster_name, cluster_dict, config)

    generate_cluster_cloudwatch_metric_filters(cluster_name, cluster_dict, config)

    generate_cluster_cloudwatch_metric_alarms(cluster_name, cluster_dict, config)

    if modules.get('cloudwatch_monitoring', {}).get('enabled'):
        if not generate_monitoring(cluster_name, cluster_dict, config):
            return

    if modules.get('kinesis'):
        if not generate_kinesis_streams(cluster_name, cluster_dict, config):
            return

    if modules.get('kinesis_events'):
        if not generate_kinesis_events(cluster_name, cluster_dict, config):
            return

    if modules.get('cloudtrail'):
        if not generate_cloudtrail(cluster_name, cluster_dict, config):
            return

    # purposely not using .get, since no extra settings are required for this module
    if 'cloudwatch_events' in modules:
        if not generate_cloudwatch_events(cluster_name, cluster_dict, config):
            return

    if modules.get('cloudwatch_logs_destination'):
        if not generate_cloudwatch_destinations(cluster_name, cluster_dict, config):
            return

    if modules.get('flow_logs'):
        if not generate_flow_logs(cluster_name, cluster_dict, config):
            return

    if modules.get('s3_events'):
        if not generate_s3_events(cluster_name, cluster_dict, config):
            return

    generate_apps(cluster_name, cluster_dict, config)

    return cluster_dict


def cleanup_old_tf_files():
    """
    Cleanup old *.tf.json files
    """
    for terraform_file in os.listdir('terraform'):
        if fnmatch(terraform_file, '*.tf.json'):
            os.remove(os.path.join('terraform', terraform_file))


class TerraformGenerateCommand(CLICommand):
    description = 'Generate Terraform files from JSON cluster files'

    @classmethod
    def setup_subparser(cls, subparser):
        """Manage.py generate takes no arguments"""

    @classmethod
    def handler(cls, options, config):
        return terraform_generate_handler(config, check_creds=False)


def terraform_generate_handler(config, init=False, check_tf=True, check_creds=True):
    """Generate all Terraform plans for the configured clusters.

    Keyword Args:
        config (dict): The loaded config from the 'conf/' directory
        init (bool): Indicates if main.tf.json is generated for `init`

    Returns:
        bool: Result of cluster generating
    """
    # Check for valid credentials
    if check_creds and not check_credentials():
        return False

    # Verify terraform is installed
    if check_tf and not terraform_check():
        return False

    cleanup_old_tf_files()

    # Setup the main.tf.json file
    LOGGER.debug('Generating cluster file: main.tf.json')
    _create_terraform_module_file(generate_main(config, init=init), 'terraform/main.tf.json')

    # Return early during the init process, clusters are not needed yet
    if init:
        return True

    # Setup cluster files
    for cluster in config.clusters():
        if cluster in RESTRICTED_CLUSTER_NAMES:
            raise InvalidClusterName(
                'Rename cluster "main" or "athena" to something else!')

        LOGGER.debug('Generating cluster file: %s.tf.json', cluster)
        cluster_dict = generate_cluster(config=config, cluster_name=cluster)
        if not cluster_dict:
            LOGGER.error(
                'An error was generated while creating the %s cluster', cluster)
            return False

        _create_terraform_module_file(cluster_dict, 'terraform/{}.tf.json'.format(cluster))

    metric_filters = generate_aggregate_cloudwatch_metric_filters(config)
    if metric_filters:
        _create_terraform_module_file(metric_filters, 'terraform/metric_filters.tf.json')

    metric_alarms = generate_aggregate_cloudwatch_metric_alarms(config)
    if metric_alarms:
        _create_terraform_module_file(metric_alarms, 'terraform/metric_alarms.tf.json')

    # Setup Athena
    generate_global_lambda_settings(
        config,
        config_name='athena_partition_refresh_config',
        generate_func=generate_athena,
        tf_tmp_file='terraform/athena.tf.json',
        message='Removing old Athena Terraform file'
    )

    # Setup Threat Intel Downloader Lambda function if it is enabled
    generate_global_lambda_settings(
        config,
        config_name='threat_intel_downloader_config',
        generate_func=generate_threat_intel_downloader,
        tf_tmp_file='terraform/ti_downloader.tf.json',
        message='Removing old Threat Intel Downloader Terraform file'
    )

    # Setup Rule Promotion if it is enabled
    generate_global_lambda_settings(
        config,
        config_name='rule_promotion_config',
        generate_func=generate_rule_promotion,
        tf_tmp_file='terraform/rule_promotion.tf.json',
        message='Removing old Rule Promotion Terraform file'
    )

    # Setup Rules Engine
    generate_global_lambda_settings(
        config,
        config_name='rules_engine_config',
        generate_func=generate_rules_engine,
        tf_tmp_file='terraform/rules_engine.tf.json',
        message='Removing old Rules Engine Terraform file'
    )

    # Setup Alert Processor
    generate_global_lambda_settings(
        config,
        config_name='alert_processor_config',
        generate_func=generate_alert_processor,
        tf_tmp_file='terraform/alert_processor.tf.json',
        message='Removing old Alert Processor Terraform file'
    )

    # Setup Alert Merger
    generate_global_lambda_settings(
        config,
        config_name='alert_merger_config',
        generate_func=generate_alert_merger,
        tf_tmp_file='terraform/alert_merger.tf.json',
        message='Removing old Alert Merger Terraform file'
    )

    # Setup Lookup Tables if applicable
    _generate_lookup_tables_settings(config)

    return True


def _generate_lookup_tables_settings(config):
    """
    Generates .tf.json file for LookupTables
    """
    tf_file_name = 'terraform/lookup_tables.tf.json'

    if not config['lookup_tables'].get('enabled', False):
        remove_temp_terraform_file(tf_file_name, 'Removing old LookupTables Terraform file')
        return

    # Use the lookup_tables.json configuration file to determine which resources we have
    dynamodb_tables = set()
    s3_buckets = set()
    for _, table_config in config['lookup_tables'].get('tables', {}).items():
        if table_config['driver'] == 's3':
            s3_buckets.add(table_config['bucket'])
            continue

        if table_config['driver'] == 'dynamodb':
            dynamodb_tables.add(table_config['table'])
            continue

    if not dynamodb_tables and not s3_buckets:
        # If no resources are configured at all, simply return and do not generate lookuptables
        # IAM policies
        remove_temp_terraform_file(tf_file_name, 'No tables configured')
        return

    roles = {
        '${module.alert_processor_lambda.role_id}',
        '${module.alert_merger_lambda.role_id}',
        '${module.rules_engine_lambda.role_id}',
    }

    for cluster in config.clusters():
        roles.add('${{module.classifier_{}_lambda.role_id}}'.format(cluster))

    generated_config = {'module': {}}

    if dynamodb_tables:
        generated_config['module']['lookup_tables_iam_dynamodb'] = {
            'source': './modules/tf_lookup_tables_dynamodb',
            'dynamodb_tables': sorted(dynamodb_tables),
            'roles': sorted(roles),
            'role_count': len(roles),
            'account_id': config['global']['account']['aws_account_id'],
            'region': config['global']['account']['region'],
            'prefix': config['global']['account']['prefix'],
        }

    if s3_buckets:
        generated_config['module']['lookup_tables_iam_s3'] = {
            'source': './modules/tf_lookup_tables_s3',
            's3_buckets': sorted(s3_buckets),
            'roles': sorted(roles),
            'role_count': len(roles),
            'prefix': config['global']['account']['prefix'],
        }

    _create_terraform_module_file(generated_config, tf_file_name)


def generate_global_lambda_settings(config, config_name, generate_func, tf_tmp_file, message):
    """Generate settings for global Lambda functions

    Args:
        config (dict): lambda function settings read from 'conf/' directory
        config_name (str): keyname of lambda function settings in config.
        generate_func (func): method to generate lambda function settings.
        tf_tmp_file (str): filename of terraform file, generated by CLI.
        message (str): Message will be logged by LOGGER.
    """
    if not config['lambda'].get(config_name):
        LOGGER.warning('Config for \'%s\' not in lambda.json', config_name)
        remove_temp_terraform_file(tf_tmp_file, message)
        return

    if config['lambda'][config_name].get('enabled', True):
        generated_config = generate_func(config=config)
        if generated_config:
            _create_terraform_module_file(generated_config, tf_tmp_file)
    else:
        remove_temp_terraform_file(tf_tmp_file, message)


def remove_temp_terraform_file(tf_tmp_file, message):
    """Remove temporal terraform file

    Args:
        tf_tmp_file (str): filename of terraform file, generated by CLI.
        message (str): Message will be logged by LOGGER.
    """
    if os.path.isfile(tf_tmp_file):
        LOGGER.info(message)
        os.remove(tf_tmp_file)


def _generate_global_module(config):
    # 2019-08-22 (Ryxias)
    #   In version 3.0.0+, StreamAlert will default to always using the prefix, when "use_prefix"
    #   is not present.
    #
    #   Refer to this PR for more information: https://github.com/airbnb/streamalert/pull/979
    use_prefix = config['global']['infrastructure'].get('classifier_sqs', {}).get(
        'use_prefix', True
    )

    global_module = {
        'source': './modules/tf_globals',
        'account_id': config['global']['account']['aws_account_id'],
        'region': config['global']['account']['region'],
        'prefix': config['global']['account']['prefix'],
        'kms_key_arn': '${aws_kms_key.server_side_encryption.arn}',
        'rules_engine_timeout': config['lambda']['rules_engine_config']['timeout'],
        'sqs_use_prefix': use_prefix,
    }

    # The below code applies settings for resources only if the settings are explicitly
    # defined. This is because these resources have defaults defined in the
    # ./modules/tf_globals module. This will allow for overriding these setting, but
    # avoids storing defaults in mulitple locations
    if 'alerts_table' in config['global']['infrastructure']:
        for setting in {'read_capacity', 'write_capacity'}:
            value = config['global']['infrastructure']['alerts_table'].get(setting)
            if value:
                global_module['alerts_table_{}'.format(setting)] = value

    alert_fh_settings_with_defaults = {
        'bucket_name',
        'buffer_size',
        'buffer_interval',
        'cloudwatch_log_retention',
        'compression_format',
    }

    if 'alerts_firehose' in config['global']['infrastructure']:
        for setting in alert_fh_settings_with_defaults:
            value = config['global']['infrastructure']['alerts_firehose'].get(setting)
            if not value:
                continue

            global_module['alerts_firehose_{}'.format(setting)] = value

    if 'rule_staging' in config['global']['infrastructure']:
        if config['global']['infrastructure']['rule_staging'].get('enabled'):
            global_module['enable_rule_staging'] = True
            for setting in {'table_read_capacity', 'table_write_capacity'}:
                value = config['global']['infrastructure']['rule_staging'].get(setting)
                if value:
                    # Defaults are set for this in the terraform module, so skip
                    global_module['rules_{}'.format(setting)] = value

    return global_module


def _create_terraform_module_file(generated_config, filename):
    """
    Dumps the given generated_config, a JSON dict, into the given filename under the terraform/
    directory, as a .tf.json file.
    """
    with open(filename, 'w') as file:
        json.dump(generated_config, file, indent=2, sort_keys=True)

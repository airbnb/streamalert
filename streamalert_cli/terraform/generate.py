"""
Copyright 2017-present Airbnb, Inc.

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
import json
import os

from streamalert.shared.config import ConfigError, firehose_alerts_bucket
from streamalert.shared.logger import get_logger
from streamalert.shared.utils import get_data_file_format, get_database_name
from streamalert_cli.athena.helpers import generate_alerts_table_schema
from streamalert_cli.helpers import check_credentials
from streamalert_cli.terraform.alert_merger import generate_alert_merger
from streamalert_cli.terraform.alert_processor import generate_alert_processor
from streamalert_cli.terraform.apps import generate_apps
from streamalert_cli.terraform.artifact_extractor import \
    generate_artifact_extractor
from streamalert_cli.terraform.athena import generate_athena
from streamalert_cli.terraform.classifier import generate_classifier
from streamalert_cli.terraform.cloudtrail import generate_cloudtrail
from streamalert_cli.terraform.cloudwatch_destinations import \
    generate_cloudwatch_destinations
from streamalert_cli.terraform.cloudwatch_events import \
    generate_cloudwatch_events
from streamalert_cli.terraform.common import (InvalidClusterName, infinitedict,
                                              monitoring_topic_name,
                                              s3_access_logging_bucket,
                                              terraform_state_bucket)
from streamalert_cli.terraform.firehose import generate_firehose
from streamalert_cli.terraform.flow_logs import generate_flow_logs
from streamalert_cli.terraform.helpers import terraform_check
from streamalert_cli.terraform.kinesis_events import generate_kinesis_events
from streamalert_cli.terraform.kinesis_streams import generate_kinesis_streams
from streamalert_cli.terraform.metrics import (
    generate_aggregate_cloudwatch_metric_alarms,
    generate_aggregate_cloudwatch_metric_filters,
    generate_cluster_cloudwatch_metric_alarms,
    generate_cluster_cloudwatch_metric_filters)
from streamalert_cli.terraform.monitoring import generate_monitoring
from streamalert_cli.terraform.rule_promotion import generate_rule_promotion
from streamalert_cli.terraform.rules_engine import generate_rules_engine
from streamalert_cli.terraform.s3_events import generate_s3_events
from streamalert_cli.terraform.scheduled_queries import \
    generate_scheduled_queries_module_configuration
from streamalert_cli.terraform.threat_intel_downloader import \
    generate_threat_intel_downloader
from streamalert_cli.utils import CLICommand

RESTRICTED_CLUSTER_NAMES = ('main', 'athena')

LOGGER = get_logger(__name__)


def write_vars(config, **kwargs):
    """Write root variables to a terraform.tfvars.json file

    Keyword Args:
        region (string): AWS region where infrastructure will be built
    """
    _create_terraform_module_file(kwargs,
                                  os.path.join(config.build_directory, 'terraform.tfvars.json'))


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
        'bucket':
        bucket,
        'acl':
        kwargs.get('acl', 'private'),
        'force_destroy':
        kwargs.get('force_destroy', True),
        'versioning': {
            'enabled': kwargs.get('versioning', True)
        },
        'logging': {
            'target_bucket': logging,
            'target_prefix': f'{bucket}/'
        },
        'server_side_encryption_configuration': {
            'rule': {
                'apply_server_side_encryption_by_default': {
                    'sse_algorithm': sse_algorithm
                }
            }
        },
        'policy':
        json.dumps({
            'Version':
            '2012-10-17',
            'Statement': [{
                'Sid': 'ForceSSLOnlyAccess',
                'Effect': 'Deny',
                'Principal': '*',
                'Action': 's3:*',
                'Resource': [f'arn:aws:s3:::{bucket}/*', f'arn:aws:s3:::{bucket}'],
                'Condition': {
                    'Bool': {
                        'aws:SecureTransport': 'false'
                    }
                }
            }]
        })
    }

    if sse_algorithm == 'aws:kms':
        s3_bucket['server_side_encryption_configuration']['rule'][
            'apply_server_side_encryption_by_default']['kms_master_key_id'] = (
                '${aws_kms_key.server_side_encryption.key_id}')

    if lifecycle_rule := kwargs.get('lifecycle_rule'):
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
    write_vars(config, region=config['global']['account']['region'])

    main_dict = infinitedict()

    logging_bucket, create_logging_bucket = s3_access_logging_bucket(config)

    state_lock_table_name = f"{config['global']['account']['prefix']}_streamalert_terraform_state_lock"

    # Setup the Backend depending on the deployment phase.
    # When first setting up StreamAlert, the Terraform statefile
    # is stored locally.  After the first dependencies are created,
    # this moves to S3.
    if init:
        main_dict['terraform']['backend']['local'] = {
            'path': 'terraform.tfstate',
        }
    else:
        terraform_bucket_name, _ = terraform_state_bucket(config)
        main_dict['terraform']['backend']['s3'] = {
            'bucket':
            terraform_bucket_name,
            'key':
            config['global'].get('terraform', {}).get('state_key_name',
                                                      'streamalert_state/terraform.tfstate'),
            'region':
            config['global']['account']['region'],
            'encrypt':
            True,
            'dynamodb_table':
            state_lock_table_name,
            'acl':
            'private',
            'kms_key_id':
            'alias/{}'.format(config['global']['account'].get(
                'kms_key_alias', f"{config['global']['account']['prefix']}_streamalert_secrets"))
        }

    # Configure initial S3 buckets
    main_dict['resource']['aws_s3_bucket'] = {
        'streamalerts':
        generate_s3_bucket(bucket=firehose_alerts_bucket(config), logging=logging_bucket)
    }

    # Configure remote state locking table
    main_dict['resource']['aws_dynamodb_table'] = {
        'terraform_remote_state_lock': {
            'name': state_lock_table_name,
            'billing_mode': 'PAY_PER_REQUEST',
            'hash_key': 'LockID',
            'attribute': {
                'name': 'LockID',
                'type': 'S'
            },
            'tags': {
                'Name': 'StreamAlert'
            }
        }
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

    terraform_bucket_name, create_state_bucket = terraform_state_bucket(config)
    # Create bucket for Terraform state (if applicable)
    if create_state_bucket:
        main_dict['resource']['aws_s3_bucket']['terraform_remote_state'] = generate_s3_bucket(
            bucket=terraform_bucket_name, logging=logging_bucket)

    # Setup Firehose Delivery Streams
    generate_firehose(logging_bucket, main_dict, config)

    # Configure global resources like Firehose alert delivery and alerts table
    main_dict['module']['globals'] = _generate_global_module(config)

    # KMS Key and Alias creation
    main_dict['resource']['aws_kms_key']['server_side_encryption'] = {
        'enable_key_rotation':
        True,
        'description':
        'StreamAlert S3 Server-Side Encryption',
        'policy':
        json.dumps({
            'Version':
            '2012-10-17',
            'Statement': [{
                'Sid': 'Enable IAM User Permissions',
                'Effect': 'Allow',
                'Principal': {
                    'AWS': f"arn:aws:iam::{config['global']['account']['aws_account_id']}:root"
                },
                'Action': 'kms:*',
                'Resource': '*'
            }, {
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
            }]
        })
    }

    main_dict['resource']['aws_kms_alias']['server_side_encryption'] = {
        'name': f"alias/{config['global']['account']['prefix']}_server-side-encryption",
        'target_key_id': '${aws_kms_key.server_side_encryption.key_id}'
    }

    main_dict['resource']['aws_kms_key']['streamalert_secrets'] = {
        'enable_key_rotation': True,
        'description': 'StreamAlert secret management'
    }
    main_dict['resource']['aws_kms_alias']['streamalert_secrets'] = {
        'name':
        'alias/{}'.format(config['global']['account'].get(
            'kms_key_alias', f"{config['global']['account']['prefix']}_streamalert_secrets")),
        'target_key_id':
        '${aws_kms_key.streamalert_secrets.key_id}'
    }

    # Global infrastructure settings
    topic_name, create_topic = monitoring_topic_name(config)
    if create_topic:
        main_dict['resource']['aws_sns_topic']['monitoring'] = {'name': topic_name}

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

    if modules.get('cloudwatch_monitoring', {}).get('enabled') and not generate_monitoring(
            cluster_name, cluster_dict, config):
        return

    if modules.get('kinesis') and not generate_kinesis_streams(cluster_name, cluster_dict, config):
        return

    if modules.get('kinesis_events') and not generate_kinesis_events(cluster_name, cluster_dict,
                                                                     config):
        return

    if modules.get('cloudtrail') and not generate_cloudtrail(cluster_name, cluster_dict, config):
        return

    # purposely not using .get, since no extra settings are required for this module
    if 'cloudwatch_events' in modules and not generate_cloudwatch_events(
            cluster_name, cluster_dict, config):
        return

    if modules.get('cloudwatch_logs_destination') and not generate_cloudwatch_destinations(
            cluster_name, cluster_dict, config):
        return

    if modules.get('flow_logs') and not generate_flow_logs(cluster_name, cluster_dict, config):
        return

    if modules.get('s3_events') and not generate_s3_events(cluster_name, cluster_dict, config):
        return

    generate_apps(cluster_name, cluster_dict, config)

    return cluster_dict


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

    # Setup the main.tf.json file
    LOGGER.debug('Generating cluster file: main.tf.json')
    _create_terraform_module_file(generate_main(config, init=init),
                                  os.path.join(config.build_directory, 'main.tf.json'))

    # Return early during the init process, clusters are not needed yet
    if init:
        return True

    # Setup cluster files
    for cluster in config.clusters():
        if cluster in RESTRICTED_CLUSTER_NAMES:
            raise InvalidClusterName('Rename cluster "main" or "athena" to something else!')

        LOGGER.debug('Generating cluster file: %s.tf.json', cluster)
        cluster_dict = generate_cluster(config=config, cluster_name=cluster)
        if not cluster_dict:
            LOGGER.error('An error was generated while creating the %s cluster', cluster)
            return False

        file_name = f'{cluster}.tf.json'
        _create_terraform_module_file(
            cluster_dict,
            os.path.join(config.build_directory, file_name),
        )

    if metric_filters := generate_aggregate_cloudwatch_metric_filters(config):
        _create_terraform_module_file(
            metric_filters, os.path.join(config.build_directory, 'metric_filters.tf.json'))

    if metric_alarms := generate_aggregate_cloudwatch_metric_alarms(config):
        _create_terraform_module_file(metric_alarms,
                                      os.path.join(config.build_directory, 'metric_alarms.tf.json'))

    # Setup Threat Intel Downloader Lambda function if it is enabled
    generate_global_lambda_settings(
        config,
        conf_name='threat_intel_downloader_config',
        generate_func=generate_threat_intel_downloader,
        tf_tmp_file_name='ti_downloader',
        required=False,
    )

    # Setup Rule Promotion if it is enabled
    generate_global_lambda_settings(
        config,
        conf_name='rule_promotion_config',
        generate_func=generate_rule_promotion,
        tf_tmp_file_name='rule_promotion',
        required=False,
    )

    # Setup Athena Partitioner
    generate_global_lambda_settings(
        config,
        conf_name='athena_partitioner_config',
        generate_func=generate_athena,
        tf_tmp_file_name='athena',
    )

    # Setup Rules Engine
    generate_global_lambda_settings(
        config,
        conf_name='rules_engine_config',
        generate_func=generate_rules_engine,
        tf_tmp_file_name='rules_engine',
    )

    # Setup Alert Processor
    generate_global_lambda_settings(
        config,
        conf_name='alert_processor_config',
        generate_func=generate_alert_processor,
        tf_tmp_file_name='alert_processor',
    )

    # Setup Alert Merger
    generate_global_lambda_settings(
        config,
        conf_name='alert_merger_config',
        generate_func=generate_alert_merger,
        tf_tmp_file_name='alert_merger',
    )

    # Setup Lookup Tables if applicable
    _generate_lookup_tables_settings(config)

    # Setup StreamQuery
    _generate_streamquery_module(config)

    # FIXME: make sure test 'python manage.py destroy' artifact_extractor case
    # Setup artifact_extractor
    _generate_artifact_extractor_module(config)

    return True


def _generate_lookup_tables_settings(config):
    """
    Generates .tf.json file for LookupTables
    """
    tf_file_name = os.path.join(config.build_directory, 'lookup_tables.tf.json')

    if not config['lookup_tables'].get('enabled', False):
        remove_temp_terraform_file(tf_file_name)
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
        remove_temp_terraform_file(tf_file_name, extra='No tables configured')
        return

    roles = {
        '${module.alert_processor_lambda.role_id}',
        '${module.alert_merger_lambda.role_id}',
        '${module.rules_engine_lambda.role_id}',
        '${module.scheduled_queries.lambda_function_role_id}',
    }

    for cluster in config.clusters():
        roles.add(f'${{module.classifier_{cluster}_lambda.role_id}}')

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


def _generate_streamquery_module(config):
    """
    Generates .tf.json file for scheduled queries
    """
    tf_file_name = os.path.join(config.build_directory, 'scheduled_queries.tf.json')
    if not config.get('scheduled_queries', {}).get('enabled', False):
        remove_temp_terraform_file(tf_file_name)
        return

    _create_terraform_module_file(generate_scheduled_queries_module_configuration(config),
                                  tf_file_name)


def _generate_artifact_extractor_module(config):
    tf_file_name = os.path.join(config.build_directory, 'artifact_extractor.tf.json')
    if 'artifact_extractor' in config['global']['infrastructure']:
        if config['global']['infrastructure']['artifact_extractor'].get('enabled'):
            _create_terraform_module_file(generate_artifact_extractor(config), tf_file_name)
            return

        remove_temp_terraform_file(tf_file_name)


def generate_global_lambda_settings(config,
                                    conf_name,
                                    generate_func,
                                    tf_tmp_file_name,
                                    required=True):
    """Generate settings for global Lambda functions

    Args:
        config (dict): lambda function settings read from 'conf/' directory
        config_name (str): keyname of lambda function settings in config.
        generate_func (func): method to generate lambda function settings.
        tf_tmp_file (str): filename of terraform file, generated by CLI.
        message (str): Message will be logged by LOGGER.
    """
    tf_tmp_file = os.path.join(config.build_directory, f'{tf_tmp_file_name}.tf.json')

    if required and conf_name not in config['lambda']:
        message = f'Required configuration missing in lambda.json: {conf_name}'
        raise ConfigError(message)

    if not config['lambda'].get(conf_name):
        LOGGER.warning('Optional configuration missing in lambda.json, skipping: %s', conf_name)
        remove_temp_terraform_file(tf_tmp_file)
        return

    if config['lambda'][conf_name].get('enabled', True):
        if generated_config := generate_func(config=config):
            _create_terraform_module_file(generated_config, tf_tmp_file)
    else:
        remove_temp_terraform_file(tf_tmp_file)


def remove_temp_terraform_file(tf_tmp_file, extra=None):
    """Remove temporal terraform file

    Args:
        tf_tmp_file (str): filename of terraform file, generated by CLI.
        message (str): Message will be logged by LOGGER.
    """
    if extra:
        LOGGER.info(extra)

    message = f'Removing old Terraform file: {tf_tmp_file}'
    if os.path.isfile(tf_tmp_file):
        LOGGER.info(message)
        os.remove(tf_tmp_file)


def _generate_global_module(config):
    # 2019-08-22 (Ryxias)
    #   In version 3.0.0+, StreamAlert will default to always using the prefix, when "use_prefix"
    #   is not present.
    #
    #   Refer to this PR for more information: https://github.com/airbnb/streamalert/pull/979
    use_prefix = config['global']['infrastructure'].get('classifier_sqs',
                                                        {}).get('use_prefix', True)

    global_module = {
        'source': './modules/tf_globals',
        'account_id': config['global']['account']['aws_account_id'],
        'region': config['global']['account']['region'],
        'prefix': config['global']['account']['prefix'],
        'kms_key_arn': '${aws_kms_key.server_side_encryption.arn}',
        'rules_engine_timeout': config['lambda']['rules_engine_config']['timeout'],
        'sqs_use_prefix': use_prefix,
        'alerts_db_name': get_database_name(config),
        'alerts_file_format': get_data_file_format(config),
        'alerts_schema': generate_alerts_table_schema()
    }

    # The below code applies settings for resources only if the settings are explicitly
    # defined. This is because these resources have defaults defined in the
    # ./modules/tf_globals module. This will allow for overriding these setting, but
    # avoids storing defaults in mulitple locations
    if 'alerts_table' in config['global']['infrastructure']:
        for setting in {'read_capacity', 'write_capacity'}:
            if value := config['global']['infrastructure']['alerts_table'].get(setting):
                global_module[f'alerts_table_{setting}'] = value

    alert_fh_settings_with_defaults = {
        'bucket_name', 'buffer_size', 'buffer_interval', 'cloudwatch_log_retention'
    }

    if 'alerts_firehose' in config['global']['infrastructure']:
        for setting in alert_fh_settings_with_defaults:
            if value := config['global']['infrastructure']['alerts_firehose'].get(setting):
                global_module[f'alerts_firehose_{setting}'] = value

    if 'rule_staging' in config['global']['infrastructure'] and config['global']['infrastructure'][
            'rule_staging'].get('enabled'):
        global_module['enable_rule_staging'] = True
        for setting in {'table_read_capacity', 'table_write_capacity'}:
            if value := config['global']['infrastructure']['rule_staging'].get(setting):
                # Defaults are set for this in the terraform module, so skip
                global_module[f'rules_{setting}'] = value

    return global_module


def _create_terraform_module_file(generated_config, filename):
    """
    Dumps the given generated_config, a JSON dict, into the given filename under the terraform/
    directory, as a .tf.json file.
    """
    with open(filename, 'w', encoding="utf-8") as file:
        json.dump(generated_config, file, indent=2, sort_keys=True)

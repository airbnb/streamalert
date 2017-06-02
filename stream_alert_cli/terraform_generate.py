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
    main_dict['prodiver']['aws'] = {}

    # Configure Terraform version requirement
    main_dict['terraform']['required_version'] = '> 0.9.0'

    # Setup the Backend
    if init:
        main_dict['terraform']['backend']['local'] = {
            'path': 'terraform/terraform.tfstate'
        }
    else:
        main_dict['terraform']['backend']['s3'] = {
            'bucket': '{}.streamalert.terraform.state'.format(config['account']['prefix']),
            'key': 'stream_alert_state/terraform.tfstate',
            'region': 'us-east-1',
            'encrypt': True,
            'acl': 'private',
            'kms_key_id': 'alias/stream_alert_secrets'
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
        'name': 'alias/stream_alert_secrets',
        'target_key_id': '${aws_kms_key.stream_alert_secrets.key_id}'
    }

    return main_dict

def generate_cluster():
    pass

def terraform_generate(**kwargs):
    """Generate all Terraform plans for the clusters in variables.json"""
    LOGGER_CLI.info('Generating Terraform files')
    config = kwargs.get('config')
    init = kwargs.get('init', False)

    # Setup main.tf
    main_json = json.dumps(
        generate_main(init=init, config=config),
        indent=4)
    with open('terraform/main.tf', 'w') as tf_file:
        tf_file.write(main_json)

    # # Setup cluster Terraform files
    # for cluster in CONFIG['clusters'].keys():
    #     if cluster == 'main':
    #         raise InvalidClusterName('Rename cluster "main" to something else!')
    # 
    #     with open('terraform/{}.tf'.format(cluster), 'w') as tf_file:
    #         tf_file.write(contents)

    return True

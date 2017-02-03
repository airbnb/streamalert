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
import logging

import boto3

class LambdaVersion(object):
    """
    Publish versions of the StreamAlert Lambda function.

    There are two environments, staging and production.  They are configured
    as Lambda alises, which are pointers to certain published versions
    of code.  Versions can be either: the most recently uploaded code,
    which is represented as $LATEST, or a published version (0, 1, 2, etc).

    Staging always points to $LATEST, and production always points to a
    published version.  These are both defined in `variables.json`.

    The goal of this class is to publish production Lambda versions.
    """
    def __init__(self, config):
        self.config = config

    def publish_function(self):
        logging.info('Publishing New Function Version')
        new_versions = {}

        for cluster, region in self.config['clusters'].iteritems():
            client = boto3.client('lambda',region_name=region)
            functionName = '{}_{}_stream_alert_processor'.format(
                            self.config['prefix'], cluster)
            logging.info('Publishing %s', functionName)
            response = client.publish_version(
                FunctionName=functionName,
                CodeSha256=self.config['lambda_source_current_hash'],
                Description='publish new version of lambda function'
            )
            version = response['Version']
            new_versions[cluster] = int(version)
            logging.info('Published version %s for %s cluster', version, cluster)
        self._update_config(new_versions)

    @staticmethod
    def _update_config(new_versions):
        vers_key = 'lambda_function_prod_versions'
        with open('variables.json', 'r+') as varfile:
            config = json.load(varfile)
            for cluster, new_version in new_versions.iteritems():
                config[vers_key][cluster] = new_version
            config_out = json.dumps(
                config,
                indent=4,
                separators=(',', ': '),
                sort_keys=True
            )
            varfile.seek(0)
            varfile.write(config_out)
            varfile.truncate()

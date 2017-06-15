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

from datetime import datetime

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

    def __init__(self, **kwargs):
        self.config = kwargs['config']
        self.package = kwargs['package']

    def publish_function(self):
        logging.info('Publishing New Function Version')
        date = datetime.utcnow().strftime("%Y%m%d_T%H%M%S")
        new_versions = {}

        for cluster in self.config.clusters():
            region = self.config['clusters'][cluster]['region']
            client = boto3.client('lambda', region_name=region)
            function_name = '{}_{}_streamalert_{}'.format(
                self.config['global']['account']['prefix'],
                cluster,
                self.package.package_name
            )
            logging.info('Publishing %s', function_name)
            response = client.publish_version(
                FunctionName=function_name,
                CodeSha256=self.config['lambda'][self.package.config_key]['source_current_hash'],
                Description='Publish Lambda {} on {}'.format(function_name, date)
            )
            version = response['Version']
            new_versions[cluster] = int(version)
            logging.info('Published version %s for %s:%s',
                         version, cluster, function_name)

        for cluster, new_version in new_versions.iteritems():
            self.config['clusters'][cluster]['modules']['stream_alert'][self.package.package_name]['current_version'] = new_version
        self.config.write()

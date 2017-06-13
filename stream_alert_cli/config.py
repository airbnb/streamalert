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
import os

from collections import defaultdict

class ConfigError(Exception):
    """Generic config exception for a non existent/invalid config files"""
    pass


class CLIConfig(object):
    '''Provide an object to load, modify, and display the StreamAlertCLI Config'''
    def __init__(self):
        self.config = self.load()

    def __repr__(self):
        return json.dumps(self.config)

    def __getitem__(self, key):
        return self.config[key]

    def __setitem__(self, key, new_value):
        self.config.__setitem__(key, new_value)
        self.write()

    def get(self, key):
        return self.config.get(key)

    def clusters(self):
        return self.config['clusters'].keys()

    def load(self):
        """Load the cluster, global, and lambda configuration files

        Returns:
            [dict] loaded config from all config files with the following keys:
                'clusters', 'global', and 'lambda'
        """
        config_files = {
            'global': 'conf/global.json',
            'lambda': 'conf/lambda.json'
        }
        config = {}
        config['clusters'] = {}

        def _config_loader(key, filepath, cluster_file):
            if not os.path.isfile(filepath):
                raise ConfigError('StreamAlert {} file not found!'.format(filepath))

            with open(filepath) as data:
                try:
                    if cluster_file:
                        config['clusters'][key] = json.load(data)
                    else:
                        config[key] = json.load(data)
                except ValueError:
                    raise ConfigError('StreamAlert {} file is not valid JSON!'.format(filepath))

        # Load individual files
        for key, filepath in config_files.iteritems():
            _config_loader(key, filepath, False)

        # Load cluster files
        for cluster_file in os.listdir('conf/clusters'):
            key = os.path.splitext(cluster_file)[0]
            _config_loader(key, 'conf/clusters/{}'.format(cluster_file), True)

        return config

    def write(self):
        """Write the current config in memory to disk"""
        with open(self.filename, 'r+') as varfile:
            varfile.write(json.dumps(
                self.config,
                indent=4,
                separators=(',', ': '),
                sort_keys=True
            ))
            varfile.truncate()

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

from collections import OrderedDict

OUTPUTS_CONFIG = 'outputs.json'

def load_outputs_config(conf_dir='conf'):
    """Load the outputs configuration file from disk

    Args:
        conf_dir [string='conf']: directory to read outputs config from

    Returns:
        [dict] the outputs config settings
    """
    with open(os.path.join(conf_dir, OUTPUTS_CONFIG)) as outputs:
        try:
            values = json.load(outputs, object_pairs_hook=OrderedDict)
        except ValueError as err:
            raise err

    return values

def write_outputs_config(data, conf_dir='conf'):
    """Write the outputs configuration file back to disk

    Args:
        data [dict]: dictionary to be converted to json and written to disk
        conf_dir [string='conf']: directory to write outputs config to
    """
    with open(os.path.join(conf_dir, OUTPUTS_CONFIG), 'w') as outputs:
        outputs.write(json.dumps(
            data,
            indent=4,
            separators=(',', ': '),
            sort_keys=True
        ))

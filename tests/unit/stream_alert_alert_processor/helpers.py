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
from collections import OrderedDict
import os
import random
import shutil
import tempfile

from mock import Mock

from tests.unit.stream_alert_alert_processor import FUNCTION_NAME, REGION


def get_mock_context():
    """Create a fake context object using Mock"""
    arn = 'arn:aws:lambda:{}:555555555555:function:{}:production'
    context = Mock(invoked_function_arn=(arn.format(REGION, FUNCTION_NAME)),
                   function_name='corp-prefix_prod_streamalert_alert_processor')

    return context


def get_random_alert(key_count, rule_name, omit_rule_desc=False):
    """This loop generates key/value pairs with a key of length 6 and
        value of length 148. when formatted, each line should consume
        160 characters, account for newline and asterisk for bold.

        For example:
        '*000001:* 6D829150B0154BF9BAC733FD25C61FA3D8CD3868AC2A92F19EEE119B
        9CE8D6094966AA7592CE371002F1F7D82617673FCC9A9DB2A8F432AA791D74AB80BBCAD9\n'

        Therefore, 25*160 = 4000 character message size (exactly the 4000 limit)
        Anything over 4000 characters will result in multi-part slack messages:
        55*160 = 8800 & 8800/4000 = ceil(2.2) = 3 messages needed
    """
    values = OrderedDict([('{:06}'.format(key),
                           '{:0148X}'.format(random.randrange(16**128)))
                          for key in range(key_count)])

    # This default value is set in the rule processor's rules_engine.py
    rule_description = 'No rule description provided' if omit_rule_desc else 'rule test description'
    alert = {
        'record': values,
        'rule_name': rule_name,
        'rule_description': rule_description
    }

    return alert


def get_alert(context=None):
    """This function generates a sample alert for testing purposes

    Args:
        index (int): test_index value (0 by default)
        context(dict): context dictionary (None by default)
    """
    return {
        'record': {
            'compressed_size': '9982',
            'timestamp': '1496947381.18',
            'node_id': '1',
            'cb_server': 'cbserver',
            'size': '21504',
            'type': 'binarystore.file.added',
            'file_path': '/tmp/5DA/AD8/0F9AA55DA3BDE84B35656AD8911A22E1.zip',
            'md5': '0F9AA55DA3BDE84B35656AD8911A22E1'
        },
        'log_source': 'carbonblack:binarystore.file.added',
        'rule_name': 'cb_binarystore_file_added',
        'outputs': [
            'slack:unit_test_channel'
        ],
        'context': context or dict(),
        'source_service': 's3',
        'source_entity': 'corp-prefix.prod.cb.region',
        'log_type': 'json',
        'rule_description': 'Info about this rule and what actions to take'
    }


def remove_temp_secrets():
    """Remove the local secrets directory that may be left from previous runs"""
    secrets_dirtemp_dir = os.path.join(tempfile.gettempdir(), 'stream_alert_secrets')

    # Check if the folder exists, and remove it if it does
    if os.path.isdir(secrets_dirtemp_dir):
        shutil.rmtree(secrets_dirtemp_dir)

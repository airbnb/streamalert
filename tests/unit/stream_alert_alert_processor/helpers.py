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
import os
import random
import shutil
import tempfile

from stream_alert.shared.alert import Alert


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
    # This default value is set in the rule processor's rules_engine.py
    rule_description = 'No rule description provided' if omit_rule_desc else 'rule test description'

    return Alert(
        rule_name,
        {
            '{:06}'.format(key): '{:0148X}'.format(random.randrange(16**128))
            for key in range(key_count)
        },
        {'slack:unit_test_channel'},
        rule_description=rule_description
    )


def get_alert(context=None):
    """This function generates a sample alert for testing purposes

    Args:
        context (dict): Optional alert context
    """
    return Alert(
        'cb_binarystore_file_added',
        {
            'compressed_size': '9982',
            'timestamp': '1496947381.18',
            'node_id': '1',
            'cb_server': 'cbserver',
            'size': '21504',
            'type': 'binarystore.file.added',
            'file_path': '/tmp/5DA/AD8/0F9AA55DA3BDE84B35656AD8911A22E1.zip',
            'md5': '0F9AA55DA3BDE84B35656AD8911A22E1'
        },
        {'slack:unit_test_channel'},
        alert_id='79192344-4a6d-4850-8d06-9c3fef1060a4',
        context=context,
        log_source='carbonblack:binarystore.file.added',
        log_type='json',
        rule_description='Info about this rule and what actions to take',
        source_entity='corp-prefix.prod.cb.region',
        source_service='s3'
    )


def remove_temp_secrets():
    """Remove the local secrets directory that may be left from previous runs"""
    secrets_dirtemp_dir = os.path.join(tempfile.gettempdir(), 'stream_alert_secrets')

    # Check if the folder exists, and remove it if it does
    if os.path.isdir(secrets_dirtemp_dir):
        shutil.rmtree(secrets_dirtemp_dir)

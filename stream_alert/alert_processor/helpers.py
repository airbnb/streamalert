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
import logging

logging.basicConfig()
LOGGER = logging.getLogger('StreamAlertOutput')
LOGGER.setLevel(logging.DEBUG)

def validate_alert(alert):
    """Helper function to perform simple validatation of an alert's keys and structure

    Args:
        alert [dict]: the alert record to test that should be in the form of a dict

    Returns:
        [bool] a boolean value indicating whether or not the alert has the proper structure
    """
    if not _validate_root(alert):
        return False

    metadata_keys = {'log', 'rule_name', 'rule_description', 'type', 'source', 'outputs'}
    if not set(alert['metadata'].keys()) == metadata_keys:
        LOGGER.error('The value of the \'metadata\' key must be a map (dict) '
                     'that contains the following keys: %s',
                     ', '.join('\'{}\''.format(key) for key in metadata_keys))
        return False

    valid = True
    for key in metadata_keys:
        if key == 'source':
            if not (isinstance(alert['metadata'][key], dict) and
                    set(alert['metadata'][key].keys()) == {'service', 'entity'}):
                LOGGER.error('The value of the \'source\' key must be a map (dict) that '
                             'contains \'service\' and \'entity\' keys.')
                valid = False
                continue

            for entry in alert['metadata'][key].values():
                if not isinstance(entry, (str, unicode)):
                    LOGGER.error('The value of the \'%s\' key within \'%s\' must be '
                                 'a string (str).', entry, key)
                    valid = False
                    continue

        elif key == 'outputs':
            if not (isinstance(alert['metadata'][key], list) and
                    alert['metadata'][key]):
                LOGGER.error(
                    'The value of the \'outputs\' key must be an array (list) that '
                    'contains at least one configured output.')
                valid = False
                continue

            for entry in alert['metadata'][key]:
                if not isinstance(entry, (str, unicode)):
                    LOGGER.error('The value of each entry in the \'outputs\' list '
                                 'must be a string (str).')
                    valid = False
                    continue

        elif not isinstance(alert['metadata'][key], (str, unicode)):
            LOGGER.error('The value of the \'%s\' key must be a string (str), not %s',
                         key, type(alert['metadata'][key]))
            valid = False
            continue

    return valid

def _validate_root(alert):
    """Private helper function to validate the root keys on an alert

    Args:
        alert [dict]: the alert record to test that should be in the form of a dict

    Returns:
        [bool] a boolean value indicating whether or not the expected root keys in
            the alert exist and have the proper values
    """
    if not (isinstance(alert, dict) and
            set(alert.keys()) == {'record', 'metadata'}):
        LOGGER.error('The alert must be a map (dict) that contains \'record\' '
                     'and \'metadata\' keys.')
        return False

    if not (isinstance(alert['record'], dict) and
            isinstance(alert['metadata'], dict)):
        LOGGER.error('The value of both the \'record\' and \'metadata\' keys '
                     'must be a map (dict).')
        return False

    return True

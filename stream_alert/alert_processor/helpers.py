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
from stream_alert.alert_processor import LOGGER


def validate_alert(alert):
    """Helper function to perform simple validation of an alert's keys and structure

    Args:
        alert (dict): the alert record to test that should be in the form of a dict

    Returns:
        bool: whether or not the alert has the proper structure
    """

    if not isinstance(alert, dict):
        LOGGER.error('The alert must be a map (dict)')
        return False

    alert_keys = {
        'record',
        'rule_name',
        'rule_description',
        'log_type',
        'log_source',
        'outputs',
        'source_service',
        'source_entity',
        'context'
    }
    if not set(alert.keys()) == alert_keys:
        LOGGER.error('The alert object must contain the following keys: %s',
                     ', '.join(alert_keys))
        return False

    valid = True

    for key in alert_keys:
        if key == 'record':
            if not isinstance(alert['record'], dict):
                LOGGER.error('The alert record must be a map (dict)')
                return False

        elif key == 'context':
            if not isinstance(alert['context'], dict):
                LOGGER.error('The alert context must be a map (dict)')
                return False

        elif key == 'outputs':
            if not isinstance(alert[key], list):
                LOGGER.error(
                    'The value of the \'outputs\' key must be an array (list) that '
                    'contains at least one configured output.')
                valid = False
                continue

            for entry in alert[key]:
                if not isinstance(entry, (str, unicode)):
                    LOGGER.error('The value of each entry in the \'outputs\' list '
                                 'must be a string (str).')
                    valid = False

        elif not isinstance(alert[key], (str, unicode)):
            LOGGER.error('The value of the \'%s\' key must be a string (str), not %s',
                         key, type(alert[key]))
            valid = False

    return valid

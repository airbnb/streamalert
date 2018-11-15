#! /usr/bin/env python
"""Script to sort conf/logs.json schema file"""
import json
import os
import logging

from collections import OrderedDict

SCRIPT_NAME = 'JsonFileSorter'
CONF_LOGS_FILE = os.path.join(os.path.dirname(__file__), '../../conf/logs.json')


class JsonFileSorter(object):
    """
    Tests that the conf.json file is formatted properly and is sorted alphabetically
    on the top-level key
    """

    def __init__(self):
        self._logger = logging.getLogger(SCRIPT_NAME)

    def sort_json_file(self, file_path):
        self._logger.info('Sorting file: {}...'.format(file_path))

        with open(file_path, 'r') as infile:
            original_text = infile.read().strip()

        # Load the JSON document using OrderedDict so that it preserves original ordering
        schema = json.loads(original_text, object_pairs_hook=OrderedDict)

        ordered_schema = OrderedDict(sorted(schema.items(), key=lambda k: k[0]))

        with open(file_path, 'w') as outfile:
            json.dump(ordered_schema, outfile, indent=2, separators=(',', ': '))
            outfile.write('\n')

        self._logger.info('Sorting completed.')


if __name__ == "__main__":
    sorter = JsonFileSorter()
    sorter.sort_json_file(CONF_LOGS_FILE)

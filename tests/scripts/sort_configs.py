#! /usr/bin/env python
"""Script to sort conf/logs.json schema file"""
import json
import logging
import os
from collections import OrderedDict

CONF_LOGS_FILE = os.path.join(os.path.dirname(__file__), '../../conf/logs.json')


class JsonFileSorter:
    """
    Tests that the conf.json file is formatted properly and is sorted alphabetically
    on the top-level key
    """

    def __init__(self):
        self._logger = logging.getLogger()

    def sort_json_file(self, file_path):
        self._logger.info(f'Sorting file: {file_path}...')

        with open(file_path) as infile:
            original_text = infile.read().strip()

        # Load the JSON document using OrderedDict, as it allows us to preserve the ordering
        # of the internal json keys. This is important for certain schemas, such as ones parsed
        # via csv, as the ordering of the keys does matter.
        schema = json.loads(original_text, object_pairs_hook=OrderedDict)

        # Sort the loaded schema by top-level key. Preserve the ordering of internal keys.
        ordered_schema = OrderedDict(sorted(list(schema.items()), key=lambda k: k[0]))

        with open(file_path, 'w') as outfile:
            json.dump(ordered_schema, outfile, indent=2, separators=(',', ': '))
            outfile.write('\n')

        self._logger.info('Sorting completed.')


if __name__ == "__main__":
    sorter = JsonFileSorter()
    sorter.sort_json_file(CONF_LOGS_FILE)

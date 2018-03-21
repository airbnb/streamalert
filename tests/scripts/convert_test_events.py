#! /usr/bin/env python

# This script should be used as a one-off to convert all rule test events
# from the legacy format to the new test format

import json
import os

TEST_FILES_PATH = 'tests/integration/rules'


def convert_test_event(file):
    with open(file, 'r+') as test_event:
        # Load the file, handle bad JSON
        try:
            data = json.load(test_event)
        except ValueError as err:
            print '[ERROR] {}: {}'.format(os.path.basename(file), err)
            return
        # Convert legacy test events
        if isinstance(data, dict) and 'records' in data:
            test_event.seek(0)
            test_event.truncate()
            json.dump(
                data['records'], test_event, indent=2, separators=(',', ':'), sort_keys=True)

def convert():
    for root, dirs, files in os.walk(TEST_FILES_PATH):
        for file in files:
            convert_test_event(os.path.join(root, file))


if __name__ == "__main__":
    convert()

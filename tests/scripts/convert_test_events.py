#! /usr/bin/env python
"""One-off script to convert all rule test events from the legacy format to the new test format."""
import json
import os

TEST_FILES_PATH = 'tests/integration/rules'


def convert_test_event(path):
    with open(path, 'r+') as test_event:
        # Load the file, handle bad JSON
        try:
            data = json.load(test_event)
        except ValueError as err:
            print '[ERROR] {}: {}'.format(os.path.basename(path), err)
            return
        # Convert legacy test events
        if isinstance(data, dict) and 'records' in data:
            test_event.seek(0)
            test_event.truncate()
            json.dump(
                data['records'], test_event, indent=2, separators=(',', ':'), sort_keys=True)


def convert():
    for root, _, files in os.walk(TEST_FILES_PATH):
        for file_name in files:
            convert_test_event(os.path.join(root, file_name))


if __name__ == "__main__":
    convert()

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
from collections import deque, OrderedDict
import re
from stream_alert.shared.publisher import Register
from stream_alert.shared.normalize import Normalizer
from stream_alert.shared.utils import get_keys


@Register
def add_record(alert, publication):
    """Publisher that adds the alert.record to the publication."""
    publication['record'] = alert.record

    return publication


@Register
def blank(*_):
    """Erases all fields on existing publications and returns a blank dict"""
    return {}


@Register
def remove_internal_fields(_, publication):
    """This publisher removes fields from DefaultPublisher that are only useful internally"""

    publication.pop('staged', None)
    publication.pop('publishers', None)
    publication.pop('outputs', None)

    return publication


def _delete_dictionary_fields(publication, regexp):
    """Deeply destroys all nested dict keys matching the given regexp string

    Args:
        publication (dict): A publication
        regexp (str): A String that is valid regexp

    Returns:
        dict
        (!) warning, will modify the original publication
    """
    # Python is bad at recursion so I managed to tip toe around that with BFS using a queue.
    # This heavily takes advantage of internal references being maintained properly as the loop
    # does not actually track the "current scope" of the next_item.
    fringe = deque()
    fringe.append(publication)
    while len(fringe) > 0:
        next_item = fringe.popleft()

        if isinstance(next_item, dict):
            for key in next_item.keys():
                if re.search(regexp, key):
                    next_item.pop(key, None)

            for key, item in next_item.iteritems():
                fringe.append(item)
        elif isinstance(next_item, list):
            fringe.extend(next_item)
        else:
            # It's a leaf node, or it's some strange object that doesn't belong here
            pass

    return publication


@Register
def remove_fields(alert, publication):
    """This publisher deletes fields from the current publication.

    The publisher uses the alert's context to determine which fields to delete. Example:

    context={
      'remove_fields': ['^field1$', '^field2$', ...]
    }

    "remove_fields" should be an array of strings that are valid regular expressions.

    The algorithm deeply searches the publication for any dict key that matches the given regular
    expression. Any such key is removed, and if the value is a nested dict, the entire dict
    branch underneath is removed.
    """
    fields = alert.context.get('remove_fields', [])

    for field in fields:
        publication = _delete_dictionary_fields(publication, field)

    return publication


@Register
def remove_streamalert_normalization(_, publication):
    """This publisher removes the super heavyweight 'streamalert:normalization' fields"""
    return _delete_dictionary_fields(publication, Normalizer.NORMALIZATION_KEY)


@Register
def enumerate_fields(_, publication):
    """Flattens all currently published fields.

    By default, publications are deeply nested dict structures. This can be very hard to read
    when rendered in certain outputs. PagerDuty is one example where the default UI does a very
    poor job rendering nested dicts.

    This publisher collapses deeply nested fields into a single-leveled dict with keys that
    correspond to the original path of each value in a deeply nested dict. For example:

    {
      "top1": {
        "mid1": "low",
        "mid2": [ "low1", "low2", "low3" ],
        "mid3": {
          "low1": "verylow"
        }
      },
      "top2": "mid"
    }

    .. would collapse into the following structure:

    {
      "top1.mid1": "low",
      "top1.mid2[0]": "low1",
      "top1.mid2[1]": "low1",
      "top1.mid2[2]": "low1",
      "top1.mid3.low1: "verylow",
      "top2": "mid"
    }

    The output dict is an OrderedDict with keys sorted in alphabetical order.
    """
    def _recursive_enumerate_fields(structure, output_reference, path=''):
        if isinstance(structure, list):
            for index, item in enumerate(structure):
                _recursive_enumerate_fields(item, output_reference, '{}[{}]'.format(path, index))

        elif isinstance(structure, dict):
            for key in structure:
                _recursive_enumerate_fields(structure[key], output_reference, '{prefix}{key}'.format(
                    prefix='{}.'.format(path) if path else '',  # Omit first period
                    key=key
                ))

        else:
            output_reference[path] = structure

    output = {}
    _recursive_enumerate_fields(publication, output)

    return OrderedDict(sorted(output.items()))


@Register
def bubble_fields(alert, publication):
    """This publisher bubbles all requested fields to the top level and deletes everything else.

    It uses the context to determine which fields to keep. Example:

    context={
      'bubble_fields': [ 'field1', 'field2', 'field3' ]
    }

    "bubble_fields" should be an array of strings that are exact matches to the field names.

    The algorithm deeply searches the publication for any dict key that exactly matches one of the
    given fields. It then takes the contents of that field and bubbles them up to the top level.
    It discovers ALL values matching each field, so if a field is returned multiple times, the
    resulting top level field will be an array. In the special case where exactly one entry is
    returned for a bubble_field, the value will instead be equal to that value (instead of an
    array with 1 element being that value). In the special case when no entries are returned for
    an extract_field, the value will be None.

    Aside from the bubbled fields, this publisher throws away everything else in the original
    publication.

    NOTE: It is possible for bubbled fields to continue to contain nested dicts, so do not assume
          this publisher will result in a flat dictionary publication.
    """

    new_publication = {}
    for bubble_field in alert.context.get('bubble_fields', []):
        extractions = get_keys(publication, bubble_field)

        if len(extractions) > 1:
            value = extractions
        elif len(extractions) == 1:
            value = extractions[0]
        else:
            value = None

        new_publication[bubble_field] = value

    return new_publication

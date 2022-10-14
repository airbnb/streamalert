"""
Copyright 2017-present Airbnb, Inc.

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
import re
from collections import OrderedDict, deque

from streamalert.shared.normalize import Normalizer
from streamalert.shared.publisher import AlertPublisher, Register
from streamalert.shared.utils import get_keys


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
            # work on a copy of the keys to avoid modifying the dict while iterating over it
            for key in list(next_item.keys()):
                if re.search(regexp, key):
                    next_item.pop(key, None)

            for key, item in next_item.items():
                fringe.append(item)
        elif isinstance(next_item, list):
            fringe.extend(next_item)
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
    """This publisher removes the super heavyweight 'streamalert_normalization' fields"""
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
                _recursive_enumerate_fields(item, output_reference, f'{path}[{index}]')

        elif isinstance(structure, dict):
            for key in structure:
                _recursive_enumerate_fields(
                    structure[key],
                    output_reference,
                    '{prefix}{key}'.format(
                        prefix=f'{path}.' if path else '',  # Omit first period
                        key=key))

        else:
            output_reference[path] = structure

    output = {}
    _recursive_enumerate_fields(publication, output)

    return OrderedDict(sorted(output.items()))


@Register
def populate_fields(alert, publication):
    """This publisher moves all requested fields to the top level and ignores everything else.

    It uses the context to determine which fields to keep. Example:

    context={
      'populate_fields': [ 'field1', 'field2', 'field3' ]
    }

    "populate_fields" should be an array of strings that are exact matches to the field names.

    The algorithm deeply searches the publication for any dict key that exactly matches one of the
    given fields. It then takes the contents of that field and moves them up to the top level.
    It discovers ALL values matching each field, so if a field is returned multiple times, the
    resulting top level field will be an array. In the special case where exactly one entry is
    returned for a populate_field, the value will instead be equal to that value (instead of an
    array with 1 element being that value). In the special case when no entries are returned for
    an extract_field, the value will be None.

    Aside from the moved fields, this publisher throws away everything else in the original
    publication.

    NOTE: It is possible for moved fields to continue to contain nested dicts, so do not assume
          this publisher will result in a flat dictionary publication.
    """

    new_publication = {}
    for populate_field in alert.context.get('populate_fields', []):
        extractions = get_keys(publication, populate_field)
        new_publication[populate_field] = extractions

    return new_publication


@Register
class StringifyArrays(AlertPublisher):
    """Deeply navigates a dict publication and coverts all scalar arrays to strings

    Any array discovered with only scalar values will be joined into a single string with the
    given DELIMITER. Subclass implementations of this can override the delimiter to join the
    string differently.
    """
    DELIMITER = '\n'

    def publish(self, alert, publication):
        fringe = deque()
        fringe.append(publication)
        while len(fringe) > 0:
            next_item = fringe.popleft()

            if isinstance(next_item, dict):
                # Check all keys
                for key, item in next_item.items():
                    if self.is_scalar_array(item):
                        next_item[key] = self.stringify(item)
                    else:
                        fringe.append(item)

            elif isinstance(next_item, list):
                # At this point, if the item is a list we assert that it is not a SCALAR array;
                # because it is too late to stringify it, since we do not have a back reference
                # to the object that contains it
                fringe.extend(next_item)
        return publication

    @staticmethod
    def is_scalar_array(item):
        """Returns if the given item is a python list containing only scalar elements

        NOTE: This method assumes that the 'item' provided comes from a valid JSON compliant dict.
              It does not account for strange or complicated types, such as references to functions
              or class definitions or other stuff.

        Args:
            item (mixed): The python variable to check

        Returns:
            bool
        """
        return not any(isinstance(element, (dict, list))
                       for element in item) if isinstance(item, list) else False

    @classmethod
    def stringify(cls, array):
        """Given a list of elements, will join them together with the publisher's DELIMITER

        Args:
            array (list): The array of elements.

        Returns:
            str
        """
        return cls.DELIMITER.join([str(elem) for elem in array])

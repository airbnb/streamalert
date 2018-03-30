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


def elide_string_middle(text, max_length):
    """Replace the middle of the text with ellipses to shorten text to the desired length.

    Args:
        text (str): Text to shorten.
        max_length (int): Maximum allowable length of the string.

    Returns:
        (str) The elided text, e.g. "Some really long tex ... the end."
    """
    if len(text) <= max_length:
        return text

    half_len = (max_length - 5) / 2  # Length of text on either side.
    return '{} ... {}'.format(text[:half_len], text[-half_len:])

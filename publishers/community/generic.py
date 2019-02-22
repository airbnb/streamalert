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
from stream_alert.shared.publisher import Register


@Register
def add_record(alert, publication):
    """Publisher that adds the alert.record to the publication."""
    publication['record'] = alert.record

    return publication


@Register
def blank(_, __):
    """Erases all fields on existing publications and returns a blank dict"""
    return {}


@Register
def remove_internal_fields(_, publication):
    """This publisher removes fields from DefaultPublisher that are only useful internally"""

    publication.pop('staged', None)
    publication.pop('publishers', None)
    publication.pop('outputs', None)

    return publication

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

# How to map log schema types to Athena/Hive types
SCHEMA_TYPE_MAPPING = {
    'string': 'string',
    'integer': 'bigint',
    'boolean': 'boolean',
    'float': 'decimal(10,3)',
    dict: 'map<string, string>',
    list: 'array<string>'
}


def to_athena_schema(log_schema):
    """Convert streamalert log schema to athena schema

    Args:
        log_schema (dict): StreamAlert log schema object.

    Returns:
        athena_schema (dict): Equivalent Athena schema used for generating create table statement
    """

    athena_schema = {}

    for key_name, key_type in log_schema.iteritems():
        key_name = '`{}`'.format(key_name)
        if key_type == {}:
            # For empty dicts
            athena_schema[key_name] = SCHEMA_TYPE_MAPPING[dict]
        elif key_type == []:
            # For empty array
            athena_schema[key_name] = SCHEMA_TYPE_MAPPING[list]
        elif isinstance(key_type, dict):
            # For recursion
            athena_schema[key_name] = to_athena_schema(key_type)
        else:
            athena_schema[key_name] = SCHEMA_TYPE_MAPPING[key_type]

    return athena_schema

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
import re

PARTITION_PARTS = re.compile(r'dt=(?P<year>\d{4})\-'
                             r'(?P<month>\d{2})\-'
                             r'(?P<day>\d{2})\-'
                             r'(?P<hour>\d{2})')


def unique_values_from_query(query_result):
    """Simplify Athena query results into a set of values.

    Useful for listing tables, partitions, databases, enable_metrics

    Args:
        query_result (dict): The result of run_athena_query

    Returns:
        set: Unique values from the query result"""
    return {
        res
        for row in query_result['ResultSet']['Rows'] for result in row['Data']
        for res in result.values()
    }


def partition_statement(partitions, bucket, table_name):
    """Generate ALTER TABLE commands from existing partitions.

    Args:
        partitions (set): The unique set of partitions gathered from Athena
        bucket (str): The bucket name
        table_name (str): The name of the Athena table

    Returns:
        str: The ALTER TABLE statement to add the new partitions
    """
    statement = 'ALTER TABLE {} ADD IF NOT EXISTS '.format(table_name)

    for partition in sorted(partitions):
        parts = PARTITION_PARTS.match(partition)
        if not parts:
            continue

        # The returned partition from the SHOW PARTITIONS command is dt=YYYY-MM-DD-HH,
        # But when re-creating new partitions this value must be quoted
        statement += ('PARTITION ({partition}) '
                      'LOCATION \'s3://{bucket}/{table_name}/{year}/{month}/{day}/{hour}\' '.format(
                          partition='dt = \'{}-{}-{}-{}\''.format(
                              parts.group('year'),
                              parts.group('month'),
                              parts.group('day'),
                              parts.group('hour')),
                          bucket=bucket,
                          table_name=table_name,
                          year=parts.group('year'),
                          month=parts.group('month'),
                          day=parts.group('day'),
                          hour=parts.group('hour')))

    return statement

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
from streamalert.scheduled_queries.query_packs.configuration import \
    QueryPackConfiguration

QueryPackConfiguration(
    name='athena_any_query',
    description='This query returns all Athena queries... how meta!',

    # Make sure to edit the database name properly or this query will error with some
    # "insufficient privileges errors"
    query="""
SELECT
  eventtime,
  json_extract(requestparameters['queryexecutioncontext'], '$.database') as database_name,
  requestparameters['querystring'] as querystring,
  useridentity['type'] as user_identity_type,
  useridentity['arn'] as user_identity_arn,
  dt
FROM
  "ATHENA_DATABASE_NAME"."cloudwatch_cloudtrail"
WHERE
  dt = '{utcdatehour_minus1hour}'

  -- Only Events from Athena
  AND eventsource = 'athena.amazonaws.com'
  AND eventname = 'StartQueryExecution'

  -- Only on the CSIRT Prod account
  AND recipientaccountid = '123456789012'

  -- Filter out noisy ALTER and SHOW queries. SHOW queries are commonly run in automation
  -- by API clients, and ALTER queries are run commonly by the Athena partition function.
  AND upper(substr(requestparameters['querystring'], 1, 5)) NOT IN ('ALTER', 'SHOW ')
""",
    params=['utcdatehour_minus1hour'],
    tags=['sample'])

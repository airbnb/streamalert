from streamalert.streamquery.query_packs.configuration import QueryPackConfiguration

QueryPackConfiguration(
    name='athena_any_query',
    description='This query returns all Athena queries... how meta!',
    handler='athena:csirt',
    query="""
SELECT
  eventtime,
  json_extract(requestparameters['queryexecutioncontext'], '$.database') as database_name,
  requestparameters['querystring'] as querystring,
  useridentity['type'] as user_identity_type,
  useridentity['arn'] as user_identity_arn,
  dt
FROM
  "streamalert"."cloudwatch_cloudtrail"
WHERE
  dt = '{utcdatehour_minus1hour}'

  -- Only Events from Athena
  AND eventsource = 'athena.amazonaws.com'
  AND eventname = 'StartQueryExecution'

  -- Only on the CSIRT Prod account
  AND recipientaccountid = '569589067625'

  -- Filter out noisy ALTER and SHOW queries. SHOW queries are commonly run in automation
  -- by API clients, and ALTER queries are run commonly by the Athena partition function.
  AND upper(substr(requestparameters['querystring'], 1, 5)) NOT IN ('ALTER', 'SHOW ')
""",
    params=['utcdatehour_minus1hour'],
    tags=['hourly', 'production']
)

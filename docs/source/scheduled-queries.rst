Scheduled Queries
=================

Overview
--------
Originally dubbed "StreamQuery", this system allows you to execute Athena queries on a schedule, and
funnel their results back into StreamAlert for rules analysis.

Because StreamAlert is mostly stateless, scheduled queries can allow you to correlate data together
and analyze them automatically. Rules that were not previously possible can be written:

* Detect X failed logins within Y minutes
* Detect spike in API behavior that is correlated with an increase in # of a different alert/rule
* Detect elevated API % error rates from specific IP address


How do scheduled queries work?
``````````````````````````````
This system leverages two main components: AWS Lambda and AWS Step Functions.

First, a CloudWatch scheduled event triggers the execution of a new AWS Step Function State Machine.
This State Machine manages the lifecycle of Athena queries through the Lambda function. Its sole
responsibility is to execute the Lambda, wait a predefined window of time, and execute the Lambda again,
repeating until the Lambda reports it is finished.

The Lambda function is a simple function that starts Athena queries, caches their execution ids, checks
on their execution status, and uploads results to StreamAlert via Kinesis. Instead of doing all of these
steps in a blocking fashion and sleeping while it waits for Athena, it runs through all queries in a single
nonblocking pass, and returns the result of its execution to the State Machine. Once all queries have
completed and their results sent to StreamAlert, the Lambda returns a "done" flag to the State Machine,
signalling that this job has been finished.



Configuration
-------------
Scheduled Queries is configured via a single file, ``conf/scheduled_queries.json``.

.. code-block:: json

  {
    "enabled": true,
    "config": {
      "destination_kinesis": "prefix_prod_streamalert",
      "sfn_timeout_secs": 3600,
      "sfn_wait_secs": 30
    },
    "packs": {
      "hourly": {
        "description": "Runs all hourly queries",
        "schedule_expression": "rate(1 hour)"
      },
      "two_hour": {
        "description": "Runs all queries run every two hours",
        "schedule_expression": "rate(2 hours)"
      },
      "daily": {
        "description": "Runs all daily queries",
        "schedule_expression": "rate(24 hours)"
      },
      "two_day": {
        "description": "Runs all queries that are run once every 2 days",
        "schedule_expression": "rate(2 days)"
      }
    },
    "lambda_config": {}
  }

* ``enabled`` — (bool) Pass `true` to activate ScheduledQueries. Leave `false` to disable.
* ``config.destination_kinesis`` — (str) The name of the Kinesis stream to upload results to.
* ``config.sfn_timeout_secs`` - (int) Max number of seconds for the state machine to execute.
* ``config.sfn_wait_secs`` - (int) Time to wait between checks of query status.
* ``query_packs`` - (dict) The keys of this dict are the **names** of the query packs. This section is discussed in more depth below.


Query Packs
```````````
Query Packs are batches of scheduled Athena queries that are executed together.

.. code-block::

  "query_packs": {
    ...
    "hourly": {
      "description": "Runs all hourly queries",
      "schedule_expression": "rate(1 hour)"
    },
    ...
  }

- ``description`` - (str) A string summary of what queries belong in this pack.
- ``schedule_expression`` - (str) A CloudWatch schedule expression defining how frequently to execute this query pack.

Again, the keys to the ``query_packs`` dict are the **names** of the query packs. These names are used below.


Writing Queries
```````````````
After you've defined a few Query Packs, it's time to add actual scheduled queries.

All scheduled queries are located in the ``scheduled_queries/`` directory, located in the root of the project.


.. code-block:: python

    from streamalert.scheduled_queries.query_packs.configuration import QueryPackConfiguration

    QueryPackConfiguration(
        name='NAME_OF_QUERY',
        description='Hey, hey! This is a description!',

        # Make sure to edit the database name properly or this query will error with some
        # "insufficient privileges errors"
        query="""
    SELECT
      *
    FROM
      "ATHENA_DATABASE_NAME"."cloudwatch_cloudtrail"
    WHERE
      dt = '{utcdatehour_minus1hour}'

      AND eventsource = 'athena.amazonaws.com'
      AND eventname = 'StartQueryExecution'
    """,
        params=['utcdatehour_minus1hour'],
        tags=['sample']
    )

* ``name`` - (str) The name of this query. This name is published in the final result, and is useful when writing rules.
* ``description`` - (str) Description of this query. This is published in the final result.
* ``query`` - (str) A template SQL statement sent to Athena, with query parameters identified ``{like_this}``.
* ``params`` - (list[str]|dict[str,callable]) Read on below...
* ``tags`` - (list[str]) Tags required by this query to be run. The simplest way to use this is to put the **Query pack name** into this array.

params
``````
The "params" option specifies how to calculate special query parameters. It supports two formats.

The first format is a list of strings from a predefined set of strings. These have special values that are calculated at runtime,
and are interpolated into the template SQL string. Here is a list of the supported strings:



The second format is a dictionary mapping parameter names to functions, like so:

.. code-block:: python

    def func1(date):
        return date.timestamp()

    def func2(date):
        return LookupTables.get('aaaa', 'bbbb')

    QueryPackConfiguration(
        ...
        query="""
    SELECT *
    FROM stuff
    WHERE
      dt = '{my_param_1}'
      AND p2 = '{my_param_2}'
    """,
        params={
            'my_param_1': func1,
            'my_param_2': func2,
        }
    )



Writing Rules for StreamQuery
-----------------------------

Classifier Schema
`````````````````
We provide an out-of-box sample schema for scheduled query v1.0.0 results. It is located at ``conf/schemas/streamquery.json``.


What does a scheduled query result look like?
`````````````````````````````````````````````
Below is an example of what StreamAlert may receive as a result from a scheduled query.

.. code-block:: json

    {
        "streamquery_schema_version": "1.0.0",
        "execution": {
            "name": "query_name_goes_here",
            "description": "This is an example",
            "query": "SELECT *\nFROM my_database.my_table\nWHERE dt = '2020-01-01-01' LIMIT 10",
            "query_parameters": {
                "dt": "2020-01-01-01"
            },
            "data_scanned_in_bytes": 4783293,
            "execution_time_ms": 12374,
            "tags": [ "query_pack_1" ],
            "query_execution_id": "123845ac-273b-ad3b-2812-9812739789",
            "console_link": "https://console.amazonaws.com/athena/somethingsomething",
        },
        "data": {
            "headers": [
                "username",
                "time"
            ],
            "rows": [
                {
                    "username": "bob",
                    "time": 1,
                },
                {
                    "username": "sally",
                    "time": 2,
                },
                {
                    "username": "joe",
                    "time": 3,
                },
            ],
            "count": 3,
        },
    }

Because the **data** of each query may be different it is generally advisable to write a StreamAlert
matcher on the ``execution.name`` value of the data, first. The rest is up to you!


Deployment
----------
Deploying the various components of scheduled_queries is easy.

Building the Step Function, Lambda, and Query Packs
```````````````````````````````````````````````````

Anytime you change the configured query packs, you will need to run this to update the AWS Resources.

.. code-block:: bash

    % ./manage.py build -t scheduled_queries


Deploying Python Code to Lambda
```````````````````````````````

.. code-block:: bash

    % ./manage.py deploy -f scheduled_queries



Best Practices
--------------

Use cron() instead of rate()
````````````````````````````
When defining ``schedule_expressions``, it's safer to use ``cron(1 * * * *)`` than ``rate(1 hour)``. The reason for
this is, if you use Terraform to build or rebuild your scheduled queries resources, you may end up recreating the
query pack. When using ``rate(1 hour)``, this will cause the CloudWatch event to immediately trigger, then wait
1 hour increments. With ``cron(1 * * * *)``, it is easier to determine exactly when a query pack will be executed. In this case:
"1st minute of every hour".


Be mindful of how much data is being sent
`````````````````````````````````````````
Athena queries can return a TON of data. Remember that this data has to fit in Lambda memory or it will crash your application.
Try to structure your queries with GROUP BY statements or restrict the fields they operate on.


CAREFULLY CONSIDER Firehose'ing Scheduled Query results into Athena
```````````````````````````````````````````````````````````````````
It is theoretically possible to Firehose all StreamQuery results received by StreamAlert back into S3, using scheduled
queries for data transformation.

We don't really recommend doing this. This can add significantly more data to the pipeline, and usage of ``CREATE TABLE AS SELECT``
is likely a more cost efficient choice.


Use dt BETWEEN, not dt > Queries
````````````````````````````````
In queries, prefer to be explicit about which partitions to scan. Use clauses like these:

* ``dt = {datehour}``
* ``dt BETWEEN {datehour_minus1hour} AND {datehour}``

Avoid things like ``dt > {datehour_minus1hour}``. This creates time-sensitivity in your query, and
may cause it to return different results than expected if there is a delay in Step Function execution (see below).



Neat Little Details
-------------------

Athena Queries are Incredibly Cheap
```````````````````````````````````
At $5 per 1 Terabyte scanned, Athena is absurdly cheap. Go nuts with your scheduled queries!


Failed State Machine Executions are Retriable
`````````````````````````````````````````````
AWS Step Functions record every single execution of each State Machine, as well as each state change.
Going to the console, you can observe that the Input event of a State Machine execution is simply a JSON blob:

.. code-block:: json

    {
      "name": "streamalert_scheduled_queries_cloudwatch_trigger",
      "event_id": "12345678-53e7-b479-0601-1234567890",
      "source_arn": "arn:aws:events:us-east-1:123456789012:rule/myprefix_streamalert_scheduled_queries_event_0",
      "streamquery_configuration": {
        "clock": "2020-02-13T22:06:20Z",
        "tags": [
          "hourly"
        ]
      }
    }

Notice the "clock". This value is generated at the time the CloudWatch scheduled event is triggered. Thus,
if you start a new State Machine execution using the exact same Input event (with the same clock), the
results of that execution will be exactly (mostly...) the same.

This is useful for replaying failed State Machine executions that are resultant of Athena downtime, or
deployed bugs. Simply use the AWS Console, navigate to any failed executions, and click the ``New Execution``
button, whereupon a form will be shown with a copy of the Input event already pre-populated!


You manually trigger query executions
`````````````````````````````````````
Knowing the above, you can force StreamQuery to execute ad hoc queries simply by manually triggering State
Machine executions, and passing in a correctly formatted Input event!

Make sure the Input event's tags and clock are populated correctly to ensure the correct queries are
executed.
